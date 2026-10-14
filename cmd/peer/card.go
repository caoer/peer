package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// cmdCard is `peer card publish`: re-sign the party's card with the root key
// at command time and send it, with details, as a card message on every
// confirmed channel (design §3.3: card updates travel the channel). The
// receiver refreshes its pin when the identity key is the one it holds. A
// signed prekey past its interval is rotated first, since the root is here
// to announce the new one.
func cmdCard(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "publish" {
		fmt.Fprintln(stderr, "usage: peer card publish [--dir D]")
		return 2
	}
	fl := flag.NewFlagSet("card publish", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	if err := fl.Parse(args[1:]); err != nil {
		return 2
	}
	if fl.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: peer card publish [--dir D]")
		return 2
	}
	if err := runCardPublish(context.Background(), *dirFlag, stdout); err != nil {
		fmt.Fprintf(stderr, "peer card publish: %v\n", err)
		return 1
	}
	return 0
}

// errNoRoot is the rule for a party whose root key is kept off the fleet
// (design §3.2): nothing on the fleet signs a card.
func errNoRoot(dir string) error {
	return fmt.Errorf("%s is not in %s: the card is signed by the root key, which lives off the fleet (design §3.2); run peer card publish on the machine that holds %s, against the same state — the signed card then goes out on every confirmed channel, and nothing on the fleet signs one", rootFile, dir, rootFile)
}

func runCardPublish(ctx context.Context, dir string, out io.Writer) error {
	dir, err := peerDir(dir)
	if err != nil {
		return err
	}
	p, err := openParty(dir)
	if err != nil {
		return err
	}
	if p.root == nil {
		return errNoRoot(dir)
	}
	k, err := p.keys(ctx)
	if err != nil {
		return err
	}
	if _, err := rotateIfDue(ctx, p, k, time.Now(), out); err != nil {
		return err
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return err
	}
	var errs []error
	n := 0
	for _, pe := range r.Peers {
		if pe.State != roster.Confirmed {
			continue
		}
		n++
		if err := p.publish(ctx, k, pe, out); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", pe.Name, err))
		}
	}
	if n == 0 {
		fmt.Fprintln(out, "no confirmed channel to publish on")
	}
	return errors.Join(errs...)
}

// publish signs the card with details and sends it on pe's channel through
// session.Send (decision 5: commit, then put); a put the relay refuses after
// the commit stays in the outbox for replay. The channel's announced signed
// prekey becomes the card's.
func (p *party) publish(ctx context.Context, k *store.Keys, pe roster.Peer, out io.Writer) error {
	if p.root == nil {
		return errNoRoot(p.dir)
	}
	rc := relay.New(pe.Relay, nil)
	for try := 1; ; try++ {
		ch, err := p.store.Channel(ctx, pe.Channel)
		if err != nil {
			return err
		}
		if has, _ := ch.ContainsSession(ctx, session.Addr); !has {
			return errors.New("no session on the channel")
		}
		own, err := p.signedCard(k.PartyKeys, relaysOf(p.cfg), true, time.Now())
		if err != nil {
			return err
		}
		dm, err := session.CardMessage(p.partyID(), keys.PartyID(ch.Root()), own)
		if err != nil {
			return err
		}
		ch.SetAnnounced(k.PartyKeys.SignedPrekey.ID())
		rcpt, err := session.New(ch, k).Send(ctx, p.outbox, rc, pe.Token, dm)
		var putErr *session.PutError
		switch {
		case err == nil:
			fmt.Fprintf(out, "card published to %s (#%d)\n", pe.Name, rcpt.Seq)
			return nil
		case errors.As(err, &putErr):
			fmt.Fprintf(out, "card to %s is committed but the relay did not take it (%v); it stays in the outbox\n", pe.Name, putErr.Err)
			return nil
		case errors.Is(err, store.ErrConflict) && try < sendTries:
			// Another host advanced the channel: re-encrypt from its state.
			if k, err = p.keys(ctx); err != nil {
				return err
			}
		default:
			return err
		}
	}
}
