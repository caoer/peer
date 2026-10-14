package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// cmdConfirm finishes an invite on the host's side: pull the guest's card
// (#1) and decrypt it, check that the identity key the session was built
// with is the card's (design §3.4), check the 8-digit code (§4), pin the
// card, then send this party's card with details inside the session. A
// refusal keeps nothing; the host re-invites.
func cmdConfirm(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("confirm", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	codeFlag := fl.String("code", "", "the 8-digit code the invitee read back (asked on stdin when absent)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer confirm [--dir D] [--code 8-digits] <name>")
		return 2
	}
	name := fl.Arg(0)
	code := strings.TrimSpace(*codeFlag)
	if code == "" {
		fmt.Fprintf(stderr, "code from %s: ", name)
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintf(stderr, "peer confirm: no code given\n")
			return 2
		}
		code = strings.TrimSpace(line)
	}
	res, err := runConfirm(context.Background(), *dirFlag, name, code)
	if err != nil {
		fmt.Fprintf(stderr, "peer confirm: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "confirmed %s (%s) on channel %s\n", name, res.party, res.channel)
	if res.putErr != nil {
		fmt.Fprintf(stdout, "the card with details did not reach the relay (%v); it stays in the outbox for replay\n", res.putErr)
	}
	if res.keysErr != nil {
		fmt.Fprintf(stdout, "the party keys were not committed (%v); the one-time prekey this handshake used stays a spare\n", res.keysErr)
	}
	return 0
}

type confirmResult struct {
	party, channel string
	putErr         error
	keysErr        error
}

func runConfirm(ctx context.Context, dir, name, code string) (*confirmResult, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, err
	}
	if p.root == nil {
		return nil, fmt.Errorf("%s is not in %s: the code is derived from the root key", rootFile, dir)
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return nil, err
	}
	pe := r.ByName(name)
	switch {
	case pe == nil:
		return nil, fmt.Errorf("no peer named %s: run peer invite %s first", name, name)
	case pe.Side != roster.Host:
		return nil, fmt.Errorf("%s invited you; the confirm is theirs", name)
	case pe.State == roster.Confirmed:
		return nil, fmt.Errorf("%s is confirmed already", name)
	}
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return nil, err
	}
	// A previous confirm's commit may have landed with its roster write lost
	// — a crash, a refused write, a keys conflict: the channel then holds the
	// pinned card and the session while the row still says invited, and the
	// pull below would find a message where the card was. Finish that confirm
	// rather than refuse it; the guest's token is spent and cannot be retried.
	if done, err := confirmLanded(ctx, p, ch, code); err != nil {
		return nil, err
	} else if done {
		if err := confirmRoster(ctx, p, name, pe.Channel); err != nil {
			return nil, err
		}
		return &confirmResult{party: keys.PartyID(ch.Root()), channel: pe.Channel}, nil
	}
	k, err := p.keys(ctx)
	if err != nil {
		return nil, err
	}
	rc := relay.New(pe.Relay, nil)
	recs, err := rc.Pull(ctx, pe.Channel, pe.Token, ch.Cursor())
	if err != nil {
		return nil, fmt.Errorf("pull: %w", err)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("nothing from %s yet: they have not run peer accept", name)
	}
	s := session.New(ch, k)
	m, err := s.Receive(ctx, recs[0])
	if err != nil {
		return nil, fmt.Errorf("envelope #%d does not open as %s's card: %w; refusing, re-invite", recs[0].Seq, name, err)
	}
	c, signed, root, err := session.PeerCard(m)
	if err != nil {
		return nil, fmt.Errorf("%s's card: %w; refusing, re-invite", name, err)
	}
	if err := s.CheckIdentity(c); err != nil {
		return nil, fmt.Errorf("%w: the party in the session is not the card's; refusing, re-invite", err)
	}
	if want := session.Code(p.root.Public(), root); code != want {
		return nil, errors.New("the code does not match: refusing, re-invite")
	}
	ch.PinRoot(root)
	ch.PinCard(signed)

	// Send commits the channel (session, identity, cursor, pin) before the
	// put; the party keys (the used one-time prekey gone) commit after it,
	// so a crash between leaves a spare key, never a session without its key.
	own, err := p.signedCard(k.PartyKeys, []string{pe.Relay}, true, time.Now())
	if err != nil {
		return nil, err
	}
	party := keys.PartyID(root)
	dm, err := session.CardMessage(p.partyID(), party, own)
	if err != nil {
		return nil, err
	}
	res := &confirmResult{party: party, channel: pe.Channel}
	if _, err := s.Send(ctx, p.outbox, rc, pe.Token, dm); err != nil {
		var putErr *session.PutError
		if !errors.As(err, &putErr) {
			return nil, fmt.Errorf("commit: %w", err)
		}
		res.putErr = putErr.Err
	}
	// The channel is committed and the card is out. The keys record only
	// carries the spent one-time prekey, so a failure here — a conflict with
	// another host's serve, which commits the keys on every PreKey record, or
	// a refused write — leaves a spare key and is reported; it never leaves
	// the channel half-confirmed.
	if err := k.Commit(ctx); err != nil {
		res.keysErr = err
	}
	if err := confirmRoster(ctx, p, name, pe.Channel); err != nil {
		return nil, err
	}
	return res, nil
}

// confirmLanded reports whether this confirm's own work is on the channel
// already: the peer's root and card pinned and a session built. The code the
// caller typed must be the one those two root keys give — a wrong code never
// finishes a confirm.
func confirmLanded(ctx context.Context, p *party, ch *store.Channel, code string) (bool, error) {
	if ch.Root() == nil || ch.Card() == nil {
		return false, nil
	}
	has, err := ch.ContainsSession(ctx, session.Addr)
	if err != nil || !has {
		return false, err
	}
	if code != session.Code(p.root.Public(), ch.Root()) {
		return false, errors.New("the code does not match: refusing, re-invite")
	}
	return true, nil
}

// confirmRoster is the last step of a confirm: the peer's row goes confirmed,
// which is what makes serve pull the channel.
func confirmRoster(ctx context.Context, p *party, name, channel string) error {
	return roster.Update(ctx, p.backend, func(r *roster.Roster) error {
		cur := r.ByName(name)
		if cur == nil || cur.Channel != channel {
			return fmt.Errorf("the roster entry for %s changed under this confirm", name)
		}
		cur.State = roster.Confirmed
		return nil
	})
}
