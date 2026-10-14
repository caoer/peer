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
	return 0
}

type confirmResult struct {
	party, channel string
	putErr         error
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
	if err := k.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit party keys: %w", err)
	}
	err = roster.Update(ctx, p.backend, func(r *roster.Roster) error {
		cur := r.ByName(name)
		if cur == nil || cur.Channel != pe.Channel {
			return fmt.Errorf("the roster entry for %s changed under this confirm", name)
		}
		cur.State = roster.Confirmed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
