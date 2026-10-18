package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

func cmdForget(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("forget", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer forget [--dir D] <name>")
		return 2
	}
	if err := runForget(context.Background(), *dirFlag, fl.Arg(0), stdout); err != nil {
		fmt.Fprintf(stderr, "peer forget: %v\n", err)
		return 1
	}
	return 0
}

// runForget forgets the peer named name: a bye on the channel when there is
// a session to send it under, this party's room work riding the channel
// withdrawn, the roster entry dropped — the name is free — and the channel
// record replaced by a tombstone. It refuses while this party reads a room
// whose card and rotations go over that channel.
func runForget(ctx context.Context, dir, name string, out io.Writer) error {
	dir, err := peerDir(dir)
	if err != nil {
		return err
	}
	p, err := openParty(dir)
	if err != nil {
		return err
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return err
	}
	cur := r.ByName(name)
	if cur == nil {
		return fmt.Errorf("no peer named %s", name)
	}
	pe := *cur
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return err
	}
	for _, rm := range l.Rooms {
		if rm.Via == pe.Channel && rm.Stage == stageJoined && rm.Read {
			return fmt.Errorf("you read room %s through %s, and your room card goes to its admin over that channel: peer room leave %s first", rm.Name, name, rm.Name)
		}
	}

	if pe.State != roster.Gone {
		switch err := p.sayBye(ctx, pe); {
		case errors.Is(err, errNoSession):
			fmt.Fprintf(out, "no session with %s: nothing to tell it\n", name)
		case err != nil:
			fmt.Fprintf(out, "%s was not told (%v): its sends go to a channel nobody reads\n", name, err)
		default:
			fmt.Fprintf(out, "told %s: bye\n", name)
		}
	}

	var notes []string
	err = updateRooms(ctx, p.backend, func(l *roomList) error {
		notes = notes[:0]
		kept := l.Rooms[:0]
		for _, rm := range l.Rooms {
			if rm.Via == pe.Channel && (rm.Stage == stageInvited || rm.Stage == stageSeated) {
				// Only the channel the invite came on may seat this party.
				notes = append(notes, fmt.Sprintf("room %s: your join through %s is withdrawn", rm.Name, name))
				continue
			}
			if a := rm.add(pe.Channel); a != nil {
				note := fmt.Sprintf("room %s: the add of %s is withdrawn (%s)", rm.Name, name, a.Stage)
				if a.Stage == addRostered {
					note += fmt.Sprintf("; idx %d is in the roster without its token: peer room remove %s %d", a.Idx, rm.Name, a.Idx)
				}
				notes = append(notes, note)
				rm.dropAdd(pe.Channel)
			}
			if h := rm.handover(pe.Channel); h != nil {
				note := fmt.Sprintf("room %s: the handover to %s is withdrawn", rm.Name, name)
				if h.Recorded {
					note += fmt.Sprintf("; its record names idx %d an admin that holds no admin token", h.Idx)
				}
				notes = append(notes, note)
				hs := rm.Handovers[:0]
				for _, x := range rm.Handovers {
					if x.Channel != pe.Channel {
						hs = append(hs, x)
					}
				}
				rm.Handovers = hs
			}
			kept = append(kept, rm)
		}
		l.Rooms = kept
		return nil
	})
	if err != nil {
		return err
	}
	for _, n := range notes {
		fmt.Fprintln(out, n)
	}

	if err := roster.Update(ctx, p.backend, func(r *roster.Roster) error {
		r.Remove(pe.Name, pe.Channel)
		return nil
	}); err != nil {
		return err
	}
	if err := dropChannel(ctx, p.store, pe.Channel); err != nil {
		return fmt.Errorf("%s is off the roster; its channel record was not dropped (%v): peer forget never reads it again", name, err)
	}
	fmt.Fprintf(out, "forgot %s: channel %s dropped; the name is free\n", name, pe.Channel)
	return nil
}

var errNoSession = errors.New("no session")

// sayBye puts a bye on the channel under the session in force, the send's
// own order (encrypt → outbox → commit → put). No session, no bye: the
// peer's pin of this party is then the peer's own to drop.
func (p *party) sayBye(ctx context.Context, pe roster.Peer) error {
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return err
	}
	if has, _ := ch.ContainsSession(ctx, session.Addr); !has || ch.Root() == nil {
		return errNoSession
	}
	k, err := p.keys(ctx)
	if err != nil {
		return err
	}
	m, err := session.NewMessage(p.partyID(), keys.PartyID(ch.Root()), session.KindBye, []byte("forgotten"))
	if err != nil {
		return err
	}
	rc := relay.New(pe.Relay, nil)
	for try := 1; ; try++ {
		_, err := session.New(ch, k).Send(ctx, p.outbox, rc, pe.Token, m)
		var putErr *session.PutError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &putErr):
			return putErr.Err
		case errors.Is(err, store.ErrConflict) && try < sendTries:
			if ch, err = p.store.Channel(ctx, pe.Channel); err != nil {
				return err
			}
			if k, err = p.keys(ctx); err != nil {
				return err
			}
		default:
			return err
		}
	}
}

// dropChannel replaces the channel record with its tombstone, reloading
// when another host committed in between.
func dropChannel(ctx context.Context, s *store.Store, channel string) error {
	var err error
	for try := 0; try < sendTries; try++ {
		var ch *store.Channel
		if ch, err = s.Channel(ctx, channel); err != nil {
			return err
		}
		if err = ch.Drop(ctx); !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

// nameTaken refuses a name a confirmed peer holds, or one the peer forgot
// and this party has not; how names the other choice ("" or " with --name").
func nameTaken(r *roster.Roster, name, how string) error {
	cur := r.ByName(name)
	switch {
	case cur == nil:
		return nil
	case cur.State == roster.Confirmed:
		return fmt.Errorf("%s is a confirmed peer already; pick another name%s, or peer forget %s first", name, how, name)
	case cur.State == roster.Gone:
		return fmt.Errorf("%s forgot its channel with you; pick another name%s, or peer forget %s first", name, how, name)
	}
	return nil
}
