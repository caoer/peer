package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/store"
)

// A room's push socket (contract § Room routes, the socket row) runs as a
// channel's does (push.go): one socket per room this party is in, every
// event handled on serve's goroutine, a pull on every open and every
// push.pullEvery frames. A frame takes the pull's own step — receive, the
// room spool, Commit, settle — so a record is born once whichever path
// reads it, on whichever host. A 4401 close, or a 401 revoked at the
// upgrade, stops the socket: the pull that follows finds the revoke and
// takes the party out of the room, as a removal does.

// trackRooms opens a socket for every room this party is in without one,
// and closes those of rooms it is out of; a room whose token changed is
// opened again under the new one.
func (ps *pusher) trackRooms(ctx context.Context) {
	l, err := loadRooms(ctx, ps.sv.p.backend)
	if err != nil {
		fmt.Fprintf(ps.sv.out, "push: %v\n", err)
		return
	}
	in := map[string]roomRef{}
	for _, ref := range l.Rooms {
		if ref.Stage == stageJoined && ref.Token != "" {
			in[ref.ID] = ref
		}
	}
	for k, s := range ps.socks {
		if ref, ok := in[k.id]; k.room && (!ok || ref.Token != s.token) {
			s.cancel()
			delete(ps.socks, k)
		}
	}
	for id, ref := range in {
		k := pushKey{room: true, id: id}
		if ps.socks[k] != nil {
			continue
		}
		rc := relay.New(ref.Relay, nil)
		ps.open(k, ref.Token, func(ctx context.Context) (*pushStream, error) {
			s, err := rc.SubscribeRoom(ctx, ref.ID, ref.Token)
			if err != nil {
				return nil, err
			}
			return &pushStream{
				next: func(ctx context.Context) (pushEvent, error) {
					rec, err := s.Next(ctx)
					return pushEvent{roomRec: rec}, err
				},
				close: s.Close,
			}, nil
		}, func(err error) bool {
			return errors.Is(err, relay.ErrRevoked) || errors.Is(err, relay.ErrBadToken) || errors.Is(err, relay.ErrNoSuchRoom)
		})
	}
}

// handleRoom acts on one room socket event, with the room's entry in the
// rooms record as it is now: a frame takes the pull's step, an open or every
// push.pullEvery frames pulls the room, a revoke pulls it once more, which
// takes the party out.
func (ps *pusher) handleRoom(ctx context.Context, ev pushEvent, s *pushSocket) {
	sv, out := ps.sv, ps.sv.out
	l, err := loadRooms(ctx, sv.p.backend)
	if err != nil {
		fmt.Fprintf(out, "push: %v\n", err)
		return
	}
	r := l.byID(ev.key.id)
	if r == nil || r.Stage != stageJoined {
		return
	}
	ref := *r
	switch ev.kind {
	case pushDown:
		fmt.Fprintf(out, "room %s: no push socket (%v); pulling every round until one opens\n", ref.Name, ev.err)
	case pushGone:
		if !errors.Is(ev.err, relay.ErrRevoked) {
			fmt.Fprintf(out, "room %s: the relay refused the push socket (%v); pulling every round\n", ref.Name, ev.err)
			break
		}
		fmt.Fprintf(out, "room %s: the relay closed the push socket: it has revoked this member\n", ref.Name)
		err = sv.pullRoom(ctx, ref)
	case pushClosed:
		fmt.Fprintf(out, "room %s: push socket closed (%v); reconnecting\n", ref.Name, ev.err)
	case pushOpen:
		fmt.Fprintf(out, "room %s: push socket open\n", ref.Name)
		s.frames = 0
		err = sv.pullRoom(ctx, ref)
	case pushFrame:
		s.frames++
		var pulled bool
		pulled, err = sv.roomPushed(ctx, ref, ev.roomRec)
		if err == nil && !pulled && s.frames >= sv.p.cfg.pullEvery() {
			pulled, err = true, sv.pullRoom(ctx, ref)
		}
		if pulled {
			s.frames = 0
		}
	}
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(out, "%v\n", err)
	}
}

// pullRoom pulls one room to head: serveRooms's pull, without the round's
// sends and admin work.
func (sv *server) pullRoom(ctx context.Context, ref roomRef) error {
	c, err := sv.p.openRoom(ctx, ref, sv.out)
	if err != nil {
		return fmt.Errorf("room %s: %w", ref.Name, err)
	}
	c.sv = sv
	return sv.roomPulled(ctx, c, c.pull(ctx))
}

// roomPulled says what a room pull ended on as the round says it: a room
// this party is out of is a line, not an error; a removal record of this
// party's idx that folded takes it out.
func (sv *server) roomPulled(ctx context.Context, c *roomConn, err error) error {
	switch {
	case errors.Is(err, errGone):
		fmt.Fprintf(sv.out, "%v\n", err)
		return nil
	case err != nil:
		return err
	}
	if c.st.Removed(c.st.Idx()) {
		fmt.Fprintf(sv.out, "%v\n", c.gone(ctx, stageRemoved))
	}
	return nil
}

// roomPushed takes one pushed room record by the pull's step and reports
// whether the room was pulled instead. A frame at or before the cursor is a
// duplicate, dropped; one past the cursor's next seq is a gap — a lost
// frame, or this party's own records, which the relay never sends back —
// and the room is pulled; so is a frame whose Commit another host beat.
func (sv *server) roomPushed(ctx context.Context, ref roomRef, rec relay.RoomRecord) (bool, error) {
	c, err := sv.p.openRoom(ctx, ref, sv.out)
	if err != nil {
		return false, fmt.Errorf("room %s: %w", ref.Name, err)
	}
	fail := func(err error) error {
		if err == nil {
			return nil
		}
		return fmt.Errorf("room %s #%d: %w", ref.Name, rec.Seq, err)
	}
	c.sv = sv
	switch cur := c.st.Cursor(); {
	case rec.Seq <= cur:
		return false, nil
	case rec.Seq > cur+1:
		return true, sv.roomPulled(ctx, c, c.pull(ctx))
	}
	if err := c.receive(rec); err != nil {
		c.dropPending()
		return false, fail(err)
	}
	c.st.SetCursor(rec.Seq)
	if err := c.beforeCommit(); err != nil {
		c.dropPending()
		return false, fail(err)
	}
	if err := c.st.Commit(ctx); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			// The write may have landed: the entries stay for the next
			// replay's seen check.
			c.pending = nil
			return false, fail(err)
		}
		c.dropPending()
		c.say(rec.Seq, "another host advanced the state; reloading")
		if err := c.reload(ctx); err != nil {
			return true, fail(err)
		}
		return true, sv.roomPulled(ctx, c, c.pull(ctx))
	}
	return false, fail(c.settle())
}
