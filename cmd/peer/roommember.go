package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// The membership commands (plan C6) and the daily rotation. Each act is the
// contract's order: a removal is the roster record with removed and bump,
// then the revoke; a leave is the leave record, then DELETE …/self; a
// handover is the handover record, the admin-flagged token from POST
// …/admin, then room-admin over the channel; a close is one removal record
// naming everyone else, their revokes, the admin's own leave and its own
// revoke. A step a round cuts short is finished by the next serve round
// from the rooms record (finishRemovals, finishHandovers), never done twice.
//
// Rotation (rules 8 and 9): generate → Rotate → Commit → post the roomcard;
// a host that loses the Commit reads the winner's key. A read member cannot
// put, so its card goes over its channel to an admin as a room-join, and the
// admin's roster entry announces it; a member whose identity key changed
// does the same, since the folded party card no longer lists its key.

// roomClock is the rotation's clock; a test sets it.
var roomClock = time.Now

// rotationGrace is how long after a rotation's Commit its roomcard may still
// be on its way from the host that committed it, before another host of the
// party posts the key itself.
const rotationGrace = time.Minute

// waitingKind reports whether a record of kind waits in this host's room
// outbox for the room.
func (c *roomConn) waitingKind(kind string) bool {
	es, _ := c.p.roomOutbox.Entries()
	return slices.ContainsFunc(es, func(e *store.Entry) bool { return e.Channel == c.ref.ID && e.Type == kind })
}

// cmdRoomMember runs peer room remove|leave|handover|close|rotate.
func cmdRoomMember(verb string, args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("room "+verb, flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	want, usage := 1, "peer room "+verb+" [--dir D] <room>"
	switch verb {
	case "remove":
		want, usage = 2, "peer room remove [--dir D] <room> <peer | party id | idx>"
	case "handover":
		want, usage = 2, "peer room handover [--dir D] <room> <peer>"
	}
	if fl.NArg() != want || slices.Contains(fl.Args(), "") {
		fmt.Fprintln(stderr, "usage: "+usage)
		return 2
	}
	ctx := context.Background()
	var err error
	switch verb {
	case "remove":
		err = runRoomRemove(ctx, *dirFlag, fl.Arg(0), fl.Arg(1), stdout)
	case "leave":
		err = runRoomLeave(ctx, *dirFlag, fl.Arg(0), stdout)
	case "handover":
		err = runRoomHandover(ctx, *dirFlag, fl.Arg(0), fl.Arg(1), stdout)
	case "close":
		err = runRoomClose(ctx, *dirFlag, fl.Arg(0), stdout)
	case "rotate":
		err = runRoomRotate(ctx, *dirFlag, fl.Arg(0), stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "peer room %s: %v\n", verb, err)
		return 1
	}
	return 0
}

// openJoined opens a room this party is in, for a command, and pulls it to
// head; a room the party is out of, or not in yet, refuses.
func openJoined(ctx context.Context, dir, name string, out io.Writer) (*roomConn, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, err
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return nil, err
	}
	ref := l.byName(name)
	switch {
	case ref == nil:
		return nil, fmt.Errorf("no room named %s", name)
	case ref.Stage.followed():
		return nil, fmt.Errorf("room %s: you follow its feed by a link and hold no seat in it; its owner alone writes", ref.Name)
	case ref.Stage.gone():
		return nil, fmt.Errorf("room %s: you %s it already", ref.Name, pastTense(ref.Stage))
	case ref.Stage != stageJoined:
		return nil, fmt.Errorf("room %s: you are not in it yet (%s)", ref.Name, ref.Stage)
	}
	c, err := p.openRoom(ctx, *ref, out)
	if err != nil {
		return nil, err
	}
	if err := c.pull(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func pastTense(s roomStage) string {
	switch s {
	case stageLeft:
		return "left"
	case stageClosed:
		return "closed"
	}
	return "were removed from"
}

// requireAdmin refuses a command that is an admin's act.
func (c *roomConn) requireAdmin(act string) error {
	if !c.st.IsAdmin(c.st.Idx()) {
		return fmt.Errorf("room %s: %s is an admin's act and you are not in its admin set; leave is yours", c.ref.Name, act)
	}
	return nil
}

// resolveMember is the member a command names: a peer name (the confirmed
// channel whose root the roster holds), a party id, or an idx.
func (c *roomConn) resolveMember(ctx context.Context, who string) (*room.Member, error) {
	if n, err := strconv.Atoi(who); err == nil {
		if !relay.ValidIdx(n) {
			return nil, fmt.Errorf("idx %d is out of range", n)
		}
		if m := c.st.Member(uint16(n)); m != nil {
			return m, nil
		}
		return nil, fmt.Errorf("room %s holds no member at idx %d", c.ref.Name, n)
	}
	party := who
	if !deliver.ValidAddr(who) {
		r, err := roster.Load(ctx, c.p.backend)
		if err != nil {
			return nil, err
		}
		pe := r.ByName(who)
		if pe == nil {
			return nil, fmt.Errorf("no peer named %s", who)
		}
		ch, err := c.p.store.Channel(ctx, pe.Channel)
		if err != nil {
			return nil, err
		}
		if ch.Root() == nil {
			return nil, fmt.Errorf("%s's card is not pinned yet", who)
		}
		party = keys.PartyID(ch.Root())
	}
	for _, m := range c.st.Members() {
		if m.Party == party {
			return m, nil
		}
	}
	return nil, fmt.Errorf("%s is not in room %s", who, c.ref.Name)
}

// runRoomRemove removes a member: the roster record with removed and bump
// — a put sealed to the old roster at the old version is 409 from then on —
// then the revoke, retried by serve if it fails after the record.
func runRoomRemove(ctx context.Context, dir, name, who string, out io.Writer) error {
	c, err := openJoined(ctx, dir, name, out)
	if err != nil {
		return err
	}
	if err := c.requireAdmin("remove"); err != nil {
		return err
	}
	m, err := c.resolveMember(ctx, who)
	if err != nil {
		return err
	}
	if m.Idx == c.st.Idx() {
		return fmt.Errorf("room %s: idx %d is you; peer room leave %s is your act", c.ref.Name, m.Idx, c.ref.Name)
	}
	body, err := json.Marshal(room.RosterBody{Removed: []uint16{m.Idx}})
	if err != nil {
		return err
	}
	seq, _, err := c.post(ctx, membershipPost{kind: room.KindRoster, body: body, bump: true})
	switch {
	case errors.Is(err, errQueued):
		fmt.Fprintf(out, "room %s: the removal of idx %d (%s) is committed and did not land (%v); peer serve puts it, then revokes the idx\n", c.ref.Name, m.Idx, m.Party, err)
		return nil
	case errors.Is(err, errMoot):
		fmt.Fprintf(out, "room %s: idx %d (%s) is out of the roster already; nothing posted\n", c.ref.Name, m.Idx, m.Party)
	case err != nil:
		return err
	default:
		fmt.Fprintf(out, "room %s: idx %d (%s) removed (record #%d, membership bumped)\n", c.ref.Name, m.Idx, m.Party, seq)
	}
	c.finishRemovals(ctx)
	return nil
}

// runRoomLeave leaves the room: this host's waiting records first, then the
// leave record (a write member's; a read member cannot put), then DELETE
// …/members/self and the state dropped. The last admin of a room with other
// members hands over or closes instead.
func runRoomLeave(ctx context.Context, dir, name string, out io.Writer) error {
	c, err := openJoined(ctx, dir, name, out)
	if err != nil {
		return err
	}
	st := c.st
	if st.IsAdmin(st.Idx()) && len(st.Admins()) == 1 && len(st.Members()) > 1 {
		return fmt.Errorf("room %s: you are its last admin and %d other members stay; hand over first (peer room handover %s <peer>) or close it (peer room close %s)", c.ref.Name, len(st.Members())-1, c.ref.Name, c.ref.Name)
	}
	if st.Feed() && st.IsAdmin(st.Idx()) {
		// The link's read seat is outside the roster and only the owner's
		// admin token revokes it: a leave would drop that token and leave
		// the seat live for the room's retention.
		return fmt.Errorf("room %s is a feed: its owner ends it with peer room close %s; a leave would keep its link's read seat live with no admin left to revoke it", c.ref.Name, c.ref.Name)
	}
	if err := c.flushBefore(ctx, "leave"); err != nil {
		return err
	}
	if st.Member(st.Idx()) != nil && !c.ref.Read {
		seq, _, err := c.postMembership(ctx, room.KindLeave, []byte("{}"))
		switch {
		case errors.Is(err, errQueued):
			return fmt.Errorf("the leave record is committed and did not land (%v): run peer serve, then peer room leave %s again", err, c.ref.Name)
		case errors.Is(err, relay.ErrReadOnly):
			c.markRead(ctx)
		case err != nil:
			return err
		default:
			fmt.Fprintf(out, "room %s: leave record #%d\n", c.ref.Name, seq)
		}
	}
	if err := c.revokeSelf(ctx); err != nil {
		return fmt.Errorf("room %s: %v; run peer room leave %s again", c.ref.Name, err, c.ref.Name)
	}
	c.gone(ctx, stageLeft)
	fmt.Fprintf(out, "left room %s (%s)\n", c.ref.Name, c.ref.ID)
	return nil
}

// flushBefore puts this host's waiting records for the room, so a leave or
// close is the party's last record; anything still waiting refuses the act.
func (c *roomConn) flushBefore(ctx context.Context, act string) error {
	if res := c.flush(ctx, true); res.wait != nil {
		if n := c.p.waiting(c.ref.ID); n > 0 {
			return fmt.Errorf("room %s: %d records wait in the room outbox (%v); peer serve puts them, then %s again", c.ref.Name, n, res.wait, act)
		}
	}
	return nil
}

// revokeSelf is DELETE …/members/self; a token revoked already is done.
func (c *roomConn) revokeSelf(ctx context.Context) error {
	_, err := c.rc.LeaveRoom(ctx, c.ref.ID, c.ref.Token)
	if err != nil && !errors.Is(err, relay.ErrRevoked) {
		return fmt.Errorf("the relay did not revoke your token (%v)", err)
	}
	return nil
}

// markRead records that this party's token is a read token: the relay
// answered read_only, so its card and leave go over the channel from here.
func (c *roomConn) markRead(ctx context.Context) {
	c.ref.Read = true
	err := updateRooms(ctx, c.p.backend, func(l *roomList) error {
		if r := l.byID(c.ref.ID); r != nil {
			r.Read = true
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(c.out, "room %s: you are a read member, and the rooms record does not say so: %v\n", c.ref.Name, err)
	}
}

// runRoomHandover makes a write member an admin: the handover record, the
// admin-flagged token from POST …/admin, then room-admin over the channel;
// a re-run after the record landed sends the stored token again, no second
// grant. A read member — every member of a feed — is refused before any
// record, by its role on the relay's members list.
func runRoomHandover(ctx context.Context, dir, name, peerName string, out io.Writer) error {
	c, err := openJoined(ctx, dir, name, out)
	if err != nil {
		return err
	}
	if err := c.requireAdmin("handover"); err != nil {
		return err
	}
	r, err := roster.Load(ctx, c.p.backend)
	if err != nil {
		return err
	}
	pe := r.ByName(peerName)
	if pe == nil {
		return fmt.Errorf("no peer named %s", peerName)
	}
	if pe.State != roster.Confirmed {
		return fmt.Errorf("%s is not a confirmed channel (%s): the admin token goes only over a channel whose code was checked", peerName, pe.State)
	}
	m, err := c.resolveMember(ctx, peerName)
	if err != nil {
		return err
	}
	if m.Idx == c.st.Idx() {
		return fmt.Errorf("room %s: %s is you", c.ref.Name, peerName)
	}
	// The relay grants admin to a write seat alone; a record posted for a
	// read one would fold an admin no relay token backs.
	ms, err := c.rc.ListMembers(ctx, c.ref.ID, c.ref.Token)
	if err != nil {
		return fmt.Errorf("room %s: the relay's members are not listed, so %s's role is not known: %w", c.ref.Name, peerName, err)
	}
	for _, rm := range ms.Members {
		if uint16(rm.Idx) != m.Idx || rm.Role == relay.RoleWrite {
			continue
		}
		if c.st.Feed() {
			return fmt.Errorf("room %s is a feed: %s (idx %d) is a %s member, as every member of a feed is, and a feed cannot be handed over", c.ref.Name, peerName, m.Idx, rm.Role)
		}
		return fmt.Errorf("room %s: %s (idx %d) is a %s member; admin goes to a write member alone", c.ref.Name, peerName, m.Idx, rm.Role)
	}
	if h := c.ref.handover(pe.Channel); h != nil && h.Idx == m.Idx {
		// A re-run: the stored token goes out again, no second grant. An
		// entry at another idx is an earlier handover to a member that left
		// and was added again; the relay revoked its token with that idx.
		err = updateRooms(ctx, c.p.backend, func(l *roomList) error {
			if cur := l.byID(c.ref.ID); cur != nil {
				if ph := cur.handover(pe.Channel); ph != nil {
					ph.Sent = false
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		recorded := c.st.IsAdmin(m.Idx)
		if !recorded {
			body, err := json.Marshal(room.HandoverBody{Idx: m.Idx})
			if err != nil {
				return err
			}
			seq, _, err := c.postMembership(ctx, room.KindHandover, body)
			switch {
			case errors.Is(err, errQueued):
				fmt.Fprintf(out, "room %s: the handover to %s (idx %d) is committed and did not land (%v); peer serve puts it, then grants and sends the token\n", c.ref.Name, peerName, m.Idx, err)
			case err != nil:
				return err
			default:
				recorded = true
				fmt.Fprintf(out, "room %s: handover record #%d: idx %d (%s) joins the admin set\n", c.ref.Name, seq, m.Idx, peerName)
			}
		}
		err = updateRooms(ctx, c.p.backend, func(l *roomList) error {
			cur := l.byID(c.ref.ID)
			if cur == nil {
				return fmt.Errorf("room %s left the rooms record under this command", c.ref.Name)
			}
			fresh := pendingHandover{Peer: peerName, Channel: pe.Channel, Idx: m.Idx, Recorded: recorded}
			if ph := cur.handover(pe.Channel); ph != nil {
				*ph = fresh
			} else {
				cur.Handovers = append(cur.Handovers, fresh)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	c.finishHandovers(ctx)
	return nil
}

// runRoomClose ends the room for everyone: one removal record naming every
// other live idx with bump, their revokes, a feed's link revoked, every
// other seat the relay serves outside the roster revoked, the admin's own
// leave record and its own revoke; the local state is dropped.
func runRoomClose(ctx context.Context, dir, name string, out io.Writer) error {
	c, err := openJoined(ctx, dir, name, out)
	if err != nil {
		return err
	}
	if err := c.requireAdmin("close"); err != nil {
		return err
	}
	if err := c.flushBefore(ctx, "close"); err != nil {
		return err
	}
	var others []uint16
	for _, m := range c.st.Members() {
		if m.Idx != c.st.Idx() {
			others = append(others, m.Idx)
		}
	}
	if len(others) > 0 {
		body, err := json.Marshal(room.RosterBody{Removed: others})
		if err != nil {
			return err
		}
		seq, _, err := c.post(ctx, membershipPost{kind: room.KindRoster, body: body, bump: true})
		switch {
		case errors.Is(err, errQueued):
			return fmt.Errorf("the removal of %d members is committed and did not land (%v): run peer serve, then peer room close %s again", len(others), err, c.ref.Name)
		case errors.Is(err, errMoot): // every other member is out of the roster already
		case err != nil:
			return err
		default:
			fmt.Fprintf(out, "room %s: %d members removed (record #%d, membership bumped)\n", c.ref.Name, len(others), seq)
		}
	}
	if left := c.finishRemovals(ctx); len(left) > 0 {
		return fmt.Errorf("room %s: the revoke of idx %v did not land; run peer room close %s again", c.ref.Name, left, c.ref.Name)
	}
	if err := c.closeLink(ctx); err != nil {
		return fmt.Errorf("room %s: %v; run peer room close %s again", c.ref.Name, err, c.ref.Name)
	}
	if err := c.closeSeats(ctx); err != nil {
		return fmt.Errorf("room %s: %v; run peer room close %s again", c.ref.Name, err, c.ref.Name)
	}
	if c.st.Member(c.st.Idx()) != nil {
		seq, _, err := c.postMembership(ctx, room.KindLeave, []byte("{}"))
		if errors.Is(err, errQueued) {
			return fmt.Errorf("your leave record is committed and did not land (%v): run peer serve, then peer room close %s again", err, c.ref.Name)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "room %s: leave record #%d\n", c.ref.Name, seq)
	}
	if err := c.revokeSelf(ctx); err != nil {
		return fmt.Errorf("room %s: %v; run peer room close %s again", c.ref.Name, err, c.ref.Name)
	}
	c.gone(ctx, stageClosed)
	fmt.Fprintf(out, "closed room %s (%s): every token revoked, the state dropped\n", c.ref.Name, c.ref.ID)
	return nil
}

// runRoomRotate rotates the seal key by hand, due or not.
func runRoomRotate(ctx context.Context, dir, name string, out io.Writer) error {
	c, err := openJoined(ctx, dir, name, out)
	if err != nil {
		return err
	}
	return c.rotate(ctx, roomClock(), true)
}

// closeSeats is close's end of every seat the relay serves outside the fold
// — a feed's link this state does not hold, a stray mint: it lists the
// relay's members and queues each live one the fold does not hold on the
// removals' revoke queue, then drains it; a revoke the relay did not answer
// stays queued for serve and the next close, and refuses the close.
func (c *roomConn) closeSeats(ctx context.Context) error {
	ms, err := c.rc.ListMembers(ctx, c.ref.ID, c.ref.Token)
	if err != nil {
		return fmt.Errorf("the relay's members are not listed: %w", err)
	}
	c.st.ObserveMembership(ms.Membership)
	var unheld []uint16
	for _, m := range ms.Members {
		idx := uint16(m.Idx)
		if !m.Revoked && idx != c.st.Idx() && c.st.Member(idx) == nil {
			unheld = append(unheld, idx)
		}
	}
	if len(unheld) > 0 {
		err := updateRooms(ctx, c.p.backend, func(l *roomList) error {
			r := l.byID(c.ref.ID)
			if r == nil {
				return fmt.Errorf("room %s left the rooms record under this command", c.ref.Name)
			}
			for _, idx := range unheld {
				if !slices.Contains(r.Removals, idx) {
					r.Removals = append(r.Removals, idx)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("the revoke of the seats outside the roster (idx %v) is not queued: %w", unheld, err)
		}
		fmt.Fprintf(c.out, "room %s: the relay serves idx %v outside the roster; revoking\n", c.ref.Name, unheld)
	}
	if left := c.finishRemovals(ctx); len(left) > 0 {
		return fmt.Errorf("the revoke of idx %v did not land", left)
	}
	return nil
}

// finishRemovals revokes the idxs whose removal record landed and whose
// revoke has not (the rooms record's removals), and returns those still
// waiting. The relay's revoke is idempotent, so a retry is safe.
func (c *roomConn) finishRemovals(ctx context.Context) []uint16 {
	l, err := loadRooms(ctx, c.p.backend)
	if err != nil {
		fmt.Fprintf(c.out, "room %s: %v\n", c.ref.Name, err)
		return nil
	}
	ref := l.byID(c.ref.ID)
	if ref == nil || len(ref.Removals) == 0 {
		return nil
	}
	var left []uint16
	for _, idx := range ref.Removals {
		_, err := c.rc.RemoveMember(ctx, c.ref.ID, c.ref.Token, int(idx))
		if err != nil && !errors.Is(err, relay.ErrNoSuchMember) {
			fmt.Fprintf(c.out, "room %s: the revoke of idx %d did not land (%v); serve tries again\n", c.ref.Name, idx, err)
			left = append(left, idx)
			continue
		}
		fmt.Fprintf(c.out, "room %s: idx %d revoked\n", c.ref.Name, idx)
	}
	err = updateRooms(ctx, c.p.backend, func(l *roomList) error {
		if r := l.byID(c.ref.ID); r != nil {
			r.Removals = slices.DeleteFunc(r.Removals, func(idx uint16) bool { return !slices.Contains(left, idx) })
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(c.out, "room %s: the revokes are not recorded: %v\n", c.ref.Name, err)
	}
	return left
}

// finishHandovers grants and sends the token of every handover whose record
// landed and whose token has not gone out: POST …/admin once (the token is
// stored), then room-admin over the channel.
func (c *roomConn) finishHandovers(ctx context.Context) {
	l, err := loadRooms(ctx, c.p.backend)
	if err != nil {
		fmt.Fprintf(c.out, "room %s: %v\n", c.ref.Name, err)
		return
	}
	ref := l.byID(c.ref.ID)
	if ref == nil {
		return
	}
	var r *roster.Roster
	for _, h := range ref.Handovers {
		if !h.Recorded || h.Sent {
			continue
		}
		if h.Token == "" {
			tok, membership, err := c.rc.GrantAdmin(ctx, c.ref.ID, c.ref.Token, int(h.Idx))
			if err != nil {
				fmt.Fprintf(c.out, "room %s: the admin token for %s (idx %d) was not granted (%v); serve tries again\n", c.ref.Name, h.Peer, h.Idx, err)
				continue
			}
			c.st.ObserveMembership(membership)
			h.Token = tok
			err = updateRooms(ctx, c.p.backend, func(l *roomList) error {
				if cur := l.byID(c.ref.ID); cur != nil {
					if ph := cur.handover(h.Channel); ph != nil {
						ph.Token = tok
					}
				}
				return nil
			})
			if err != nil {
				fmt.Fprintf(c.out, "room %s: the admin token for %s is granted and not recorded: %v\n", c.ref.Name, h.Peer, err)
				continue
			}
		}
		if r == nil {
			if r, err = roster.Load(ctx, c.p.backend); err != nil {
				fmt.Fprintf(c.out, "room %s: %v\n", c.ref.Name, err)
				return
			}
		}
		pe := r.ByChannel(h.Channel)
		if pe == nil {
			continue
		}
		if err := c.p.sendOnChannel(ctx, *pe, kindRoomAdmin, roomAdmin{Room: c.ref.ID, Token: h.Token}, c.out); err != nil {
			fmt.Fprintf(c.out, "room %s: the admin token for %s did not go out: %v\n", c.ref.Name, h.Peer, err)
			continue
		}
		err = updateRooms(ctx, c.p.backend, func(l *roomList) error {
			if cur := l.byID(c.ref.ID); cur != nil {
				if ph := cur.handover(h.Channel); ph != nil {
					ph.Sent = true
				}
			}
			return nil
		})
		if err != nil {
			fmt.Fprintf(c.out, "room %s: the admin token went to %s and the rooms record does not say so (%v)\n", c.ref.Name, h.Peer, err)
			continue
		}
		fmt.Fprintf(c.out, "room %s: %s (idx %d) is an admin; its token went out\n", c.ref.Name, h.Peer, h.Idx)
	}
}

// markHandedOver records that a handover record landed: its token may go out.
func (c *roomConn) markHandedOver(ctx context.Context, idx uint16) {
	err := updateRooms(ctx, c.p.backend, func(l *roomList) error {
		if r := l.byID(c.ref.ID); r != nil {
			for i := range r.Handovers {
				if r.Handovers[i].Idx == idx {
					r.Handovers[i].Recorded = true
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(c.out, "room %s: the handover record landed and the rooms record does not say so: %v\n", c.ref.Name, err)
	}
}

// checkRevoked is how an admin's host sees a reader gone: GET …/members,
// and a roster record removing every revoked idx the fold still holds.
func (c *roomConn) checkRevoked(ctx context.Context) {
	ms, err := c.rc.ListMembers(ctx, c.ref.ID, c.ref.Token)
	if err != nil {
		fmt.Fprintf(c.out, "room %s: members: %v\n", c.ref.Name, err)
		return
	}
	c.st.ObserveMembership(ms.Membership)
	var gone []uint16
	for _, m := range ms.Members {
		if m.Revoked && m.Idx != int(c.st.Idx()) && c.st.Member(uint16(m.Idx)) != nil {
			gone = append(gone, uint16(m.Idx))
		}
	}
	if len(gone) == 0 {
		return
	}
	body, err := json.Marshal(room.RosterBody{Removed: gone})
	if err != nil {
		return
	}
	seq, _, err := c.post(ctx, membershipPost{kind: room.KindRoster, body: body, bump: true})
	if errors.Is(err, errMoot) {
		return // another admin's removal folded first
	}
	if err != nil {
		fmt.Fprintf(c.out, "room %s: idx %v left (token revoked) and the roster record did not land: %v\n", c.ref.Name, gone, err)
		return
	}
	fmt.Fprintf(c.out, "room %s: idx %v left (token revoked); roster record #%d\n", c.ref.Name, gone, seq)
}

// rotate replaces the seal key when the daily rotation is due, or on
// force: a write member posts the roomcard (the key swap and the own fold in
// one Commit, rule 9); a read member sends its card over the channel.
func (c *roomConn) rotate(ctx context.Context, now time.Time, force bool) error {
	if c.ref.Read {
		return c.rotateViaChannel(ctx, now, force)
	}
	st := c.st
	// A rotation whose roomcard neither waits in this host's outbox nor was
	// recorded as posted, past the grace another host's put takes, lost its
	// post between the Commit and the outbox: the current key is announced.
	lost := st.RotationPending() && !c.waitingKind(room.KindRoomCard) && now.Sub(st.LastRotated()) > rotationGrace
	if !force && !st.RotationDue(now) && !lost {
		return nil
	}
	if st.RotationPending() && !lost {
		fmt.Fprintf(c.out, "room %s: a rotation is in flight; its roomcard is on its way\n", c.ref.Name)
		return nil
	}
	prep := func(st *room.State) ([]byte, bool, error) {
		switch {
		case st.RotationPending():
			if !lost || now.Sub(st.LastRotated()) <= rotationGrace {
				return nil, true, nil // another host rotated; its roomcard is on its way
			}
		case !force && !st.RotationDue(now):
			return nil, true, nil // another host rotated and posted
		default:
			k, err := room.GenerateSealKey()
			if err != nil {
				return nil, false, err
			}
			st.Rotate(k, now)
		}
		signed, err := st.OwnCard(now).Signed(c.p.id)
		if err != nil {
			return nil, false, err
		}
		body, err := json.Marshal(room.RoomCardBody{RoomCard: signed})
		return body, false, err
	}
	seq, _, err := c.post(ctx, membershipPost{kind: room.KindRoomCard, prep: prep})
	switch {
	case errors.Is(err, errMoot):
		fmt.Fprintf(c.out, "room %s: another host rotated the seal key; reading its roomcard\n", c.ref.Name)
		return nil
	case errors.Is(err, errQueued):
		fmt.Fprintf(c.out, "room %s: seal key rotated; the roomcard waits in the room outbox (%v)\n", c.ref.Name, err)
		return nil
	case errors.Is(err, relay.ErrReadOnly):
		c.markRead(ctx)
		return c.sendCard(ctx, now)
	case err != nil:
		return err
	}
	fmt.Fprintf(c.out, "room %s: seal key rotated; roomcard #%d\n", c.ref.Name, seq)
	return nil
}

// rotateViaChannel is a read member's rotation: the key swap committed,
// then the card to an admin over the channel; a card the admin has not
// announced after RotateEvery goes again.
func (c *roomConn) rotateViaChannel(ctx context.Context, now time.Time, force bool) error {
	st := c.st
	if !st.RotationPending() {
		if !force && !st.RotationDue(now) {
			return nil
		}
		for try := 1; ; try++ {
			k, err := room.GenerateSealKey()
			if err != nil {
				return err
			}
			st.Rotate(k, now)
			err = st.Commit(ctx)
			if err == nil {
				break
			}
			if !errors.Is(err, store.ErrConflict) || try >= sendTries {
				return err
			}
			if err := c.reload(ctx); err != nil {
				return err
			}
			if c.st.RotationPending() {
				fmt.Fprintf(c.out, "room %s: another host rotated the seal key; its card goes out from there\n", c.ref.Name)
				return nil
			}
			st = c.st
		}
	} else if !force && now.Before(c.ref.CardSent.Add(room.RotateEvery)) {
		return nil
	}
	return c.sendCard(ctx, now)
}

// sendCard sends this party's room card, signed by its identity key now,
// to an admin over the channel as a room-join: the admin's roster entry
// announces it to the room.
func (c *roomConn) sendCard(ctx context.Context, now time.Time) error {
	pe, err := c.adminPeer(ctx)
	if err != nil {
		return err
	}
	signed, err := c.st.OwnCard(now).Signed(c.p.id)
	if err != nil {
		return err
	}
	if err := c.p.sendOnChannel(ctx, *pe, kindRoomJoin, roomJoin{Room: c.ref.ID, RoomCard: signed}, c.out); err != nil {
		return err
	}
	c.ref.CardSent = now
	err = updateRooms(ctx, c.p.backend, func(l *roomList) error {
		if r := l.byID(c.ref.ID); r != nil {
			r.CardSent = now
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "room %s: your room card went to %s over the channel; an admin's roster entry announces it\n", c.ref.Name, pe.Name)
	return nil
}

// adminPeer is an admin of the room this party holds a confirmed channel
// with — the one the invite came over when it is still an admin.
func (c *roomConn) adminPeer(ctx context.Context) (*roster.Peer, error) {
	r, err := roster.Load(ctx, c.p.backend)
	if err != nil {
		return nil, err
	}
	_, names, err := c.p.channelRoots(ctx)
	if err != nil {
		return nil, err
	}
	var pick *roster.Peer
	for _, a := range c.st.Admins() {
		m := c.st.Member(a)
		if m == nil {
			continue
		}
		n, ok := names[m.Party]
		if !ok {
			continue
		}
		pe := r.ByName(n)
		if pe == nil {
			continue
		}
		if pe.Channel == c.ref.Via {
			return pe, nil
		}
		if pick == nil {
			pick = pe
		}
	}
	if pick == nil {
		return nil, fmt.Errorf("room %s: no admin of it is on a confirmed channel of yours, so your room card cannot reach the room", c.ref.Name)
	}
	return pick, nil
}

// recard announces an identity change to the room: when the folded own
// party card no longer names this party's identity key as current, an admin
// posts a roster entry with the new party card and a room card re-signed by
// the new key, same idx — itself, or the admin its card goes to over the
// channel.
func (c *roomConn) recard(ctx context.Context, now time.Time) error {
	own := c.st.Member(c.st.Idx())
	if own == nil {
		return nil
	}
	var pc card.Card
	if err := json.Unmarshal(own.Card.Body, &pc); err != nil {
		return nil
	}
	if cur, err := session.CurrentKey(&pc); err == nil && cur.Identity == keys.CurveText(c.p.id.PublicKey()) {
		return nil
	}
	if !c.st.IsAdmin(c.st.Idx()) || c.ref.Read {
		if now.Before(c.ref.CardSent.Add(room.RotateEvery)) {
			return nil
		}
		return c.sendCard(ctx, now)
	}
	signedParty, _, _, err := c.p.ownCard(ctx, false)
	if err != nil {
		return fmt.Errorf("room %s: your identity key changed and your card is not on the state (%v); peer card publish puts it there", c.ref.Name, err)
	}
	signed, err := c.st.OwnCard(now).Signed(c.p.id)
	if err != nil {
		return err
	}
	entry := room.Entry{Idx: own.Idx, Party: own.Party, Card: room.PartyCard{Body: signedParty.Body, Sig: signedParty.Sig}, RoomCard: signed}
	body, err := json.Marshal(room.RosterBody{Members: []room.Entry{entry}})
	if err != nil {
		return err
	}
	seq, _, err := c.postMembership(ctx, room.KindRoster, body)
	if errors.Is(err, errQueued) {
		fmt.Fprintf(c.out, "room %s: the roster entry with your new identity key is committed and waits in the room outbox (%v)\n", c.ref.Name, err)
		return nil
	}
	if errors.Is(err, errMoot) {
		return nil // the entry carries this key already
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "room %s: roster entry #%d announces your new identity key\n", c.ref.Name, seq)
	return nil
}

// retire drops the retired seal keys whose time is up (rule 3) and commits.
func (c *roomConn) retire(ctx context.Context, now time.Time) {
	n := c.st.Retire(now)
	if n == 0 {
		return
	}
	if err := c.st.Commit(ctx); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			fmt.Fprintf(c.out, "room %s: %d retired seal keys dropped and not committed: %v\n", c.ref.Name, n, err)
		}
		c.reload(ctx)
		return
	}
	fmt.Fprintf(c.out, "room %s: %d retired seal key(s) dropped\n", c.ref.Name, n)
}
