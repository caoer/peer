package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/sealed"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// The room outbox (contract § Kinds, the closing list), v1's send order for a
// room: the room state's Commit consumes the record's ctr, then the record —
// room, ctr, kind, and the message JSON with its to — is journaled in this
// host's own <dir>/room-outbox, then put. The relay's {seq} removes it. A
// transport failure leaves it there, and the next send or serve round puts
// the room's waiting records in ctr order; a 409 folds the room to head and
// seals the same plaintext at the same ctr to the roster as it then stands.
// Each host retries its own records, and the state's Commit keeps ctrs unique
// across hosts; nothing of a waiting record lives in the shared state.
//
// On one host the room's outbox lock keeps each entry to one put: a send
// holds it from the entry's Add to its put's answer, and every flush holds it
// over its pass, so a serve round beside a running peer send never puts the
// send's record too — a second seal of the same ctr, under a fresh content
// key and so a second kh, that every receiver refuses as a step back (C9
// finding 2).
//
// An entry is a store.Entry: ID the message id, Channel the room id, Seq the
// record's ctr, Type its kind, Body the message JSON.
const roomOutboxDir = "room-outbox"

// errQueued is a record whose ctr is committed and whose put did not land:
// it waits in the room outbox.
var errQueued = errors.New("it waits in the room outbox")

// errUnputtable is a waiting record no retry can put: dropped from the outbox.
var errUnputtable = errors.New("the record cannot be put")

// permanentRoomPut reports whether a room put failed for good: the relay
// refused the token, the role or the bytes, or the record itself cannot be
// sealed. Anything else — a 5xx, a timeout, rate limiting, a 409 three times
// — waits for the next round.
func permanentRoomPut(err error) bool {
	if errors.Is(err, errUnputtable) || errors.Is(err, sealed.ErrTooLarge) {
		return true
	}
	for _, p := range []*relay.Error{
		relay.ErrReadOnly, relay.ErrRevoked, relay.ErrNotAdmin, relay.ErrNoSuchRoom,
		relay.ErrBadToken, relay.ErrTooLarge, relay.ErrBadRequest,
	} {
		if errors.Is(err, p) {
			return true
		}
	}
	return false
}

// send puts m at ctr — consumed by a Commit the caller made — through the
// room outbox: journaled, then the room's waiting records put in ctr order,
// so a receiver's counter gap names a record that never landed. It returns
// m's seq; an error wrapping errQueued says m waits in the outbox.
func (c *roomConn) send(ctx context.Context, m *roomMessage, ctr uint64) (int64, error) {
	return c.sendEntry(ctx, m, ctr, false)
}

// sendEntry is send with the entry's bump flag: a removal record bumps the
// membership version with its put, however often the put is retried.
func (c *roomConn) sendEntry(ctx context.Context, m *roomMessage, ctr uint64, bump bool) (int64, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return 0, err
	}
	e := &store.Entry{ID: m.ID, Channel: c.ref.ID, Seq: int64(ctr), Type: m.Kind, Body: plain, Bump: bump}
	unlock, err := c.p.roomOutbox.Lock(c.ref.ID, true)
	if err != nil {
		return 0, fmt.Errorf("room %s: ctr %d is committed and the room outbox did not take the record: %w", c.ref.Name, ctr, err)
	}
	defer unlock()
	if err := c.p.roomOutbox.Add(e); err != nil {
		return 0, fmt.Errorf("room %s: ctr %d is committed and the room outbox did not take the record: %w", c.ref.Name, ctr, err)
	}
	if err := c.p.roomOutbox.MarkCommitted(e); err != nil {
		return 0, fmt.Errorf("room %s: ctr %d is committed and the room outbox did not take the record: %w", c.ref.Name, ctr, err)
	}
	res := c.flushLocked(ctx)
	if seq, ok := res.put[m.ID]; ok {
		return seq, nil
	}
	if err, ok := res.dropped[m.ID]; ok {
		return 0, err
	}
	return 0, fmt.Errorf("%w: %v", errQueued, res.wait)
}

// flushResult is one pass over a room's waiting records.
type flushResult struct {
	put     map[string]int64 // message id → the relay's seq
	dropped map[string]error // message id → why it can never be put
	wait    error            // what the rest wait on; nil when none wait
}

// flush puts this room's waiting records under the room's outbox lock. wait
// blocks on another process's pass, as a command does before its leave or
// close; serve's round passes false, and a lock another process holds — a
// peer send putting its record now — leaves the room's records to it and to
// the next round.
func (c *roomConn) flush(ctx context.Context, wait bool) flushResult {
	res := flushResult{put: map[string]int64{}, dropped: map[string]error{}}
	unlock, err := c.p.roomOutbox.Lock(c.ref.ID, wait)
	if errors.Is(err, store.ErrBusy) {
		return res
	}
	if err != nil {
		res.wait = err
		return res
	}
	defer unlock()
	return c.flushLocked(ctx)
}

// flushLocked puts this room's waiting records in ctr order, the lock held,
// stopping at the first that fails on something passing; one the relay can
// never take is dropped with its reason and the next is tried.
func (c *roomConn) flushLocked(ctx context.Context) flushResult {
	res := flushResult{put: map[string]int64{}, dropped: map[string]error{}}
	all, err := c.p.roomOutbox.Entries()
	if err != nil {
		res.wait = err
		return res
	}
	var es []*store.Entry
	for _, e := range all {
		if e.Channel == c.ref.ID {
			es = append(es, e)
		}
	}
	slices.SortStableFunc(es, func(a, b *store.Entry) int { return int(a.Seq - b.Seq) })
	for _, e := range es {
		seq, err := c.putEntry(ctx, e)
		switch {
		case err == nil:
			res.put[e.ID] = seq
		case permanentRoomPut(err):
			res.dropped[e.ID] = err
			fmt.Fprintf(c.out, "room %s: the %s %s (ctr %d) is dropped from the room outbox: %v\n", c.ref.Name, e.Type, e.ID, e.Seq, err)
		default:
			res.wait = err
			return res
		}
		if err := c.p.roomOutbox.Remove(e); err != nil {
			res.wait = err
			return res
		}
	}
	return res
}

// putEntry seals a waiting record at its ctr to the roster as the state
// holds it and puts it at the state's membership version; a 409 folds the
// room to head and seals it again, the same plaintext and ctr.
func (c *roomConn) putEntry(ctx context.Context, e *store.Entry) (int64, error) {
	var m roomMessage
	if err := json.Unmarshal(e.Body, &m); err != nil {
		return 0, fmt.Errorf("%w: %v", errUnputtable, err)
	}
	ctr := uint64(e.Seq)
	for try := 1; ; try++ {
		b, err := c.seal(&m, e.Body, ctr)
		if err != nil {
			return 0, err
		}
		rcpt, err := c.rc.PutRecord(ctx, c.ref.ID, c.ref.Token, b, c.st.Membership(), e.Bump)
		if err == nil {
			c.landed(ctx, e, rcpt)
			return rcpt.Seq, nil
		}
		if !errors.Is(err, relay.ErrStaleMembership) || try >= putTries {
			return 0, fmt.Errorf("room %s: put: %w", c.ref.Name, err)
		}
		// The roster moved: fold to head and seal to it.
		if err := c.pull(ctx); err != nil {
			return 0, err
		}
	}
}

// landed records what a put's answer says: the membership version, the seq
// of an own roomcard — or of a roster entry carrying this party's own card
// (rule 3 reads it before a replaced seal key retires) — and, for a roster
// record, the adds it carried, whose token goes out next, and the removals,
// whose revoke follows.
func (c *roomConn) landed(ctx context.Context, e *store.Entry, rcpt relay.RoomReceipt) {
	var body room.RosterBody
	if e.Type == room.KindRoster {
		var m roomMessage
		if json.Unmarshal(e.Body, &m) != nil || json.Unmarshal(m.Body, &body) != nil {
			body = room.RosterBody{}
		}
	}
	own := slices.ContainsFunc(body.Members, func(en room.Entry) bool { return en.Idx == c.st.Idx() })
	for try := 1; ; try++ {
		c.st.ObserveMembership(rcpt.Membership)
		if e.Type == room.KindRoomCard || own {
			c.st.Posted(rcpt.Seq)
		}
		err := c.st.Commit(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			fmt.Fprintf(c.out, "room %s: #%d landed and the room state does not record it: %v\n", c.ref.Name, rcpt.Seq, err)
			break
		}
		if err := c.reload(ctx); err != nil {
			fmt.Fprintf(c.out, "room %s: #%d landed and the room state does not record it: %v\n", c.ref.Name, rcpt.Seq, err)
			break
		}
	}
	if len(body.Members) > 0 || len(body.Removed) > 0 {
		c.markRostered(ctx, body)
	}
	if e.Type == room.KindHandover {
		var m roomMessage
		var h room.HandoverBody
		if json.Unmarshal(e.Body, &m) == nil && json.Unmarshal(m.Body, &h) == nil {
			c.markHandedOver(ctx, h.Idx)
		}
	}
}

// markRostered records what a landed roster record did on the rooms record:
// the adds it carried move to rostered — rule 2 lets their token go out now
// (finishAdds) — and the idxs it removed wait for their revoke
// (finishRemovals).
func (c *roomConn) markRostered(ctx context.Context, body room.RosterBody) {
	err := updateRooms(ctx, c.p.backend, func(l *roomList) error {
		r := l.byID(c.ref.ID)
		if r == nil {
			return nil
		}
		for i := range r.Adds {
			a := &r.Adds[i]
			if (a.Stage == addMinted || a.Stage == addSeated) && slices.ContainsFunc(body.Members, func(en room.Entry) bool { return en.Idx == a.Idx }) {
				a.Stage = addRostered
			}
		}
		for _, idx := range body.Removed {
			if !slices.Contains(r.Removals, idx) {
				r.Removals = append(r.Removals, idx)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(c.out, "room %s: the roster record landed and the rooms record does not say so: %v\n", c.ref.Name, err)
	}
}

// finishAdds sends the token of every add whose roster record landed and
// whose token has not gone out — a roster record that waited in the room
// outbox, or a round cut between the two (rule 2: the token after the
// roster record).
func (p *party) finishAdds(ctx context.Context, ref roomRef, out io.Writer) {
	var r *roster.Roster
	for _, a := range ref.Adds {
		if a.Stage != addRostered {
			continue
		}
		if r == nil {
			var err error
			if r, err = roster.Load(ctx, p.backend); err != nil {
				fmt.Fprintf(out, "room %s: %v\n", ref.Name, err)
				return
			}
		}
		pe := r.ByChannel(a.Channel)
		if pe == nil {
			continue
		}
		if err := p.sendOnChannel(ctx, *pe, kindRoomToken, roomTokenMessage(ref.ID, &a), out); err != nil {
			fmt.Fprintf(out, "room %s: the token for %s (idx %d) did not go out: %v\n", ref.Name, a.Peer, a.Idx, err)
			continue
		}
		if err := dropPendingAdd(ctx, p.backend, ref.ID, a.Channel); err != nil {
			fmt.Fprintf(out, "room %s: the token went to %s; the add is still listed (%v)\n", ref.Name, a.Peer, err)
			continue
		}
		fmt.Fprintf(out, "room %s: %s is idx %d; its token went out\n", ref.Name, a.Peer, a.Idx)
	}
}

// seal locks m's plaintext at ctr to its recipients: every member, or the
// members whose party its to names. One recipient whose key takes no stanza
// does not cost the rest the record (format review M1): it is named, and the
// record is sealed to the others.
func (c *roomConn) seal(m *roomMessage, plain []byte, ctr uint64) ([]byte, error) {
	to := c.recipients(m)
	if len(to) == 0 {
		if m.Kind != room.KindLeave {
			return nil, fmt.Errorf("%w: nobody its to names is in room %s", errUnputtable, c.ref.Name)
		}
		// The admin's own leave after a close has no reader left: it is on
		// the wire for the relay's log, sealed to its own idx.
		to = []sealed.Recipient{{Idx: c.st.Idx(), Key: c.st.SealKey().PublicKey()}}
	}
	h := sealed.Header{Room: c.ref.ID, Idx: c.st.Idx(), Ctr: ctr, At: m.At}
	b, err := sealed.Seal(h, plain, to, c.st.SignKey())
	if err == nil || errors.Is(err, sealed.ErrTooLarge) {
		return b, err
	}
	var ok []sealed.Recipient
	for _, r := range to {
		if _, perr := sealed.Seal(h, nil, []sealed.Recipient{r}, c.st.SignKey()); perr != nil {
			fmt.Fprintf(c.out, "room %s: idx %d gets no stanza (%v); the record goes to the rest\n", c.ref.Name, r.Idx, perr)
			continue
		}
		ok = append(ok, r)
	}
	if len(ok) == 0 || len(ok) == len(to) {
		return nil, fmt.Errorf("%w: %v", errUnputtable, err)
	}
	return sealed.Seal(h, plain, ok, c.st.SignKey())
}

// recipients is a record's stanza list: every member for the whole room, or
// the members whose party m's to names — a subset's stanzas say what its to
// says.
func (c *roomConn) recipients(m *roomMessage) []sealed.Recipient {
	named := map[string]bool{}
	for _, t := range m.To {
		party, _ := splitAddr(t)
		named[party] = true
	}
	var out []sealed.Recipient
	for _, mem := range c.st.Members() {
		if len(m.To) == 0 || named[mem.Party] {
			out = append(out, sealed.Recipient{Idx: mem.Idx, Key: mem.Seal()})
		}
	}
	// A feed's whole-room record of a v1 kind carries the link stanza at idx
	// 65535 beside the members': a subset's stanzas say what its to says, and
	// a membership record is the members' alone (a link holder keeps no roster).
	if l := c.st.Link(); l != nil && len(out) > 0 && len(m.To) == 0 && !room.MembershipKind(m.Kind) {
		if k, err := room.LinkSealKey(l.Key, c.ref.ID); err == nil {
			out = append(out, sealed.Recipient{Idx: relay.FeedIdx, Key: k.PublicKey()})
		} else {
			fmt.Fprintf(c.out, "room %s: the link stanza is left off: %v\n", c.ref.Name, err)
		}
	}
	return out
}

// dropLeftRooms drops the waiting records of rooms this host no longer
// holds a token in: nothing can put them.
func (p *party) dropLeftRooms(l *roomList, out io.Writer) {
	es, err := p.roomOutbox.Entries()
	if err != nil {
		fmt.Fprintf(out, "room outbox: %v\n", err)
		return
	}
	for _, e := range es {
		if r := l.byID(e.Channel); r != nil && r.Stage == stageJoined {
			continue
		}
		if err := p.roomOutbox.Remove(e); err != nil {
			fmt.Fprintf(out, "room outbox: %v\n", err)
			continue
		}
		fmt.Fprintf(out, "room %s: the %s %s (ctr %d) is dropped from the room outbox: this host is not in the room\n", e.Channel, e.Type, e.ID, e.Seq)
	}
}

// waiting is how many of a room's records wait in this host's room outbox.
func (p *party) waiting(roomID string) int {
	es, _ := p.roomOutbox.Entries()
	n := 0
	for _, e := range es {
		if e.Channel == roomID {
			n++
		}
	}
	return n
}

// isRoomTarget reports whether peer send's target is a room: --to names one,
// or the name is a room's and no peer's. A name both carry is refused: the
// room is named by its id then.
func isRoomTarget(ctx context.Context, dir, target string, subset bool) (bool, error) {
	if strings.Contains(target, "/") {
		if subset {
			return false, fmt.Errorf("--to goes with a room, and %s names an agent: a room send names the room alone", target)
		}
		return false, nil
	}
	dir, err := peerDir(dir)
	if err != nil {
		return false, err
	}
	p, err := openParty(dir)
	if err != nil {
		return false, err
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return false, err
	}
	ref := l.byName(target)
	if subset {
		if ref == nil {
			return false, fmt.Errorf("no room named %s (--to names members of a room)", target)
		}
		return true, nil
	}
	if ref == nil {
		return false, nil
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return false, err
	}
	if r.ByName(target) != nil {
		return false, fmt.Errorf("both a peer and a room are named %s: name the room by its id, %s", target, ref.ID)
	}
	return true, nil
}

// runRoomSend sends one record into a room (plan C5): to head first, so the
// roster it is sealed to is the folded one; the subset --to names, each a
// member's peer name or party id with an optional agent; the ctr committed;
// then the room outbox and the put.
func runRoomSend(ctx context.Context, warn io.Writer, dir, name string, to []string, fromAgent, kind string, body []byte) (*sendResult, error) {
	switch {
	case kind == session.KindCard:
		return nil, errors.New("a card goes out with peer card publish, not peer send")
	case session.RoomKind(kind) || room.MembershipKind(kind):
		return nil, fmt.Errorf("a %s goes out with the peer room commands, not peer send", kind)
	case kind == session.KindDoc || kind == session.KindFile:
		return nil, fmt.Errorf("a %s goes to a peer: a room carries no blob in this version", kind)
	case !session.ValidKind(kind):
		return nil, fmt.Errorf("%w %q: a vendor kind is vnd.<party id>.<name>", session.ErrKind, kind)
	case fromAgent != "" && !deliver.ValidAgent(fromAgent):
		return nil, fmt.Errorf("--from %q is not an agent id: letters, digits, dot, dash, underscore, at most 64", fromAgent)
	}
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
	c, err := p.openRoom(ctx, *ref, warn)
	if err != nil {
		return nil, err
	}
	if err := c.pull(ctx); err != nil {
		return nil, err
	}
	addrs, err := c.resolveTo(ctx, to)
	if err != nil {
		return nil, err
	}
	from := p.partyID()
	if fromAgent != "" {
		from += "/" + fromAgent
	}
	m, err := newRoomMessage(from, ref.ID, kind, body)
	if err != nil {
		return nil, err
	}
	m.To = addrs
	if len(c.recipients(m)) == 0 {
		return nil, fmt.Errorf("room %s: nobody --to names is in it", ref.Name)
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	// The cap is the relay's on the sealed record — the body less the
	// stanzas — so the record is measured sealed, before a ctr is spent on it.
	if b, err := c.seal(m, plain, math.MaxUint32); errors.Is(err, sealed.ErrTooLarge) || len(b) > relay.MaxSealed {
		return nil, fmt.Errorf("the message is %d bytes and a room record sealed to %d members holds at most %d bytes", len(plain), len(c.recipients(m)), relay.MaxSealed)
	} else if err != nil {
		return nil, err
	}
	var ctr uint64
	for try := 1; ; try++ {
		ctr = c.st.NextCounter()
		err := c.st.Commit(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			return nil, err
		}
		// Another host committed the room: its ctr may be taken, take the next.
		if err := c.reload(ctx); err != nil {
			return nil, err
		}
	}
	seq, err := c.send(ctx, m, ctr)
	res := &sendResult{id: m.ID, to: roomTo(ref.Name, to), kind: kind, seq: seq}
	if errors.Is(err, errQueued) {
		res.putErr = err
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// resolveTo reads --to: each a member's peer name — the confirmed channel
// whose root the roster holds — or its party id, with an optional /agent.
func (c *roomConn) resolveTo(ctx context.Context, to []string) ([]string, error) {
	if len(to) == 0 {
		return nil, nil
	}
	r, err := roster.Load(ctx, c.p.backend)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range to {
		name, agent := splitAddr(t)
		if strings.Contains(t, "/") && !deliver.ValidAgent(agent) {
			return nil, fmt.Errorf("--to %q: %q is not an agent id: letters, digits, dot, dash, underscore, at most 64", t, agent)
		}
		party := name
		if !deliver.ValidAddr(name) {
			pe := r.ByName(name)
			if pe == nil {
				return nil, fmt.Errorf("--to %q: no peer named %s", t, name)
			}
			ch, err := c.p.store.Channel(ctx, pe.Channel)
			if err != nil {
				return nil, err
			}
			if ch.Root() == nil {
				return nil, fmt.Errorf("--to %q: %s's card is not pinned yet", t, name)
			}
			party = keys.PartyID(ch.Root())
		}
		switch {
		case party == c.p.partyID():
			return nil, fmt.Errorf("--to %q names you: your own records never come back from the room", t)
		case !slices.ContainsFunc(c.st.Members(), func(m *room.Member) bool { return m.Party == party }):
			return nil, fmt.Errorf("--to %q: %s is not in room %s", t, name, c.ref.Name)
		}
		addr := party
		if agent != "" {
			addr += "/" + agent
		}
		if !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	return out, nil
}

// roomTo is how peer send names a room record's destination.
func roomTo(name string, to []string) string {
	if len(to) == 0 {
		return "room " + name
	}
	return fmt.Sprintf("room %s → %s", name, strings.Join(to, ", "))
}

// listFlag is a flag given as a comma list, or more than once.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(s string) error {
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, v)
		}
	}
	return nil
}
