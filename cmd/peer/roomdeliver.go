package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/seats"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// A room record of a v1 kind is delivered in decision 5's order, after the
// contract's receiver order: the border (roomBorder), a spool entry in this
// host's <dir>/room-spool, the room state's Commit — cursor, seen id and
// counter in one write — and the birth from the spool (settle). A host that
// loses the Commit drops its entry and pulls again from the winner's cursor,
// so two hosts serving one state birth each record once; a birth a crash cut
// after the Commit comes from the spool on the next round or start. A birth
// that waits on a seat's session keeps its entry, committed, and the pull
// goes on past it: every round's replay births it once the session is on
// this root.
//
// A spool entry is a store.Entry: ID the message id, Channel the room id, Seq
// the relay seq, Type "room", Body the message JSON.
const roomSpoolDir = "room-spool"

// roomTarget is one place a room record is born: a record under dir/place
// with its to, or a service row's callback.
type roomTarget struct {
	dir   string
	place deliver.Place
	to    string
	svc   *seats.Row
}

// roomTargets is where a room record lands here (plan decision 3). Its to
// names this party bare, or names nobody — the whole room: without ucc, one
// record in the delivery directory; under ucc, one in the session of each
// row whose rooms column names the room, and with none, one in the local
// quarantine. Its to names agents of this party: each reaches its label as a
// channel message does — the agent's accepts without ucc, the label's row
// under it; a label the map does not carry is refused and named. The second
// return lists the refusals; an error says nothing here takes the record.
func (sv *server) roomTargets(name, id string, m *roomMessage) ([]roomTarget, []error, error) {
	self := sv.p.partyID()
	whole := len(m.To) == 0
	named := whole
	var agents []string
	for _, t := range m.To {
		party, agent := splitAddr(t)
		if party != self {
			continue
		}
		named = true
		if agent == "" {
			whole = true
		} else if !slices.Contains(agents, agent) {
			agents = append(agents, agent)
		}
	}
	if !named {
		return nil, nil, errors.New("its to does not name this party")
	}
	var out []roomTarget
	var refused []error
	add := func(t roomTarget) {
		for _, o := range out {
			if o.dir == t.dir && o.place == t.place && (o.svc == nil) == (t.svc == nil) && (o.svc == nil || o.svc.URL == t.svc.URL) {
				return
			}
		}
		out = append(out, t)
	}
	if whole {
		switch rows := sv.roomRows(name, id); {
		case sv.seats == nil:
			add(roomTarget{dir: sv.dir, place: deliver.Route(m.Kind, nil), to: self})
		case len(rows) == 0:
			add(roomTarget{dir: sv.dir, place: deliver.Quarantine, to: self})
		default:
			for _, r := range rows {
				add(roomTarget{dir: sv.sessionDir(r), place: deliver.Route(m.Kind, r.Accepts), to: self + "/" + r.Label})
			}
		}
	}
	for _, agent := range agents {
		to := self + "/" + agent
		if sv.seats == nil {
			add(roomTarget{dir: sv.dir, place: deliver.Route(m.Kind, sv.p.accepts(agent)), to: to})
			continue
		}
		row, err := sv.seatRow(to)
		switch {
		case err != nil:
			refused = append(refused, err)
		case row.Kind == seats.Service:
			add(roomTarget{svc: &row, to: to})
		default:
			add(roomTarget{dir: sv.sessionDir(row), place: deliver.Route(m.Kind, row.Accepts), to: to})
		}
	}
	if len(out) == 0 {
		return nil, refused, errors.Join(refused...)
	}
	return out, refused, nil
}

// roomRows is the seat map's rows for the room, none without ucc.
func (sv *server) roomRows(name, id string) []seats.Row {
	if sv.seats == nil {
		return nil
	}
	return sv.seats.InRoom(name, id)
}

// roomBorder is the border a room record crosses before the spool and the
// Commit: a kind delivered from a room, a to of protocol addresses naming
// this party, somewhere here to take it. An error is consumed with its
// reason. A seat whose session is not on this root yet does not stop the
// record here: it waits at the birth (birthRoom), in the spool.
func (sv *server) roomBorder(ref roomRef, m *roomMessage) error {
	switch {
	case !session.ValidKind(m.Kind) || m.Kind == session.KindCard || session.RoomKind(m.Kind):
		return fmt.Errorf("a %s is not delivered from a room", m.Kind)
	case !deliver.ValidID(m.ID):
		return fmt.Errorf("message id %q cannot name a file", m.ID)
	}
	for _, t := range m.To {
		if !deliver.ValidAddr(t) {
			return fmt.Errorf("to %q is not a protocol address", t)
		}
	}
	_, refused, err := sv.roomTargets(ref.Name, ref.ID, m)
	if err != nil {
		return err
	}
	for _, r := range refused {
		fmt.Fprintf(sv.out, "room %s: %s %s: %v\n", ref.Name, m.Kind, m.ID, r)
	}
	return nil
}

// deliverRecord is the pull's step for an opened record of a v1 kind: the
// border, then the spool entry the Commit settles.
func (c *roomConn) deliverRecord(seq int64, m *roomMessage) error {
	e, err := c.sv.spoolRoom(c.ref, seq, m, c.skip)
	if e != nil {
		c.pending = append(c.pending, e)
	}
	return err
}

// spoolRoom is any room reader's delivery step: the border, then the spool
// entry. A record the border consumes is said through skip and yields no
// entry.
func (sv *server) spoolRoom(ref roomRef, seq int64, m *roomMessage, skip func(int64, string, ...any)) (*store.Entry, error) {
	if err := sv.roomBorder(ref, m); err != nil {
		skip(seq, "%s %s: %v", m.Kind, m.ID, err)
		return nil, nil
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	e := &store.Entry{ID: m.ID, Channel: ref.ID, Seq: seq, Type: "room", Body: plain}
	if err := sv.roomSpool.Add(e); err != nil {
		return nil, err
	}
	return e, nil
}

// dropPending forgets the spool entries a Commit did not carry: another
// host's state is the truth and the records come again from its cursor.
func (c *roomConn) dropPending() {
	c.sv.dropSpool(c.pending)
	c.pending = nil
}

func (sv *server) dropSpool(pending []*store.Entry) {
	for _, e := range pending {
		sv.roomSpool.Remove(e)
	}
}

// settle births the spool entries the Commit just carried.
func (c *roomConn) settle() error {
	pending := c.pending
	c.pending = nil
	return c.sv.settleSpool(pending, c.ref.Name)
}

// settleSpool births committed spool entries of room name, each removed
// from the spool once born; one whose birth waits on a seat's session stays,
// and a command's server marks them committed and leaves them for serve
// (commandServer).
func (sv *server) settleSpool(pending []*store.Entry, name string) error {
	for _, e := range pending {
		if err := sv.roomSpool.MarkCommitted(e); err != nil {
			return err
		}
		if sv.command {
			fmt.Fprintf(sv.out, "room %s #%d: %s is in the room spool; peer serve delivers it\n", name, e.Seq, e.ID)
			continue
		}
		if sv.beforeBirth != nil {
			if err := sv.beforeBirth(e); err != nil {
				return err
			}
		}
		if err := sv.birthRoom(e, name); err != nil {
			if errors.Is(err, errWait) {
				fmt.Fprintf(sv.out, "room %s #%d: %s waits in the room spool: %v\n", name, e.Seq, e.ID, err)
				continue
			}
			if !errors.Is(err, deliver.ErrRecord) && !errors.Is(err, errSpool) {
				return err
			}
			fmt.Fprintf(sv.out, "dropped %s from the room spool: %v\n", e.ID, err)
		}
		if err := sv.roomSpool.Remove(e); err != nil {
			return err
		}
	}
	return nil
}

// birthRoom writes a spooled room record at each of its targets, group the
// room id; one that is there already stays as it is. A target session not on
// this root yet answers errWait before anything is written: the record waits
// whole, in the spool.
func (sv *server) birthRoom(e *store.Entry, name string) error {
	var m roomMessage
	if err := json.Unmarshal(e.Body, &m); err != nil {
		return fmt.Errorf("%w: %v", errSpool, err)
	}
	ts, refused, err := sv.roomTargets(name, m.Group, &m)
	if err != nil {
		return fmt.Errorf("%w: %v", deliver.ErrRecord, err)
	}
	for _, t := range ts {
		if t.svc != nil || t.dir == sv.dir {
			continue
		}
		if _, err := os.Stat(t.dir); err != nil {
			return fmt.Errorf("the session %s is %w", t.dir, errWait)
		}
	}
	for _, r := range refused {
		fmt.Fprintf(sv.out, "room %s: %s %s: %v\n", name, m.Kind, m.ID, r)
	}
	for _, t := range ts {
		if t.svc != nil {
			sm := &session.Message{V: 1, ID: m.ID, From: m.From, To: t.to, Kind: m.Kind, At: m.At, Body: m.Body}
			raw, err := sm.Marshal()
			if err != nil {
				return fmt.Errorf("%w: %v", deliver.ErrRecord, err)
			}
			if err := sv.toService(*t.svc, sm, raw, m.Group); err != nil {
				return err
			}
			continue
		}
		path, born, err := deliver.Write(t.dir, t.place, m.ID, deliver.Record{From: m.From, To: t.to, Kind: m.Kind, At: m.At, Body: m.Body, Group: m.Group})
		if err != nil {
			return err
		}
		verb := "delivered"
		switch {
		case !born:
			verb = "already delivered"
		case t.place == deliver.Quarantine:
			verb = "quarantined"
		}
		fmt.Fprintf(sv.out, "%s %s %s → %s (room %s)\n", verb, m.Kind, m.ID, path, name)
	}
	return nil
}

// replayRoomSpool births the room spool entries whose Commit landed —
// marked, or whose id the room state has seen — and drops the rest, whose
// record the cursor brings again (store.ReplaySpool's rule, for rooms). An
// entry whose birth waits on a seat's session stays for the next round.
func (sv *server) replayRoomSpool(ctx context.Context) error {
	es, err := sv.roomSpool.Entries()
	if err != nil || len(es) == 0 {
		return err
	}
	l, err := loadRooms(ctx, sv.p.backend)
	if err != nil {
		return err
	}
	for _, e := range es {
		if r := l.byID(e.Channel); !e.Committed && r != nil && r.Stage == stageFollowing && r.Feed != nil {
			// A followed feed's Commit is its cursor in the rooms record.
			if e.Seq > r.Feed.Cursor {
				if err := sv.roomSpool.Remove(e); err != nil {
					return err
				}
				continue
			}
		} else if !e.Committed {
			st, err := room.Load(ctx, sv.p.backend, e.Channel)
			if err != nil && !errors.Is(err, room.ErrNoRoom) {
				return err
			}
			if err != nil || !st.Seen(e.ID) {
				if err := sv.roomSpool.Remove(e); err != nil {
					return err
				}
				continue
			}
		}
		name := e.Channel
		if r := l.byID(e.Channel); r != nil {
			name = r.Name
		}
		if err := sv.birthRoom(e, name); err != nil {
			if errors.Is(err, errWait) {
				fmt.Fprintf(sv.out, "room %s #%d: %s waits in the room spool: %v\n", name, e.Seq, e.ID, err)
				continue
			}
			if !errors.Is(err, deliver.ErrRecord) && !errors.Is(err, errSpool) {
				return err
			}
			fmt.Fprintf(sv.out, "dropped %s from the room spool: %v\n", e.ID, err)
		}
		if err := sv.roomSpool.Remove(e); err != nil {
			return err
		}
	}
	return nil
}
