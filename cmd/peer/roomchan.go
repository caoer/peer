package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// The channel kinds of a room's join (contract § Kinds), in the adder's
// order: invite → accept → (mint) → seat → join → (roster) → token. They are
// the session's own business, like card, and never delivered.
const (
	kindRoomInvite = session.KindRoomInvite
	kindRoomAccept = session.KindRoomAccept
	kindRoomSeat   = session.KindRoomSeat
	kindRoomJoin   = session.KindRoomJoin
	kindRoomToken  = session.KindRoomToken
)

// roomInvite carries no token: the newcomer takes add and its starting admin
// set from it, and the roster it is seeded with, bounded by rule 4.
type roomInvite struct {
	Room   string       `json:"room"`
	Relay  string       `json:"relay"`
	Add    room.Add     `json:"add"`
	Admins []uint16     `json:"admins"`
	Roster []room.Entry `json:"roster"`
}

type roomAccept struct {
	Room string `json:"room"`
}

type roomSeat struct {
	Room string `json:"room"`
	Idx  uint16 `json:"idx"`
}

type roomJoin struct {
	Room     string `json:"room"`
	RoomCard []byte `json:"roomcard"`
}

type roomToken struct {
	Room  string `json:"room"`
	Idx   uint16 `json:"idx"`
	Token string `json:"token"`
	From  int64  `json:"from"`
}

// channelMessage is a room channel message to the channel's peer.
func (p *party) channelMessage(ch *store.Channel, kind string, payload any) (*session.Message, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return session.NewMessage(p.partyID(), keys.PartyID(ch.Root()), kind, body)
}

// roomTokenMessage is the payload of the token an add hands over.
func roomTokenMessage(roomID string, pa *pendingAdd) roomToken {
	return roomToken{Room: roomID, Idx: pa.Idx, Token: pa.Token, From: pa.From}
}

// sendOnChannel sends a channel message from a command, in decision 5's
// order: a commit another host beat reloads the channel and encrypts again;
// a put that fails after the commit leaves the message in the outbox for the
// next send or serve.
func (p *party) sendOnChannel(ctx context.Context, pe roster.Peer, kind string, payload any, out io.Writer) error {
	rc := relay.New(pe.Relay, nil)
	for try := 1; ; try++ {
		ch, err := p.store.Channel(ctx, pe.Channel)
		if err != nil {
			return err
		}
		if has, _ := ch.ContainsSession(ctx, session.Addr); !has {
			return fmt.Errorf("no session with %s yet", pe.Name)
		}
		k, err := p.keys(ctx)
		if err != nil {
			return err
		}
		m, err := p.channelMessage(ch, kind, payload)
		if err != nil {
			return err
		}
		_, err = session.New(ch, k).Send(ctx, p.outbox, rc, pe.Token, m)
		var putErr *session.PutError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &putErr):
			fmt.Fprintf(out, "the %s to %s is committed but the relay did not take it (%v); it stays in the outbox and goes out on the next peer send or peer serve\n", m.Kind, pe.Name, putErr.Err)
			return nil
		case errors.Is(err, store.ErrConflict) && try < sendTries:
		default:
			return err
		}
	}
}

// dropPendingAdd forgets a finished add.
func dropPendingAdd(ctx context.Context, b store.Backend, roomID, channel string) error {
	return updateRooms(ctx, b, func(l *roomList) error {
		if r := l.byID(roomID); r != nil {
			r.dropAdd(channel)
		}
		return nil
	})
}

// receiveRoom handles a room channel message in serve: the step it calls for
// runs, and its answer, when it has one, goes back on the channel's snapshot
// — so one commit moves the cursor past the message and carries the answer's
// ratchet. A message that cannot be acted on is skipped with its reason and
// the cursor moves; a store conflict returns, and the pull reloads and reads
// the message again (every step is safe to run twice).
func (c *channelServe) receiveRoom(ctx context.Context, s *session.Session, rec relay.Record, m *session.Message) error {
	reply, skip, err := c.sv.p.roomStep(ctx, c.pe, c.ch, m, c.sv.out)
	if err != nil {
		return err
	}
	if skip != "" {
		fmt.Fprintf(c.sv.out, "skip %s #%d: %s\n", c.pe.Name, rec.Seq, skip)
	}
	if reply == nil {
		return c.commit(ctx, rec)
	}
	_, err = s.Send(ctx, c.sv.p.outbox, c.rc, c.pe.Token, reply)
	var putErr *session.PutError
	if errors.As(err, &putErr) {
		fmt.Fprintf(c.sv.out, "%s: the %s is committed but the relay did not take it (%v); it stays in the outbox\n", c.pe.Name, reply.Kind, putErr.Err)
		err = nil
	}
	if err != nil {
		return err
	}
	c.commitKeys(ctx, rec)
	if reply.Kind == kindRoomToken {
		var tok roomToken
		if json.Unmarshal(reply.Body, &tok) == nil {
			if err := dropPendingAdd(ctx, c.sv.p.backend, tok.Room, c.pe.Channel); err != nil {
				fmt.Fprintf(c.sv.out, "%s: the token went out; the add is still listed (%v)\n", c.pe.Name, err)
			}
		}
	}
	return nil
}

// roomStep runs one step of a join for a room channel message: the reply to
// send, or a reason the message is skipped; an error leaves it unread.
func (p *party) roomStep(ctx context.Context, pe roster.Peer, ch *store.Channel, m *session.Message, out io.Writer) (*session.Message, string, error) {
	if pe.State != roster.Confirmed {
		return nil, fmt.Sprintf("a %s on a channel that is not confirmed", m.Kind), nil
	}
	switch m.Kind {
	case kindRoomInvite:
		return p.onRoomInvite(ctx, pe, ch, m, out)
	case kindRoomAccept:
		return p.onRoomAccept(ctx, pe, ch, m, out)
	case kindRoomSeat:
		return p.onRoomSeat(ctx, pe, ch, m, out)
	case kindRoomJoin:
		return p.onRoomJoin(ctx, pe, ch, m, out)
	case kindRoomToken:
		return p.onRoomToken(ctx, pe, m, out)
	}
	return nil, fmt.Sprintf("kind %s", m.Kind), nil
}

// onRoomInvite (the newcomer) records the invite and answers room-accept.
// The invite came over a confirmed channel, a party the human checked, so
// serve accepts it; a room this party is seated in or holds already is not
// taken again.
func (p *party) onRoomInvite(ctx context.Context, pe roster.Peer, ch *store.Channel, m *session.Message, out io.Writer) (*session.Message, string, error) {
	var inv roomInvite
	if err := json.Unmarshal(m.Body, &inv); err != nil {
		return nil, fmt.Sprintf("room-invite: %v", err), nil
	}
	switch {
	case !room.ValidID(inv.Room):
		return nil, fmt.Sprintf("room-invite: room %q", inv.Room), nil
	case inv.Relay == "":
		return nil, "room-invite: no relay", nil
	case inv.Add != room.AddAdmins && inv.Add != room.AddMembers:
		return nil, fmt.Sprintf("room-invite: add %q", inv.Add), nil
	case len(inv.Roster) == 0:
		return nil, "room-invite: an empty roster", nil
	}
	var held *roomRef
	err := updateRooms(ctx, p.backend, func(l *roomList) error {
		held = nil
		ref := l.byID(inv.Room)
		if ref != nil && ref.Stage != stageInvited {
			cp := *ref
			held = &cp
			return nil
		}
		if ref == nil {
			l.Rooms = append(l.Rooms, roomRef{Name: newRoomName(l, inv.Room), ID: inv.Room})
			ref = &l.Rooms[len(l.Rooms)-1]
		}
		ref.Relay, ref.Via, ref.Invite, ref.Stage = inv.Relay, pe.Channel, &inv, stageInvited
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if held != nil {
		return nil, fmt.Sprintf("room-invite to room %s: you are %s there already (idx %d)", held.Name, held.Stage, held.Idx), nil
	}
	name := inv.Room[:8]
	if l, err := loadRooms(ctx, p.backend); err == nil {
		if r := l.byID(inv.Room); r != nil {
			name = r.Name
		}
	}
	fmt.Fprintf(out, "room %s: %s invites you (add: %s, %d members); accepted\n", name, pe.Name, inv.Add, len(inv.Roster))
	reply, err := p.channelMessage(ch, kindRoomAccept, roomAccept{Room: inv.Room})
	return reply, "", err
}

// newRoomName is a local name for a room another party created: its id's
// first eight characters, or the whole id when those are taken.
func newRoomName(l *roomList, id string) string {
	if l.byName(id[:8]) == nil {
		return id[:8]
	}
	return id
}

// onRoomAccept (the adder) mints the newcomer's token on its yes and answers
// with the idx; an accept already minted for gets the same idx again.
func (p *party) onRoomAccept(ctx context.Context, pe roster.Peer, ch *store.Channel, m *session.Message, out io.Writer) (*session.Message, string, error) {
	var acc roomAccept
	if err := json.Unmarshal(m.Body, &acc); err != nil {
		return nil, fmt.Sprintf("room-accept: %v", err), nil
	}
	ref, pa, skip, err := p.pendingFor(ctx, acc.Room, pe.Channel, kindRoomAccept)
	if err != nil || skip != "" {
		return nil, skip, err
	}
	if pa.Stage == addInvited {
		minted, err := relay.New(ref.Relay, nil).AddMember(ctx, ref.ID, ref.Token, pa.Role)
		if err != nil {
			return nil, fmt.Sprintf("room %s: the mint for %s failed (%v); peer room add %s %s starts it again", ref.Name, pe.Name, err, ref.Name, pe.Name), nil
		}
		err = updateRooms(ctx, p.backend, func(l *roomList) error {
			cur := l.byID(ref.ID)
			if cur == nil {
				return fmt.Errorf("room %s left the rooms record", ref.Name)
			}
			cp := cur.add(pe.Channel)
			if cp == nil {
				return fmt.Errorf("room %s: the add of %s left the rooms record", ref.Name, pe.Name)
			}
			if cp.Stage == addInvited {
				cp.Stage, cp.Idx, cp.Token, cp.From = addSeated, uint16(minted.Idx), minted.Token, minted.From
			}
			*pa = *cp
			return nil
		})
		if err != nil {
			return nil, "", err
		}
		fmt.Fprintf(out, "room %s: minted idx %d for %s (it reads from #%d)\n", ref.Name, pa.Idx, pe.Name, pa.From)
	}
	reply, err := p.channelMessage(ch, kindRoomSeat, roomSeat{Room: ref.ID, Idx: pa.Idx})
	return reply, "", err
}

// pendingFor is the joined room and the add in flight over channel that a
// message of kind answers, or the reason it is skipped.
func (p *party) pendingFor(ctx context.Context, roomID, channel, kind string) (*roomRef, *pendingAdd, string, error) {
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return nil, nil, "", err
	}
	ref := l.byID(roomID)
	if ref == nil || ref.Stage != stageJoined {
		return nil, nil, fmt.Sprintf("a %s for room %q, which this party does not hold", kind, roomID), nil
	}
	pa := ref.add(channel)
	if pa == nil {
		return nil, nil, fmt.Sprintf("a %s for room %s with no add pending on this channel (peer room add sends the invite)", kind, ref.Name), nil
	}
	cp := *pa
	return ref, &cp, "", nil
}

// onRoomSeat (the newcomer) births the room state at the idx the adder
// minted, seeded from the invite (rule 4 bounds its roster as a roster
// record's), and answers with its room card for that idx.
func (p *party) onRoomSeat(ctx context.Context, pe roster.Peer, ch *store.Channel, m *session.Message, out io.Writer) (*session.Message, string, error) {
	var seat roomSeat
	if err := json.Unmarshal(m.Body, &seat); err != nil {
		return nil, fmt.Sprintf("room-seat: %v", err), nil
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return nil, "", err
	}
	ref := l.byID(seat.Room)
	switch {
	case ref == nil:
		return nil, fmt.Sprintf("a room-seat for room %q, which no invite named", seat.Room), nil
	case ref.Via != pe.Channel:
		return nil, fmt.Sprintf("a room-seat for room %s from another channel than its invite's", ref.Name), nil
	case !relay.ValidIdx(int(seat.Idx)):
		return nil, fmt.Sprintf("a room-seat for room %s at idx %d", ref.Name, seat.Idx), nil
	case ref.Stage == stageJoined:
		return nil, fmt.Sprintf("a room-seat for room %s, which you are in already", ref.Name), nil
	case ref.Stage == stageSeated && ref.Idx != seat.Idx:
		return nil, fmt.Sprintf("a room-seat for room %s at idx %d; you are seated at idx %d", ref.Name, seat.Idx, ref.Idx), nil
	}
	now := time.Now()
	var st *room.State
	if ref.Stage == stageInvited {
		if ref.Invite == nil {
			return nil, fmt.Sprintf("room %s: the invite is not on the rooms record", ref.Name), nil
		}
		own, err := room.GenerateKeys()
		if err != nil {
			return nil, "", err
		}
		if st, err = room.New(p.backend, ref.ID, seat.Idx, ref.Invite.Add, own); err != nil {
			return nil, fmt.Sprintf("room %s: %v", ref.Name, err), nil
		}
		chk, _, err := p.channelRoots(ctx)
		if err != nil {
			return nil, "", err
		}
		res := st.Seed(ref.Invite.Roster, ref.Invite.Admins, chk, now)
		for _, r := range res.Refused {
			fmt.Fprintf(out, "room %s: the invite's %s; refused\n", ref.Name, r)
		}
		if err := st.Commit(ctx); err != nil {
			if !errors.Is(err, store.ErrConflict) {
				return nil, "", err
			}
			st = nil // another host seated it first: read its state
		}
		err = updateRooms(ctx, p.backend, func(l *roomList) error {
			cur := l.byID(ref.ID)
			if cur == nil {
				return fmt.Errorf("room %s left the rooms record", ref.Name)
			}
			if cur.Stage == stageInvited {
				cur.Stage, cur.Idx, cur.Invite = stageSeated, seat.Idx, nil
			}
			return nil
		})
		if err != nil {
			return nil, "", err
		}
	}
	if st == nil {
		if st, err = room.Load(ctx, p.backend, ref.ID); err != nil {
			return nil, "", err
		}
		if st.Idx() != seat.Idx {
			return nil, fmt.Sprintf("a room-seat for room %s at idx %d; its state holds idx %d", ref.Name, seat.Idx, st.Idx()), nil
		}
	}
	signed, err := st.OwnCard(now).Signed(p.id)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(out, "room %s: seated at idx %d; your room card goes to %s\n", ref.Name, seat.Idx, pe.Name)
	reply, err := p.channelMessage(ch, kindRoomJoin, roomJoin{Room: ref.ID, RoomCard: signed})
	return reply, "", err
}

// onRoomJoin (the adder) checks the newcomer's room card against the party
// card the channel pins and the minted idx, posts the roster record that
// carries the entry (folded and committed before the put), and answers with
// the token (rule 2: only once the roster landed).
func (p *party) onRoomJoin(ctx context.Context, pe roster.Peer, ch *store.Channel, m *session.Message, out io.Writer) (*session.Message, string, error) {
	var j roomJoin
	if err := json.Unmarshal(m.Body, &j); err != nil {
		return nil, fmt.Sprintf("room-join: %v", err), nil
	}
	ref, pa, skip, err := p.pendingFor(ctx, j.Room, pe.Channel, kindRoomJoin)
	if err != nil || skip != "" {
		return nil, skip, err
	}
	switch pa.Stage {
	case addInvited:
		return nil, fmt.Sprintf("a room-join for room %s before its seat", ref.Name), nil
	case addSeated:
		root, signed := ch.Root(), ch.Card()
		if root == nil || signed == nil {
			return nil, fmt.Sprintf("room %s: no card pinned for %s", ref.Name, pe.Name), nil
		}
		pc, err := card.Verify(signed, root)
		if err != nil {
			return nil, fmt.Sprintf("room %s: %s's pinned card: %v", ref.Name, pe.Name, err), nil
		}
		rc, err := room.Verify(j.RoomCard, pc, time.Now())
		if err != nil {
			return nil, fmt.Sprintf("room %s: %s's room card: %v", ref.Name, pe.Name, err), nil
		}
		if rc.Room != ref.ID || rc.Idx != pa.Idx {
			return nil, fmt.Sprintf("room %s: %s's room card is for idx %d of room %s, and the seat was idx %d", ref.Name, pe.Name, rc.Idx, rc.Room, pa.Idx), nil
		}
		entry := room.Entry{Idx: pa.Idx, Party: keys.PartyID(root), Card: room.PartyCard{Body: signed.Body, Sig: signed.Sig}, RoomCard: j.RoomCard}
		body, err := json.Marshal(room.RosterBody{Members: []room.Entry{entry}})
		if err != nil {
			return nil, "", err
		}
		c, err := p.openRoom(ctx, *ref, out)
		if err != nil {
			return nil, "", err
		}
		seq, _, err := c.postMembership(ctx, room.KindRoster, body)
		if err != nil {
			return nil, fmt.Sprintf("the roster record adding %s did not land (%v); peer room add %s %s starts the add again", pe.Name, err, ref.Name, pe.Name), nil
		}
		err = updateRooms(ctx, p.backend, func(l *roomList) error {
			if cur := l.byID(ref.ID); cur != nil {
				if cp := cur.add(pe.Channel); cp != nil {
					cp.Stage = addRostered
				}
			}
			return nil
		})
		if err != nil {
			return nil, "", err
		}
		fmt.Fprintf(out, "room %s: %s is idx %d (roster #%d); its token goes out\n", ref.Name, pe.Name, pa.Idx, seq)
	}
	reply, err := p.channelMessage(ch, kindRoomToken, roomTokenMessage(ref.ID, pa))
	return reply, "", err
}

// onRoomToken (the newcomer) takes its token: the room is joined and serve
// pulls it from here on.
func (p *party) onRoomToken(ctx context.Context, pe roster.Peer, m *session.Message, out io.Writer) (*session.Message, string, error) {
	var tok roomToken
	if err := json.Unmarshal(m.Body, &tok); err != nil {
		return nil, fmt.Sprintf("room-token: %v", err), nil
	}
	if !relay.ValidToken(tok.Token) || tok.From < 0 {
		return nil, "room-token: a malformed token or from", nil
	}
	var name, skip string
	err := updateRooms(ctx, p.backend, func(l *roomList) error {
		skip = ""
		ref := l.byID(tok.Room)
		switch {
		case ref == nil:
			skip = fmt.Sprintf("a room-token for room %q, which no invite named", tok.Room)
		case ref.Via != pe.Channel:
			skip = fmt.Sprintf("a room-token for room %s from another channel than its invite's", ref.Name)
		case ref.Stage == stageInvited:
			skip = fmt.Sprintf("a room-token for room %s before its seat", ref.Name)
		case ref.Idx != tok.Idx:
			skip = fmt.Sprintf("a room-token for room %s at idx %d; you are seated at idx %d", ref.Name, tok.Idx, ref.Idx)
		default:
			name = ref.Name
			ref.Stage, ref.Token, ref.From = stageJoined, tok.Token, tok.From
		}
		return nil
	})
	if err != nil || skip != "" {
		return nil, skip, err
	}
	fmt.Fprintf(out, "joined room %s as idx %d (it reads from #%d)\n", name, tok.Idx, tok.From)
	return nil, "", nil
}

// serveRooms pulls every room this party holds a token in.
func (sv *server) serveRooms(ctx context.Context) error {
	l, err := loadRooms(ctx, sv.p.backend)
	if err != nil {
		return err
	}
	var errs []error
	for _, ref := range l.Rooms {
		if ref.Stage != stageJoined {
			continue
		}
		c, err := sv.p.openRoom(ctx, ref, sv.out)
		if err == nil {
			err = c.pull(ctx)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
