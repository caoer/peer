package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
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
// order: invite → accept → (mint) → seat → join → (roster) → token; and
// room-admin, a handover's token. They are the session's own business, like
// card, and never delivered.
const (
	kindRoomInvite = session.KindRoomInvite
	kindRoomAccept = session.KindRoomAccept
	kindRoomSeat   = session.KindRoomSeat
	kindRoomJoin   = session.KindRoomJoin
	kindRoomToken  = session.KindRoomToken
	kindRoomAdmin  = session.KindRoomAdmin
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

// invite is the room-invite the fold holds now and the sha256 of its JSON,
// which the add keeps (pendingAdd.Invite) for the check after the mint.
func (c *roomConn) invite() (roomInvite, string, error) {
	inv := roomInvite{Room: c.ref.ID, Relay: c.ref.Relay, Add: c.st.Add(), Admins: c.st.Admins()}
	for _, m := range c.st.Members() {
		inv.Roster = append(inv.Roster, m.Entry)
	}
	b, err := json.Marshal(inv)
	if err != nil {
		return roomInvite{}, "", err
	}
	sum := sha256.Sum256(b)
	return inv, hex.EncodeToString(sum[:]), nil
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
	// Role is the token's role, write or read: a read member learns here
	// that its card and its leave go over the channel.
	Role string `json:"role,omitempty"`
}

// roomAdmin carries a handover's admin-flagged token, sent after the
// handover record landed.
type roomAdmin struct {
	Room  string `json:"room"`
	Token string `json:"token"`
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
	return roomToken{Room: roomID, Idx: pa.Idx, Token: pa.Token, From: pa.From, Role: pa.Role}
}

// sendOnChannel sends a channel message of kind with payload (sendMessage).
func (p *party) sendOnChannel(ctx context.Context, pe roster.Peer, kind string, payload any, out io.Writer) error {
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return err
	}
	m, err := p.channelMessage(ch, kind, payload)
	if err != nil {
		return err
	}
	return p.sendMessage(ctx, pe, m, out)
}

// sendMessage sends a channel message in decision 5's order: a commit
// another host beat reloads the channel and encrypts again; a put that fails
// after the commit leaves the message in the outbox for the next send or
// serve.
func (p *party) sendMessage(ctx context.Context, pe roster.Peer, m *session.Message, out io.Writer) error {
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

// receiveRoom handles a room channel message in serve in decision 5's order,
// as a message is born: spooled, the channel committed past it, then its step
// run from the spool. That commit is the claim: of a party's hosts pulling
// the message, the one whose commit lands runs the step and a loser reloads
// past it, so a step's relay write — the mint, the roster record — happens
// once however many hosts serve the state (C9 finding 1). A step cut after
// the commit runs from the spool on the next round or start (replaySpool);
// every step is safe to run twice on one host.
func (c *channelServe) receiveRoom(ctx context.Context, rec relay.Record, m *session.Message) error {
	plain, err := m.Marshal()
	if err != nil {
		return err
	}
	e := &store.Entry{ID: m.ID, Channel: c.ch.Name(), Seq: rec.Seq, Type: rec.Env.Type.String(), Body: plain}
	if err := c.sv.spool.Add(e); err != nil {
		return err
	}
	// As receive: only a conflict says the commit kept nothing, and the
	// winner's state runs the step; any other error leaves the entry for the
	// next round's seen check.
	if err := c.ch.Commit(ctx); err != nil {
		if errors.Is(err, store.ErrConflict) {
			c.sv.spool.Remove(e)
		}
		return err
	}
	if err := c.sv.spool.MarkCommitted(e); err != nil {
		return err
	}
	c.commitKeys(ctx, rec)
	if err := c.sv.runRoomStep(ctx, c.pe, m, rec.Seq); err != nil {
		return err
	}
	// The step's answer went out under a commit of its own: the pull goes on
	// from that state.
	if err := c.load(ctx); err != nil {
		return err
	}
	return c.sv.spool.Remove(e)
}

// replayRoomStep runs a room step whose claim landed and whose run a crash
// or an error cut (replaySpool).
func (sv *server) replayRoomStep(ctx context.Context, e *store.Entry, m *session.Message) error {
	r, err := roster.Load(ctx, sv.p.backend)
	if err != nil {
		return err
	}
	pe := r.ByChannel(e.Channel)
	if pe == nil {
		fmt.Fprintf(sv.out, "dropped the %s %s from the spool: no peer on channel %s\n", m.Kind, m.ID, e.Channel)
		return nil
	}
	return sv.runRoomStep(ctx, *pe, m, e.Seq)
}

// runRoomStep runs the step a claimed room channel message calls for and
// sends its answer, when it has one, on the channel; a room-token that went
// out finishes the add.
func (sv *server) runRoomStep(ctx context.Context, pe roster.Peer, m *session.Message, seq int64) error {
	ch, err := sv.p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return err
	}
	reply, skip, err := sv.roomStep(ctx, pe, ch, m)
	if err != nil {
		return err
	}
	if skip != "" {
		fmt.Fprintf(sv.out, "skip %s #%d: %s\n", pe.Name, seq, skip)
	}
	if reply == nil {
		return nil
	}
	if err := sv.p.sendMessage(ctx, pe, reply, sv.out); err != nil {
		return err
	}
	switch reply.Kind {
	case kindRoomToken:
		var tok roomToken
		if json.Unmarshal(reply.Body, &tok) == nil {
			if err := dropPendingAdd(ctx, sv.p.backend, tok.Room, pe.Channel); err != nil {
				fmt.Fprintf(sv.out, "%s: the token went out; the add is still listed (%v)\n", pe.Name, err)
			}
		}
	case kindRoomSeat, kindRoomInvite:
		// The invite check's answer went out: a minted add moves to seated
		// only now, so a send that failed replays the check, never a seat on
		// the stale invite. A move that failed replays it too.
		var r struct {
			Room string `json:"room"`
		}
		if json.Unmarshal(reply.Body, &r) == nil {
			return seatAdd(ctx, sv.p.backend, r.Room, pe.Channel)
		}
	}
	return nil
}

// seatAdd moves a minted add over channel to seated.
func seatAdd(ctx context.Context, b store.Backend, roomID, channel string) error {
	return updateRooms(ctx, b, func(l *roomList) error {
		if r := l.byID(roomID); r != nil {
			if a := r.add(channel); a != nil && a.Stage == addMinted {
				a.Stage = addSeated
			}
		}
		return nil
	})
}

// roomStep runs one step of a join for a room channel message: the reply to
// send, or a reason the message is skipped; an error leaves it in the spool.
// A step that pulls a room pulls it as serve does, delivering where serve
// delivers.
func (sv *server) roomStep(ctx context.Context, pe roster.Peer, ch *store.Channel, m *session.Message) (*session.Message, string, error) {
	p, out := sv.p, sv.out
	if pe.State != roster.Confirmed {
		return nil, fmt.Sprintf("a %s on a channel that is not confirmed", m.Kind), nil
	}
	switch m.Kind {
	case kindRoomInvite:
		return p.onRoomInvite(ctx, pe, ch, m, out)
	case kindRoomAccept:
		return p.onRoomAccept(ctx, sv, pe, ch, m)
	case kindRoomSeat:
		return p.onRoomSeat(ctx, pe, ch, m, out)
	case kindRoomJoin:
		return p.onRoomJoin(ctx, sv, pe, ch, m)
	case kindRoomToken:
		return p.onRoomToken(ctx, pe, m, out)
	case kindRoomAdmin:
		return p.onRoomAdmin(ctx, pe, m, out)
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
		if ref != nil && ref.Stage != stageInvited && !ref.Stage.gone() {
			cp := *ref
			held = &cp
			return nil
		}
		if ref == nil {
			l.Rooms = append(l.Rooms, roomRef{Name: newRoomName(l, inv.Room), ID: inv.Room})
			ref = &l.Rooms[len(l.Rooms)-1]
		}
		// A room the party left is taken afresh: the name stays, the rest is new.
		*ref = roomRef{Name: ref.Name, ID: ref.ID, Relay: inv.Relay, Via: pe.Channel, Invite: &inv, Stage: stageInvited}
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

// onRoomAccept (the adder) mints the newcomer's token on its yes, then checks
// the invite: the newcomer reads from from, so what folded below it since peer
// room add — a handover, a removal, a rotation — reaches it only in an invite.
// The fold brought to from builds the invite again; one that differs from the
// invite sent goes out fresh, and the newcomer's next accept gets the seat.
// One that matches is answered with the idx. An accept already minted for
// mints nothing; past the check it gets the same idx again.
func (p *party) onRoomAccept(ctx context.Context, sv *server, pe roster.Peer, ch *store.Channel, m *session.Message) (*session.Message, string, error) {
	out := sv.out
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
				cp.Stage, cp.Idx, cp.Token, cp.From = addMinted, uint16(minted.Idx), minted.Token, minted.From
			}
			*pa = *cp
			return nil
		})
		if err != nil {
			return nil, "", err
		}
		fmt.Fprintf(out, "room %s: minted idx %d for %s (it reads from #%d)\n", ref.Name, pa.Idx, pe.Name, pa.From)
	}
	if pa.Stage == addMinted {
		c, err := sv.openRoom(ctx, *ref)
		if err != nil {
			return nil, "", err
		}
		if err := c.pullBelow(ctx, pa.From); err != nil {
			if errors.Is(err, errGone) {
				return nil, err.Error(), nil
			}
			// The accept stays in the spool: the next round checks again.
			return nil, "", fmt.Errorf("room %s: the invite check for %s waits for the next round: %w", ref.Name, pe.Name, err)
		}
		inv, sum, err := c.invite()
		if err != nil {
			return nil, "", err
		}
		if sum != pa.Invite {
			fmt.Fprintf(out, "room %s: the room changed below #%d since %s's invite; a fresh one goes out before the seat\n", ref.Name, pa.From, pe.Name)
			reply, err := p.channelMessage(ch, kindRoomInvite, inv)
			return reply, "", err
		}
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
func (p *party) onRoomJoin(ctx context.Context, sv *server, pe roster.Peer, ch *store.Channel, m *session.Message) (*session.Message, string, error) {
	out := sv.out
	var j roomJoin
	if err := json.Unmarshal(m.Body, &j); err != nil {
		return nil, fmt.Sprintf("room-join: %v", err), nil
	}
	if l, err := loadRooms(ctx, p.backend); err != nil {
		return nil, "", err
	} else if ref := l.byID(j.Room); ref != nil && ref.Stage == stageJoined && ref.add(pe.Channel) == nil {
		// No add in flight over this channel: a member's new card — a read
		// member's rotation, an identity change — for this admin to announce.
		return p.onCardUpdate(ctx, sv, pe, ch, *ref, j)
	}
	ref, pa, skip, err := p.pendingFor(ctx, j.Room, pe.Channel, kindRoomJoin)
	if err != nil || skip != "" {
		return nil, skip, err
	}
	switch pa.Stage {
	case addInvited:
		return nil, fmt.Sprintf("a room-join for room %s before its seat", ref.Name), nil
	case addMinted, addSeated:
		// At minted the check's seat went out — only it sends one there —
		// and the move to seated has not landed: the join proves the seat.
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
		c, err := sv.openRoom(ctx, *ref)
		if err != nil {
			return nil, "", err
		}
		seq, res, err := c.postMembership(ctx, room.KindRoster, body)
		if errors.Is(err, errQueued) {
			// Committed, folded and journaled: serve puts it, and the token
			// follows its landing (finishAdds), rule 2's order.
			return nil, fmt.Sprintf("the roster record adding %s is committed and did not land (%v); serve puts it, then sends the token", pe.Name, err), nil
		}
		// errMoot: the entry folded already — the join replayed after its
		// record landed; the token goes out as after the put.
		folded := errors.Is(err, errMoot)
		switch {
		case err == nil, folded:
		case passingPost(err, res):
			// The join stays in the spool: the next round runs it again.
			return nil, "", fmt.Errorf("room %s: the roster record adding %s waits for the next round: %w", ref.Name, pe.Name, err)
		default:
			return nil, fmt.Sprintf("the roster record adding %s did not land (%v); peer room add %s %s sends the seat again", pe.Name, err, ref.Name, pe.Name), nil
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
		if folded {
			fmt.Fprintf(out, "room %s: %s is idx %d (its roster entry folded already); its token goes out\n", ref.Name, pe.Name, pa.Idx)
		} else {
			fmt.Fprintf(out, "room %s: %s is idx %d (roster #%d); its token goes out\n", ref.Name, pe.Name, pa.Idx, seq)
		}
	}
	reply, err := p.channelMessage(ch, kindRoomToken, roomTokenMessage(ref.ID, pa))
	return reply, "", err
}

// passingPost reports whether a membership post failed on trouble a later
// round outlives — the relay's timeout, 5xx or rate limit, a store conflict
// — rather than on a verdict: the fold's refusal or the cap, a refusal from
// the relay no retry changes, or a room this party is out of.
func passingPost(err error, res room.Result) bool {
	switch {
	case !res.Folded(), len(res.Refused) > 0, errors.Is(err, room.ErrCap), errors.Is(err, errGone), permanentRoomPut(err):
		return false
	}
	return true
}

// onCardUpdate (an admin) takes a member's new room card over the channel —
// a read member's rotation, or a card re-signed after an identity change —
// checks it against the party card the channel pins, and posts the roster
// entry update that announces it: the pinned party card and the new room
// card at the member's idx.
func (p *party) onCardUpdate(ctx context.Context, sv *server, pe roster.Peer, ch *store.Channel, ref roomRef, j roomJoin) (*session.Message, string, error) {
	out := sv.out
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
	c, err := sv.openRoom(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	party := keys.PartyID(root)
	cur := c.st.Member(rc.Idx)
	switch {
	case rc.Room != ref.ID || cur == nil || cur.Party != party:
		return nil, fmt.Sprintf("room %s: %s's room card is for idx %d, which %s does not hold", ref.Name, pe.Name, rc.Idx, pe.Name), nil
	case !c.st.IsAdmin(c.st.Idx()):
		return nil, fmt.Sprintf("room %s: %s's new room card needs an admin's roster entry, and you are not in the admin set", ref.Name, pe.Name), nil
	}
	entry := room.Entry{Idx: rc.Idx, Party: party, Card: room.PartyCard{Body: signed.Body, Sig: signed.Sig}, RoomCard: j.RoomCard}
	body, err := json.Marshal(room.RosterBody{Members: []room.Entry{entry}})
	if err != nil {
		return nil, "", err
	}
	seq, res, err := c.postMembership(ctx, room.KindRoster, body)
	switch {
	case errors.Is(err, errQueued):
		return nil, fmt.Sprintf("the roster entry with %s's new room card is committed and did not land (%v); serve puts it", pe.Name, err), nil
	case errors.Is(err, errMoot), err == nil && len(res.Updated) == 0:
		return nil, fmt.Sprintf("room %s: %s's room card is no newer than the one folded; nothing posted", ref.Name, pe.Name), nil
	case err != nil:
		return nil, fmt.Sprintf("the roster entry with %s's new room card did not land: %v", pe.Name, err), nil
	case len(res.Updated) == 0:
		return nil, fmt.Sprintf("room %s: %s's room card is no newer than the one folded; nothing posted", ref.Name, pe.Name), nil
	}
	fmt.Fprintf(out, "room %s: %s's new room card is announced (roster #%d)\n", ref.Name, pe.Name, seq)
	return nil, "", nil
}

// onRoomToken (the newcomer) takes its token: the room is joined and serve
// pulls it from here on; a read token's role says the card and the leave go
// over the channel.
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
			ref.Stage, ref.Token, ref.From, ref.Read = stageJoined, tok.Token, tok.From, tok.Role == relay.RoleRead
		}
		return nil
	})
	if err != nil || skip != "" {
		return nil, skip, err
	}
	role := ""
	if tok.Role == relay.RoleRead {
		role = ", read"
	}
	fmt.Fprintf(out, "joined room %s as idx %d%s (it reads from #%d)\n", name, tok.Idx, role, tok.From)
	return nil, "", nil
}

// onRoomAdmin (the member handed the room) takes the admin-flagged token:
// it proves itself on an admin route before it replaces the one in use.
func (p *party) onRoomAdmin(ctx context.Context, pe roster.Peer, m *session.Message, out io.Writer) (*session.Message, string, error) {
	var adm roomAdmin
	if err := json.Unmarshal(m.Body, &adm); err != nil {
		return nil, fmt.Sprintf("room-admin: %v", err), nil
	}
	if !relay.ValidToken(adm.Token) {
		return nil, "room-admin: a malformed token", nil
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return nil, "", err
	}
	ref := l.byID(adm.Room)
	if ref == nil || ref.Stage != stageJoined {
		return nil, fmt.Sprintf("a room-admin for room %q, which this party is not in", adm.Room), nil
	}
	ms, err := relay.New(ref.Relay, nil).ListMembers(ctx, ref.ID, adm.Token)
	if err != nil {
		return nil, fmt.Sprintf("room %s: the admin token %s sent does not work on the relay (%v)", ref.Name, pe.Name, err), nil
	}
	if !slices.ContainsFunc(ms.Members, func(mm relay.Member) bool { return mm.Idx == int(ref.Idx) && mm.Admin && !mm.Revoked }) {
		return nil, fmt.Sprintf("room %s: the token %s sent is not an admin token for your idx %d", ref.Name, pe.Name, ref.Idx), nil
	}
	err = updateRooms(ctx, p.backend, func(l *roomList) error {
		if cur := l.byID(ref.ID); cur != nil && cur.Stage == stageJoined {
			cur.Token = adm.Token
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(out, "room %s: %s handed you the admin token; you can add, remove, hand over and close\n", ref.Name, pe.Name)
	return nil, "", nil
}

// openRoom opens a room for a step serve runs: its pulls deliver as serve's.
func (sv *server) openRoom(ctx context.Context, ref roomRef) (*roomConn, error) {
	c, err := sv.p.openRoom(ctx, ref, sv.out)
	if err != nil {
		return nil, err
	}
	c.sv = sv
	return c, nil
}

// serveRooms serves every room this party holds a token in: the pull to
// head, delivering as it goes; this host's waiting records, put in ctr order
// (roomsend.go); the token of every add whose roster record landed; the
// revoke of every removal and the token of every handover a round cut
// short; an admin's look for revoked readers; the daily rotation, an
// identity change's re-signed card, and the retired keys whose time is up
// (roommember.go); a feed admin's revokes of old links, and each followed
// feed's pull (roomfeed.go). A delivery that waits on a seat's session waits
// in the room spool while the pull goes on; a room the party is out of is
// said once and dropped.
func (sv *server) serveRooms(ctx context.Context) error {
	l, err := loadRooms(ctx, sv.p.backend)
	if err != nil {
		return err
	}
	sv.p.dropLeftRooms(l, sv.out)
	var errs []error
	for _, ref := range l.Rooms {
		if ref.Stage == stageFollowing {
			if err := sv.serveFeed(ctx, ref); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if ref.Stage != stageJoined {
			continue
		}
		c, err := sv.p.openRoom(ctx, ref, sv.out)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		c.sv = sv
		switch err := c.pull(ctx); {
		case errors.Is(err, errGone):
			fmt.Fprintf(sv.out, "%v\n", err)
			continue
		case err != nil:
			errs = append(errs, err)
			continue
		}
		if c.st.Removed(c.st.Idx()) {
			// An admin's removal record folded, or this party's own leave
			// record whose DELETE …/self did not land: the revoke runs here
			// with the token this host still holds, before the room is marked
			// gone — a seat whose token is forgotten stays live to retention.
			if err := c.revokeSelf(ctx); err != nil {
				fmt.Fprintf(sv.out, "room %s: you are out of the room and %v; the next round tries the revoke again\n", ref.Name, err)
				continue
			}
			fmt.Fprintf(sv.out, "%v\n", c.gone(ctx, stageRemoved))
			continue
		}
		if res := c.flush(ctx, false); res.wait != nil {
			fmt.Fprintf(sv.out, "room %s: %d records wait in the room outbox: %v\n", ref.Name, sv.p.waiting(ref.ID), res.wait)
		}
		if cur, err := loadRooms(ctx, sv.p.backend); err == nil {
			if r := cur.byID(ref.ID); r != nil {
				sv.p.finishAdds(ctx, *r, sv.out)
				c.ref.Read, c.ref.CardSent = r.Read, r.CardSent
			}
		}
		c.finishRemovals(ctx)
		c.finishHandovers(ctx)
		if c.st.IsAdmin(c.st.Idx()) {
			c.checkRevoked(ctx)
			c.finishLinkRevokes(ctx)
		}
		now := roomClock()
		if err := c.rotate(ctx, now, false); err != nil {
			fmt.Fprintf(sv.out, "room %s: rotation: %v\n", ref.Name, err)
		}
		if err := c.recard(ctx, now); err != nil {
			fmt.Fprintf(sv.out, "%v\n", err)
		}
		c.retire(ctx, now)
	}
	return errors.Join(errs...)
}
