package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/caoer/peer/internal/store"
)

// roomsKey is the rooms record's key in the store: the party's list of
// rooms beside the room states (room.Key), so every fleet host that holds
// the store serves every room.
const roomsKey = "rooms"

const roomsVersion = 1

// roomStage is how far this party is into a room.
type roomStage string

const (
	// stageInvited: a room-invite arrived and the room-accept went back; the
	// adder mints on it and answers with room-seat.
	stageInvited roomStage = "invited"
	// stageSeated: the idx arrived, the room state is born and the room-join
	// went back; the room-token comes once the adder's roster record landed.
	stageSeated roomStage = "seated"
	// stageJoined: the party holds a token and pulls the room.
	stageJoined roomStage = "joined"
	// stageLeft, stageRemoved, stageClosed: the party is out of the room —
	// by its own leave, by an admin's removal, or by its own close. The
	// state is dropped and pulls stop; the name stays reserved, and a new
	// invite to the same room seats the party afresh.
	stageLeft    roomStage = "left"
	stageRemoved roomStage = "removed"
	stageClosed  roomStage = "closed"
)

// stageFollowing: the party reads a feed by its link alone — no seat, no
// roster, no room state; the entry holds the link and the cursor (Feed).
// stageCut: the feed's owner made a new link or closed the feed, and the
// relay revoked the one this party held; a follow of a new link reads on
// from the cursor.
const (
	stageFollowing roomStage = "following"
	stageCut       roomStage = "cut"
)

// followed reports whether the party reads the room by a feed link.
func (s roomStage) followed() bool { return s == stageFollowing || s == stageCut }

// gone reports whether the stage is one the party is out of the room at.
func (s roomStage) gone() bool { return s == stageLeft || s == stageRemoved || s == stageClosed }

// addStage is how far an add this party runs as the adder has gone.
type addStage string

const (
	addInvited  addStage = "invited"  // room-invite sent, waiting for room-accept
	addMinted   addStage = "minted"   // minted; the seat waits on the invite's check against the fold at from
	addSeated   addStage = "seated"   // room-seat sent, or a fresh room-invite whose accept gets it; waiting for room-join
	addRostered addStage = "rostered" // the roster record landed; room-token goes out
)

// pendingAdd is one add in flight, held by the adder until the room-token
// went out: the channel it runs over, the role asked for, the sum of the
// invite peer room add sent, and from the mint on the idx, token and from the
// newcomer gets.
type pendingAdd struct {
	Peer    string   `json:"peer"`
	Channel string   `json:"channel"`
	Role    string   `json:"role"`
	Stage   addStage `json:"stage"`
	// Invite is the sha256 of the room-invite's JSON (roomConn.invite): after
	// the mint the fold brought to from is checked against it.
	Invite string `json:"invite,omitempty"`
	Idx    uint16 `json:"idx,omitempty"`
	Token  string `json:"token,omitempty"`
	From   int64  `json:"from,omitempty"`
}

// pendingHandover is one handover the admin ran: the member's channel, its
// idx, and from the grant on the admin-flagged token, kept so a re-run sends
// the stored token again and never grants a second one.
type pendingHandover struct {
	Peer    string `json:"peer"`
	Channel string `json:"channel"`
	Idx     uint16 `json:"idx"`
	// Recorded is set once the handover record landed: the grant follows.
	Recorded bool   `json:"recorded,omitempty"`
	Token    string `json:"token,omitempty"`
	// Sent is set once the token went out over the channel; a re-run clears it.
	Sent bool `json:"sent,omitempty"`
}

// roomRef is one room as this party sees it: a local name, the relay and
// this party's token on it, and the joins and adds in flight. The room's
// roster, keys, cursor and counters are the room state (room.State).
type roomRef struct {
	Name  string    `json:"name"`
	ID    string    `json:"id"`
	Relay string    `json:"relay"`
	Stage roomStage `json:"stage"`
	Token string    `json:"token,omitempty"`
	Idx   uint16    `json:"idx"`
	From  int64     `json:"from"`
	// Read is a read member: it pulls and puts nothing, so its room card and
	// its leave go over its channel (the room-token's role, or the relay's
	// read_only on a first put).
	Read bool `json:"read,omitempty"`
	// Via is the channel the invite came on: only it may seat this party
	// and hand it the token.
	Via string `json:"via,omitempty"`
	// Invite is the room-invite as it arrived, kept until the seat births
	// the state from it.
	Invite *roomInvite  `json:"invite,omitempty"`
	Adds   []pendingAdd `json:"adds,omitempty"`
	// Removals are the idxs whose removal record landed and whose revoke
	// has not: serve revokes them each round until the relay answers.
	Removals  []uint16          `json:"removals,omitempty"`
	Handovers []pendingHandover `json:"handovers,omitempty"`
	// CardSent is when this party's room card last went over a channel to
	// an admin (a read member's rotation, an identity change); it goes again
	// after room.RotateEvery when the admin's roster entry has not folded.
	CardSent time.Time `json:"cardSent,omitempty"`
	// Feed is a followed feed's link and cursor (stageFollowing, stageCut).
	Feed *followedFeed `json:"feed,omitempty"`
}

// followedFeed is what a link holder keeps of a feed beside the read token
// (Token): the link key, the owner's room signing key every record verifies
// under, and the cursor.
type followedFeed struct {
	Key    []byte `json:"key"`
	Owner  []byte `json:"owner"`
	Cursor int64  `json:"cursor"`
}

// handover is the pending handover over channel, nil when none.
func (r *roomRef) handover(channel string) *pendingHandover {
	for i := range r.Handovers {
		if r.Handovers[i].Channel == channel {
			return &r.Handovers[i]
		}
	}
	return nil
}

// add is the pending add over channel, nil when none.
func (r *roomRef) add(channel string) *pendingAdd {
	for i := range r.Adds {
		if r.Adds[i].Channel == channel {
			return &r.Adds[i]
		}
	}
	return nil
}

// dropAdd forgets the pending add over channel.
func (r *roomRef) dropAdd(channel string) {
	out := r.Adds[:0]
	for _, a := range r.Adds {
		if a.Channel != channel {
			out = append(out, a)
		}
	}
	r.Adds = out
}

type roomsRecord struct {
	V     int       `json:"v"`
	Rooms []roomRef `json:"rooms"`
}

// roomList is the rooms record loaded at a version.
type roomList struct {
	b       store.Backend
	version int64
	Rooms   []roomRef
}

func loadRooms(ctx context.Context, b store.Backend) (*roomList, error) {
	data, v, err := b.Load(ctx, roomsKey)
	if err != nil {
		return nil, err
	}
	l := &roomList{b: b, version: v}
	if data == nil {
		return l, nil
	}
	var rec roomsRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", store.ErrCorrupt, roomsKey, err)
	}
	if rec.V != roomsVersion {
		return nil, fmt.Errorf("%w: %s: record version %d, want %d", store.ErrCorrupt, roomsKey, rec.V, roomsVersion)
	}
	l.Rooms = rec.Rooms
	return l, nil
}

func (l *roomList) commit(ctx context.Context) error {
	data, err := json.Marshal(roomsRecord{V: roomsVersion, Rooms: l.Rooms})
	if err != nil {
		return err
	}
	v, err := l.b.Store(ctx, roomsKey, data, l.version)
	if err != nil {
		return err
	}
	l.version = v
	return nil
}

// byID is the room with id, nil when none.
func (l *roomList) byID(id string) *roomRef {
	for i := range l.Rooms {
		if l.Rooms[i].ID == id {
			return &l.Rooms[i]
		}
	}
	return nil
}

// byName is the room a command names: by its local name, else by its id.
func (l *roomList) byName(name string) *roomRef {
	for i := range l.Rooms {
		if l.Rooms[i].Name == name {
			return &l.Rooms[i]
		}
	}
	return l.byID(name)
}

// updateRooms loads the rooms record, applies fn and commits, reloading and
// reapplying when another host committed in between.
func updateRooms(ctx context.Context, b store.Backend, fn func(*roomList) error) error {
	var err error
	for i := 0; i < sendTries; i++ {
		var l *roomList
		if l, err = loadRooms(ctx, b); err != nil {
			return err
		}
		if err = fn(l); err != nil {
			return err
		}
		if err = l.commit(ctx); !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}
