// Package roster is the party's list of channels: for each peer its local
// name (design §3.1: names are local), the channel id, the relay the
// channel lives on, this party's side and token, and how far the invite has
// gone. It is one record, key "peers", in the party's store, so every fleet
// host that holds the store can serve every channel. The peer's root key and
// card live on the channel record (store.Channel), not here.
package roster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/caoer/peer/internal/store"
)

// Key is the roster record's key in the store.
const Key = "peers"

const recordVersion = 1

// Side is which token a party holds on a channel.
type Side string

const (
	// Host created the channel: it invited.
	Host Side = "host"
	// Guest joined with the invite token: it accepted.
	Guest Side = "guest"
)

// State is how far the invite has gone.
type State string

const (
	// Invited: the host created the channel and waits for the guest's card and the code.
	Invited State = "invited"
	// Accepted: the guest joined, built the session and sent its card; the host's confirm is pending.
	Accepted State = "accepted"
	// Confirmed: the host checked the session identity and the code and pinned the guest's card.
	Confirmed State = "confirmed"
	// Gone: the peer forgot the channel (its bye arrived). Nothing is sent or
	// pulled on it; the name stays taken until this party forgets it too.
	Gone State = "gone"
)

// Peer is one channel as this party sees it.
type Peer struct {
	Name    string `json:"name"`
	Channel string `json:"channel"`
	Relay   string `json:"relay"`
	Side    Side   `json:"side"`
	Token   string `json:"token"`
	State   State  `json:"state"`
}

type record struct {
	V     int    `json:"v"`
	Peers []Peer `json:"peers"`
}

// Roster is the record loaded at a version; Set changes it in memory and
// Commit writes it back under CAS.
type Roster struct {
	b       store.Backend
	version int64
	Peers   []Peer
}

// Load reads the roster, empty at version 0 when absent.
func Load(ctx context.Context, b store.Backend) (*Roster, error) {
	data, v, err := b.Load(ctx, Key)
	if err != nil {
		return nil, err
	}
	r := &Roster{b: b, version: v}
	if data == nil {
		return r, nil
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", store.ErrCorrupt, Key, err)
	}
	if rec.V != recordVersion {
		return nil, fmt.Errorf("%w: %s: record version %d, want %d", store.ErrCorrupt, Key, rec.V, recordVersion)
	}
	r.Peers = rec.Peers
	return r, nil
}

// Version is the loaded version; Commit raises it.
func (r *Roster) Version() int64 { return r.version }

// Commit writes the roster as version Version()+1; another host's commit in
// between is store.ErrConflict and changes nothing.
func (r *Roster) Commit(ctx context.Context) error {
	data, err := json.Marshal(record{V: recordVersion, Peers: r.Peers})
	if err != nil {
		return err
	}
	v, err := r.b.Store(ctx, Key, data, r.version)
	if err != nil {
		return err
	}
	r.version = v
	return nil
}

// ByName is the peer called name, nil when none.
func (r *Roster) ByName(name string) *Peer {
	for i := range r.Peers {
		if r.Peers[i].Name == name {
			return &r.Peers[i]
		}
	}
	return nil
}

// ByChannel is the peer on channel id, nil when none.
func (r *Roster) ByChannel(id string) *Peer {
	for i := range r.Peers {
		if r.Peers[i].Channel == id {
			return &r.Peers[i]
		}
	}
	return nil
}

// Set adds p, replacing the peer of the same name.
func (r *Roster) Set(p Peer) {
	if cur := r.ByName(p.Name); cur != nil {
		*cur = p
		return
	}
	r.Peers = append(r.Peers, p)
}

// Remove drops the peer named name on channel, and reports whether it was there.
func (r *Roster) Remove(name, channel string) bool {
	for i := range r.Peers {
		if r.Peers[i].Name == name && r.Peers[i].Channel == channel {
			r.Peers = append(r.Peers[:i], r.Peers[i+1:]...)
			return true
		}
	}
	return false
}

// updateTries bounds Update's reloads on conflict.
const updateTries = 5

// Update loads the roster, applies fn and commits, reloading and reapplying
// when another host committed in between.
func Update(ctx context.Context, b store.Backend, fn func(*Roster) error) error {
	var err error
	for i := 0; i < updateTries; i++ {
		var r *Roster
		if r, err = Load(ctx, b); err != nil {
			return err
		}
		if err = fn(r); err != nil {
			return err
		}
		if err = r.Commit(ctx); !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}
