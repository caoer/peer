// Package status is what a party knows about each peer beyond the session
// itself, and the roster page that shows it (design §8 花名册页).
//
// The activity record, key "act.<channel>" in the party's store beside the
// channel's "ss." record, holds the channel's last message from the peer and
// the unread count: serve notes every message it births, peer send notes
// every message it commits. It is advisory — a failed note is logged by the
// caller and never costs a message — and shared by every host of the party
// like the rest of the store, so any host's serve or status reads the same
// numbers.
//
// Unread counts the peer's messages born on this party since the party last
// sent anything on the channel; an ack from the peer is not counted. The
// store knows no reader, so "read" is "answered": sending on the channel —
// a reply, an ack, anything — clears it.
package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/caoer/peer/internal/store"
)

// ActivityKey is a channel's activity record key.
func ActivityKey(channel string) string { return "act." + channel }

const activityVersion = 1

// Activity is one channel's activity record.
type Activity struct {
	V int `json:"v"`
	// LastAt and LastKind are the peer's newest message born here: its own
	// at stamp and kind; LastSeq the relay seq it came under. Zero before
	// the first.
	LastAt   time.Time `json:"lastAt"`
	LastKind string    `json:"lastKind"`
	LastSeq  int64     `json:"lastSeq"`
	// Unread is the peer's messages born since SentAt, acks not counted.
	Unread int `json:"unread"`
	// SentAt is the at stamp of this party's newest message committed on
	// the channel; zero before the first.
	SentAt time.Time `json:"sentAt"`
}

// LoadActivity reads a channel's activity record; absent, it is the zero
// record at version 0.
func LoadActivity(ctx context.Context, b store.Backend, channel string) (*Activity, int64, error) {
	key := ActivityKey(channel)
	data, v, err := b.Load(ctx, key)
	if err != nil {
		return nil, 0, err
	}
	a := &Activity{V: activityVersion}
	if data == nil {
		return a, 0, nil
	}
	if err := json.Unmarshal(data, a); err != nil {
		return nil, 0, fmt.Errorf("%w: %s: %v", store.ErrCorrupt, key, err)
	}
	if a.V != activityVersion {
		return nil, 0, fmt.Errorf("%w: %s: record version %d, want %d", store.ErrCorrupt, key, a.V, activityVersion)
	}
	return a, v, nil
}

// updateTries bounds the reloads when another host noted in between.
const updateTries = 5

func update(ctx context.Context, b store.Backend, channel string, fn func(*Activity)) error {
	var err error
	for i := 0; i < updateTries; i++ {
		var a *Activity
		var v int64
		if a, v, err = LoadActivity(ctx, b, channel); err != nil {
			return err
		}
		fn(a)
		var data []byte
		if data, err = json.Marshal(a); err != nil {
			return err
		}
		if _, err = b.Store(ctx, ActivityKey(channel), data, v); !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

// NoteIn records a message from the peer born under relay seq: the newest
// by seq is the last message, and every one but an ack is unread.
func NoteIn(ctx context.Context, b store.Backend, channel string, seq int64, at time.Time, kind string) error {
	return update(ctx, b, channel, func(a *Activity) {
		if a.LastAt.IsZero() || seq > a.LastSeq {
			a.LastAt, a.LastKind, a.LastSeq = at, kind, seq
		}
		if kind != "ack" {
			a.Unread++
		}
	})
}

// NoteOut records a message this party committed on the channel: what came
// before it is answered.
func NoteOut(ctx context.Context, b store.Backend, channel string, at time.Time) error {
	return update(ctx, b, channel, func(a *Activity) {
		if at.After(a.SentAt) {
			a.SentAt = at
		}
		a.Unread = 0
	})
}
