package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/caoer/peer/internal/e2e"
	"github.com/caoer/peer/internal/store"
)

// A reader page generates its key pair on first open and sends the public
// key in every hello (plan-delivery decision 27); the feed Object passes it
// to the sources with the replay request. The key lands here, in the shared
// state record readers-pending, which every host of the party reads and
// writes under CAS, and serve says so once on its journal — the wake line
// peer-wake forwards to the party's position (osfiles peer-wake.sh, U0c) —
// so that peer e2e publish, run where root.json is, folds it into the card's
// details.readers. No key string is shown or pasted.

// readersPendingKey is the state record's key.
const readersPendingKey = "readers-pending"

// readersPending is the record: {"v":1,"keys":[{"key","reader","at"},…]}.
type readersPending struct {
	V    int             `json:"v"`
	Keys []pendingReader `json:"keys"`
}

// pendingReader is one key a page sent: the key, the hash of the reader
// token it came with, and when.
type pendingReader struct {
	Key    string `json:"key"`
	Reader string `json:"reader"`
	At     string `json:"at"`
}

const readersPendingVersion = 1

// readerHashRE is a reader token's hash as the Object names it.
var readerHashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// wakeReaderKey is the journal line a new key raises, for the wake.
const wakeReaderKey = "peer reader key pending for %s: peer e2e publish where root.json is\n"

// pendingTries bounds the CAS reloads on another host's commit.
const pendingTries = 5

// readerKey is the feed's Key callback: the key into readers-pending, and the
// wake line when it is new.
func (p *party) readerKey(key, reader string) {
	log := p.timelineLog()
	added, err := p.addPendingReader(context.Background(), key, reader, time.Now())
	if err != nil {
		fmt.Fprintf(log, "feed: reader key %s: %v\n", tail(key), err)
		return
	}
	if added {
		fmt.Fprintf(log, wakeReaderKey, p.partyID())
	}
}

// addPendingReader records key, sent with the token hashed reader, unless the
// card or the record holds it already; true when it was added.
func (p *party) addPendingReader(ctx context.Context, key, reader string, at time.Time) (bool, error) {
	if _, err := e2e.ParsePublic(key); err != nil {
		return false, err
	}
	if !readerHashRE.MatchString(reader) {
		return false, fmt.Errorf("reader %q is not a token hash", reader)
	}
	if slices.Contains(p.ownReaders(ctx), key) {
		return false, nil
	}
	for try := 1; ; try++ {
		rec, v, err := p.loadPendingReaders(ctx)
		if err != nil {
			return false, err
		}
		if slices.ContainsFunc(rec.Keys, func(k pendingReader) bool { return k.Key == key }) {
			return false, nil
		}
		rec.Keys = append(rec.Keys, pendingReader{Key: key, Reader: reader, At: at.UTC().Format(time.RFC3339)})
		err = p.storePendingReaders(ctx, rec, v)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, store.ErrConflict) || try >= pendingTries {
			return false, err
		}
	}
}

// dropPendingReaders takes keys out of the record, under CAS, so a key another
// host added meanwhile stays.
func (p *party) dropPendingReaders(ctx context.Context, keys []string) error {
	for try := 1; ; try++ {
		rec, v, err := p.loadPendingReaders(ctx)
		if err != nil {
			return err
		}
		rec.Keys = slices.DeleteFunc(rec.Keys, func(k pendingReader) bool { return slices.Contains(keys, k.Key) })
		err = p.storePendingReaders(ctx, rec, v)
		if err == nil || !errors.Is(err, store.ErrConflict) || try >= pendingTries {
			return err
		}
	}
}

// loadPendingReaders reads the record and its version; empty at 0 when absent.
func (p *party) loadPendingReaders(ctx context.Context) (*readersPending, int64, error) {
	data, v, err := p.backend.Load(ctx, readersPendingKey)
	if err != nil {
		return nil, 0, err
	}
	rec := &readersPending{V: readersPendingVersion}
	if data == nil {
		return rec, v, nil
	}
	if err := json.Unmarshal(data, rec); err != nil {
		return nil, 0, fmt.Errorf("%w: %s: %v", store.ErrCorrupt, readersPendingKey, err)
	}
	if rec.V != readersPendingVersion {
		return nil, 0, fmt.Errorf("%w: %s: record version %d, want %d", store.ErrCorrupt, readersPendingKey, rec.V, readersPendingVersion)
	}
	return rec, v, nil
}

func (p *party) storePendingReaders(ctx context.Context, rec *readersPending, v int64) error {
	if rec.Keys == nil {
		rec.Keys = []pendingReader{}
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = p.backend.Store(ctx, readersPendingKey, data, v)
	return err
}
