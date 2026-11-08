package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// FeedKey is the record key of the party's feed record.
const FeedKey = "feed"

// Feed is the party's feed record: the source secret its hosts say hello to
// the reader feed with, and every reader link minted, by the hash of its
// token. It is the one home of both — every machine of the party reads it,
// nothing is provisioned by hand, and no machine needs root.json to set the
// feed up or mint a link (plan-delivery decision 33). The worker holds the
// hashes alone. Source is "" and Readers nil while the record is absent.
type Feed struct {
	s       *Store
	version int64
	present bool
	// Source is the source secret, in clear.
	Source string
	// Readers is every link minted and not revoked, in minting order.
	Readers []FeedReader
}

// FeedReader is one minted link: the hash of its token as the worker names
// it, the label the person gave it, and when it was minted.
type FeedReader struct {
	Hash  string `json:"hash"`
	Label string `json:"label"`
	At    string `json:"at"`
}

type feedRecord struct {
	V       int          `json:"v"`
	Source  string       `json:"source"`
	Readers []FeedReader `json:"readers"`
}

// Feed loads the feed record, empty at version 0 when absent.
func (s *Store) Feed(ctx context.Context) (*Feed, error) {
	f := &Feed{s: s}
	data, v, err := s.backend.Load(ctx, FeedKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return f, nil
	}
	var rec feedRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, FeedKey, err)
	}
	if rec.V != recordVersion {
		return nil, fmt.Errorf("%w: %s: record version %d, want %d", ErrCorrupt, FeedKey, rec.V, recordVersion)
	}
	if rec.Source == "" {
		return nil, fmt.Errorf("%w: %s: no source secret", ErrCorrupt, FeedKey)
	}
	f.version, f.present, f.Source, f.Readers = v, true, rec.Source, rec.Readers
	return f, nil
}

// Present reports whether the record holds a feed.
func (f *Feed) Present() bool { return f.present }

// Version is the loaded version; Commit raises it.
func (f *Feed) Version() int64 { return f.version }

// Hashes is the readers' token hashes, in record order; never nil.
func (f *Feed) Hashes() []string {
	out := make([]string, 0, len(f.Readers))
	for _, r := range f.Readers {
		out = append(out, r.Hash)
	}
	return out
}

// Commit writes the record as version Version()+1; ErrConflict as Channel.Commit.
func (f *Feed) Commit(ctx context.Context) error {
	if f.Source == "" {
		return fmt.Errorf("store: %s: no source secret to commit", FeedKey)
	}
	readers := f.Readers
	if readers == nil {
		readers = []FeedReader{}
	}
	data, err := json.Marshal(feedRecord{V: recordVersion, Source: f.Source, Readers: readers})
	if err != nil {
		return err
	}
	v, err := f.s.backend.Store(ctx, FeedKey, data, f.version)
	if err != nil {
		return err
	}
	f.version, f.present = v, true
	return nil
}
