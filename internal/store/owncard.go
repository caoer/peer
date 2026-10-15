package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/caoer/peer/internal/card"
)

// OwnCardKey is the record key of the party's own card.
const OwnCardKey = "card"

// OwnCard is the party's own root-signed card on the store, in both forms it
// travels: without details (envelope #0, in clear on the relay) and with
// details (in-session). The root key signs it where the root lives — peer
// init, peer card publish, peer identity rotate — and every host reads it
// from here, so no fleet host needs root.json to open a channel, answer a
// card or announce a rotation. The fields are nil while the record is absent.
type OwnCard struct {
	s       *Store
	version int64
	// Issued is when the card was signed; Identity the identity key its
	// current key names, in text form; SignedPrekey the signed prekey id it
	// carries — what a reader compares against its own to see the card is stale.
	Issued       time.Time
	Identity     string
	SignedPrekey uint32
	// Public is the card without details, Details the one with them.
	Public, Details *card.Signed
}

type ownCardRecord struct {
	V            int        `json:"v"`
	Issued       time.Time  `json:"issued"`
	Identity     string     `json:"identity"`
	SignedPrekey uint32     `json:"signedPrekey"`
	Public       signedCard `json:"public"`
	Details      signedCard `json:"details"`
}

// OwnCard loads the party's card record, empty at version 0 when absent.
func (s *Store) OwnCard(ctx context.Context) (*OwnCard, error) {
	c := &OwnCard{s: s}
	data, v, err := s.backend.Load(ctx, OwnCardKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return c, nil
	}
	var rec ownCardRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, OwnCardKey, err)
	}
	if rec.V != recordVersion {
		return nil, fmt.Errorf("%w: %s: record version %d, want %d", ErrCorrupt, OwnCardKey, rec.V, recordVersion)
	}
	c.version = v
	c.Issued, c.Identity, c.SignedPrekey = rec.Issued, rec.Identity, rec.SignedPrekey
	c.Public = &card.Signed{Body: rec.Public.Body, Sig: rec.Public.Sig}
	c.Details = &card.Signed{Body: rec.Details.Body, Sig: rec.Details.Sig}
	return c, nil
}

// Present reports whether the record holds a card.
func (c *OwnCard) Present() bool { return c.Public != nil }

// Version is the loaded version; Commit raises it.
func (c *OwnCard) Version() int64 { return c.version }

// Set replaces the record's content in memory; Commit writes it.
func (c *OwnCard) Set(issued time.Time, identity string, signedPrekey uint32, public, details *card.Signed) {
	c.Issued, c.Identity, c.SignedPrekey, c.Public, c.Details = issued.UTC(), identity, signedPrekey, public, details
}

// Commit writes the record as version Version()+1; ErrConflict as Channel.Commit.
func (c *OwnCard) Commit(ctx context.Context) error {
	if c.Public == nil || c.Details == nil {
		return fmt.Errorf("store: %s: no card to commit", OwnCardKey)
	}
	data, err := json.Marshal(ownCardRecord{
		V: recordVersion, Issued: c.Issued, Identity: c.Identity, SignedPrekey: c.SignedPrekey,
		Public:  signedCard{Body: c.Public.Body, Sig: c.Public.Sig},
		Details: signedCard{Body: c.Details.Body, Sig: c.Details.Sig},
	})
	if err != nil {
		return err
	}
	v, err := c.s.backend.Store(ctx, OwnCardKey, data, c.version)
	if err != nil {
		return err
	}
	c.version = v
	return nil
}
