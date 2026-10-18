package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/state/record"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
)

// recordVersion is the channel record format version.
const recordVersion = 1

// MaxSeen is how many message ids a channel record remembers; the oldest go
// first. The ratchet rejects a replayed ciphertext on its own; the seen set
// is the fleet's second check, by message id, and bounded so the record stays
// well under the backend's cap.
const MaxSeen = 1000

// Channel is one channel's record, loaded at a version: the libsignal
// session store and identity store for the channel, the seen ids, the pull
// cursor and the pinned peer. Mutations stay in memory until Commit.
type Channel struct {
	s       *Store
	name    string
	version int64
	rec     channelRecord
	// admitAll makes IsTrustedIdentity admit every key (AdmitAnyIdentity);
	// such a snapshot is never committed.
	admitAll bool
}

// ErrProbe is a Commit of a snapshot that admits any identity.
var ErrProbe = errors.New("store: a snapshot that admits any identity is not committed")

type channelRecord struct {
	V int `json:"v"`
	// Sessions holds libsignal session records by address (name:deviceId).
	Sessions map[string][]byte `json:"sessions"`
	// Identities holds the remote identity keys SaveIdentity recorded, 32 raw bytes by address.
	Identities map[string][]byte `json:"identities"`
	Seen       []seenID          `json:"seen"`
	// Cursor is the relay seq of the last envelope pulled; -1 before the first pull.
	Cursor int64 `json:"cursor"`
	// Root is the peer's pinned root public key; Card its newest root-signed card.
	Root []byte      `json:"root,omitempty"`
	Card *signedCard `json:"card,omitempty"`
	// Secret is the invite link's secret (design §4): set by invite on the
	// host and by accept on the guest, the key of the accept proof and an
	// input of the verification code. Nothing removes it.
	Secret []byte `json:"secret,omitempty"`
	// Held is a root-signed card of the peer naming a new identity key, kept
	// for the human (design §3.2: 先提示人再生效) with the relay seq it came in
	// under; the channel waits while it is set.
	Held *heldCard `json:"held,omitempty"`
	// Deposited is how many one-time prekeys this party believes the relay
	// holds for its side of the channel: set from the relay's count at each
	// deposit, one less for each PreKey message that spent one.
	Deposited int `json:"deposited,omitempty"`
	// Announced is the id of the signed prekey the card this party last sent
	// on the channel carried; a rotation makes it stale, and serve resends.
	Announced uint32 `json:"announced,omitempty"`
	// Gone marks a tombstone (Drop): the party forgot the peer, and the
	// channel's sessions, pin and secret are not kept.
	Gone bool `json:"gone,omitempty"`
}

type seenID struct {
	ID  string `json:"id"`
	Seq int64  `json:"seq"`
}

type signedCard struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
}

type heldCard struct {
	signedCard
	Seq int64 `json:"seq"`
}

// Channel loads the channel's record, fresh at version 0 when absent.
func (s *Store) Channel(ctx context.Context, name string) (*Channel, error) {
	key := ChannelKey(name)
	if !ValidKey(key) {
		return nil, fmt.Errorf("store: channel %q: not a record key", name)
	}
	c := &Channel{s: s, name: name}
	data, v, err := s.backend.Load(ctx, key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		c.rec = channelRecord{V: recordVersion, Sessions: map[string][]byte{}, Identities: map[string][]byte{}, Cursor: -1}
		return c, nil
	}
	if err := json.Unmarshal(data, &c.rec); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, key, err)
	}
	if c.rec.V != recordVersion {
		return nil, fmt.Errorf("%w: %s: record version %d, want %d", ErrCorrupt, key, c.rec.V, recordVersion)
	}
	if c.rec.Sessions == nil {
		c.rec.Sessions = map[string][]byte{}
	}
	if c.rec.Identities == nil {
		c.rec.Identities = map[string][]byte{}
	}
	c.version = v
	return c, nil
}

// Name is the channel id.
func (c *Channel) Name() string { return c.name }

// Version is the loaded version; Commit raises it.
func (c *Channel) Version() int64 { return c.version }

// Commit writes the record as version Version()+1. Another host's commit in
// between refuses with ErrConflict and changes nothing here: reload the
// channel and redo the work on it.
func (c *Channel) Commit(ctx context.Context) error {
	if c.admitAll {
		return ErrProbe
	}
	data, err := json.Marshal(c.rec)
	if err != nil {
		return err
	}
	v, err := c.s.backend.Store(ctx, ChannelKey(c.name), data, c.version)
	if err != nil {
		return err
	}
	c.version = v
	return nil
}

// Drop replaces the record with a tombstone at the next version: the party
// forgot the peer (peer forget), so the sessions, the pinned root and card,
// the invite secret and the seen ids go. Channel ids are never reused, so
// nothing loads the tombstone again. Another host's version refuses with
// ErrConflict.
func (c *Channel) Drop(ctx context.Context) error {
	data, err := json.Marshal(channelRecord{V: recordVersion, Cursor: c.rec.Cursor, Gone: true})
	if err != nil {
		return err
	}
	v, err := c.s.backend.Store(ctx, ChannelKey(c.name), data, c.version)
	if err != nil {
		return err
	}
	c.version = v
	c.rec = channelRecord{V: recordVersion, Sessions: map[string][]byte{}, Identities: map[string][]byte{}, Cursor: c.rec.Cursor, Gone: true}
	return nil
}

// Gone reports whether the record is a tombstone (Drop).
func (c *Channel) Gone() bool { return c.rec.Gone }

// Cursor is the relay seq of the last envelope pulled, -1 before the first.
func (c *Channel) Cursor() int64 { return c.rec.Cursor }

// SetCursor records the relay seq of the last envelope pulled.
func (c *Channel) SetCursor(seq int64) { c.rec.Cursor = seq }

// Seen reports whether a message id was marked seen.
func (c *Channel) Seen(id string) bool {
	for _, s := range c.rec.Seen {
		if s.ID == id {
			return true
		}
	}
	return false
}

// MarkSeen records a message id with the relay seq it arrived under.
func (c *Channel) MarkSeen(id string, seq int64) {
	if c.Seen(id) {
		return
	}
	c.rec.Seen = append(c.rec.Seen, seenID{ID: id, Seq: seq})
	if n := len(c.rec.Seen) - MaxSeen; n > 0 {
		c.rec.Seen = append([]seenID(nil), c.rec.Seen[n:]...)
	}
}

// Received reports whether a message from the peer has opened on this
// channel: the seen set holds an id. The set drops its oldest ids past
// MaxSeen and is never emptied.
func (c *Channel) Received() bool { return len(c.rec.Seen) > 0 }

// Root is the peer's pinned root public key, nil before PinRoot.
func (c *Channel) Root() ed25519.PublicKey {
	if c.rec.Root == nil {
		return nil
	}
	return ed25519.PublicKey(append([]byte(nil), c.rec.Root...))
}

// PinRoot records the peer's root public key.
func (c *Channel) PinRoot(root ed25519.PublicKey) { c.rec.Root = append([]byte(nil), root...) }

// Card is the peer's newest pinned card as it travelled, nil before PinCard.
func (c *Channel) Card() *card.Signed {
	if c.rec.Card == nil {
		return nil
	}
	return &card.Signed{Body: append([]byte(nil), c.rec.Card.Body...), Sig: append([]byte(nil), c.rec.Card.Sig...)}
}

// PinCard records s as the peer's newest root-signed card. The caller has
// verified it (card.Verify); from here on IsTrustedIdentity accepts only the
// identity keys it lists.
func (c *Channel) PinCard(s *card.Signed) {
	c.rec.Card = &signedCard{Body: append([]byte(nil), s.Body...), Sig: append([]byte(nil), s.Sig...)}
}

// Secret is the invite link's secret, nil before SetSecret.
func (c *Channel) Secret() []byte {
	if c.rec.Secret == nil {
		return nil
	}
	return append([]byte(nil), c.rec.Secret...)
}

// SetSecret records the invite link's secret.
func (c *Channel) SetSecret(secret []byte) { c.rec.Secret = append([]byte(nil), secret...) }

// Held is the peer's root-signed card naming a new identity key that waits
// for the human, with the relay seq it came in under; nil, 0 when none.
func (c *Channel) Held() (*card.Signed, int64) {
	if c.rec.Held == nil {
		return nil, 0
	}
	return &card.Signed{Body: append([]byte(nil), c.rec.Held.Body...), Sig: append([]byte(nil), c.rec.Held.Sig...)}, c.rec.Held.Seq
}

// Hold keeps s, verified by the caller against the pinned root, for the
// human's yes; seq is the relay seq it came in under.
func (c *Channel) Hold(s *card.Signed, seq int64) {
	c.rec.Held = &heldCard{signedCard{Body: append([]byte(nil), s.Body...), Sig: append([]byte(nil), s.Sig...)}, seq}
}

// ClearHeld drops the held card.
func (c *Channel) ClearHeld() { c.rec.Held = nil }

// Deposited is how many one-time prekeys the relay is believed to hold for
// this party's side of the channel.
func (c *Channel) Deposited() int { return c.rec.Deposited }

// SetDeposited records the relay's count after a deposit.
func (c *Channel) SetDeposited(n int) { c.rec.Deposited = n }

// SpendDeposit records that a PreKey message spent one deposited key.
func (c *Channel) SpendDeposit() {
	if c.rec.Deposited > 0 {
		c.rec.Deposited--
	}
}

// Announced is the signed prekey id the card last sent on this channel carried, 0 when unknown.
func (c *Channel) Announced() uint32 { return c.rec.Announced }

// SetAnnounced records the signed prekey id the card being sent carries.
func (c *Channel) SetAnnounced(id uint32) { c.rec.Announced = id }

// AdmitAnyIdentity makes this snapshot admit every identity key, to read the
// record a key change arrives in (design §3.2) without applying anything: the
// snapshot refuses to commit from here on.
func (c *Channel) AdmitAnyIdentity() { c.admitAll = true }

// LoadSession is the libsignal session store: a fresh record for an address
// without one, never nil.
func (c *Channel) LoadSession(ctx context.Context, addr *protocol.SignalAddress) (*record.Session, error) {
	b, ok := c.rec.Sessions[addr.String()]
	if !ok {
		return record.NewSession(keys.Serializer.Session, keys.Serializer.State), nil
	}
	return record.NewSessionFromBytes(b, keys.Serializer.Session, keys.Serializer.State)
}

// GetSubDeviceSessions lists the device ids other than keys.DeviceID that
// name has sessions for.
func (c *Channel) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	var ids []uint32
	for k := range c.rec.Sessions {
		i := strings.LastIndex(k, ":")
		if i < 0 || k[:i] != name {
			continue
		}
		dev, err := strconv.ParseUint(k[i+1:], 10, 32)
		if err == nil && dev != keys.DeviceID {
			ids = append(ids, uint32(dev))
		}
	}
	return ids, nil
}

// StoreSession keeps the session record's bytes for addr.
func (c *Channel) StoreSession(ctx context.Context, addr *protocol.SignalAddress, r *record.Session) error {
	c.rec.Sessions[addr.String()] = r.Serialize()
	return nil
}

// ContainsSession reports whether addr has a session record.
func (c *Channel) ContainsSession(ctx context.Context, addr *protocol.SignalAddress) (bool, error) {
	_, ok := c.rec.Sessions[addr.String()]
	return ok, nil
}

// DeleteSession drops addr's session record.
func (c *Channel) DeleteSession(ctx context.Context, addr *protocol.SignalAddress) error {
	delete(c.rec.Sessions, addr.String())
	return nil
}

// DeleteAllSessions drops every session record of the channel.
func (c *Channel) DeleteAllSessions(ctx context.Context) error {
	c.rec.Sessions = map[string][]byte{}
	return nil
}

// GetIdentityKeyPair serves the party's identity key pair.
func (c *Channel) GetIdentityKeyPair() *identity.KeyPair { return c.s.identity.KeyPair }

// GetLocalRegistrationID serves the party's registrationId.
func (c *Channel) GetLocalRegistrationID() uint32 { return c.s.identity.RegistrationID }

// SaveIdentity records the remote identity key the library saw for addr.
func (c *Channel) SaveIdentity(ctx context.Context, addr *protocol.SignalAddress, key *identity.Key) error {
	raw := key.PublicKey().PublicKey()
	c.rec.Identities[addr.String()] = raw[:]
	return nil
}

// RemoteIdentity is the identity key SaveIdentity recorded for addr — the
// key the session was built with — for the host's check against the pinned
// card's keys[].identity (design §3.4).
func (c *Channel) RemoteIdentity(addr *protocol.SignalAddress) ([32]byte, bool) {
	var out [32]byte
	b, ok := c.rec.Identities[addr.String()]
	if !ok || len(b) != 32 {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

// IsTrustedIdentity accepts any identity key until a card is pinned, and
// after that only the identity keys the pinned card lists and has not
// retired: a rotated card makes the old session's next Encrypt or Decrypt
// fail with signalerror.ErrUntrustedIdentity, the teardown design §3.2 wants,
// and whoever holds the voided key is refused with it. Before the pin the
// host checks the first contact itself, after decrypting the peer's card
// (§3.4: session identity == card keys[].identity).
func (c *Channel) IsTrustedIdentity(ctx context.Context, addr *protocol.SignalAddress, key *identity.Key) (bool, error) {
	if c.rec.Card == nil || c.admitAll {
		return true, nil
	}
	var pinned card.Card
	if err := json.Unmarshal(c.rec.Card.Body, &pinned); err != nil {
		return false, fmt.Errorf("%w: pinned card: %v", ErrCorrupt, err)
	}
	want := key.PublicKey().PublicKey()
	now := time.Now()
	for i := range pinned.Keys {
		if pinned.Keys[i].Retired(now) {
			continue
		}
		raw, err := keys.ParseCurve(pinned.Keys[i].Identity)
		if err != nil {
			return false, fmt.Errorf("pinned card: %w", err)
		}
		if raw == want {
			return true, nil
		}
	}
	return false, nil
}
