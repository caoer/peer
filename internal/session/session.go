// Package session runs the Signal session of one channel over the store's
// snapshots: X3DH from the peer's card and a one-time prekey, encrypt and
// decrypt with the libsignal Double Ratchet, the plaintext message format,
// the send order of plan decision 5 and the 8-digit verification code.
//
// Identity trust is the pinned card's: the channel's IsTrustedIdentity
// (package store) admits only the identity keys the peer's root-signed card
// lists, so Establish wants the card pinned first, and the host's first
// contact check (design §3.4) is CheckIdentity after the peer's card
// arrived in-session.
package session

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	signal "go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/util/keyhelper"
	"go.mau.fi/libsignal/util/optional"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/store"
)

// Addr is the peer's libsignal address in every channel: v1 channels are
// pairwise (design §10 #1), so the one remote party is "peer" at
// keys.DeviceID and a channel record holds one session.
var Addr = protocol.NewSignalAddress("peer", keys.DeviceID)

// Errors a caller can match.
var (
	ErrIdentity   = errors.New("session: the session's identity key is not the card's")
	ErrDuplicate  = errors.New("session: message already received")
	ErrNotMessage = errors.New("session: envelope is not a message")
	ErrNoCard     = errors.New("session: peer card not pinned")
	ErrNoKey      = errors.New("session: card has no current key")
)

// Session binds a channel's and the party keys' snapshots to libsignal for
// the channel's peer. Mutations stay in the snapshots until they are
// committed; Send commits the channel, every other caller commits itself.
type Session struct {
	Channel *store.Channel
	Keys    *store.Keys
	builder *signal.Builder
	cipher  *signal.Cipher
}

// New opens the channel's session over its snapshots.
func New(ch *store.Channel, k *store.Keys) *Session {
	b := signal.NewBuilder(ch, k, k, ch, Addr, keys.Serializer)
	return &Session{Channel: ch, Keys: k, builder: b, cipher: signal.NewCipher(b, Addr)}
}

// CurrentKey is the card's key in force: the first with no Until.
func CurrentKey(c *card.Card) (*card.Key, error) {
	for i := range c.Keys {
		if c.Keys[i].Until == nil {
			return &c.Keys[i], nil
		}
	}
	return nil, ErrNoKey
}

// Establish runs X3DH against the peer: k is the current key of its pinned
// card, opk a one-time prekey taken from the relay (nil when its side held
// none). The channel must have the card pinned so the bundle's identity key
// is admitted only when the card lists it.
func (s *Session) Establish(ctx context.Context, k *card.Key, opk *relay.Prekey) error {
	if s.Channel.Card() == nil {
		return ErrNoCard
	}
	idk, err := k.IdentityKey()
	if err != nil {
		return err
	}
	spk, sig, err := k.SignedPrekeyPublic()
	if err != nil {
		return err
	}
	opkID := optional.NewEmptyUint32()
	var opkPub ecc.ECPublicKeyable
	if opk != nil {
		if err := envelope.CheckKey(opk.Pub); err != nil {
			return fmt.Errorf("one-time prekey %d: %w", opk.ID, err)
		}
		if opkPub, err = ecc.DecodePoint(opk.Pub, 0); err != nil {
			return fmt.Errorf("one-time prekey %d: %w", opk.ID, err)
		}
		opkID = optional.NewOptionalUint32(opk.ID)
	}
	bundle := prekey.NewBundle(k.RegistrationID, keys.DeviceID, opkID, k.SignedPrekey.ID, opkPub, spk, sig, idk)
	return s.builder.ProcessBundle(ctx, bundle)
}

// Encrypt makes the relay record for m: a PreKey message until the peer's
// first reply is decrypted, a normal message after.
func (s *Session) Encrypt(ctx context.Context, m *Message) (envelope.Envelope, error) {
	plain, err := m.Marshal()
	if err != nil {
		return envelope.Envelope{}, err
	}
	ct, err := s.cipher.Encrypt(ctx, plain)
	if err != nil {
		return envelope.Envelope{}, err
	}
	typ := envelope.Msg
	if ct.Type() == protocol.PREKEY_TYPE {
		typ = envelope.Prekey
	}
	e := envelope.Envelope{Type: typ, Body: ct.Serialize()}
	if err := e.Check(); err != nil {
		return envelope.Envelope{}, err
	}
	return e, nil
}

// Receive decrypts one pulled record and advances the channel's cursor and
// seen set in the snapshot. A record at or before the cursor, or a message
// id already seen, is ErrDuplicate; a card record (envelope #0) is
// ErrNotMessage; malformed bytes never reach the library.
func (s *Session) Receive(ctx context.Context, rec relay.Record) (*Message, error) {
	if rec.Err != nil {
		return nil, rec.Err
	}
	if rec.Seq <= s.Channel.Cursor() {
		return nil, fmt.Errorf("%w: seq %d at cursor %d", ErrDuplicate, rec.Seq, s.Channel.Cursor())
	}
	plain, err := s.decrypt(ctx, rec.Env)
	if err != nil {
		return nil, err
	}
	m, err := UnmarshalMessage(plain)
	if err != nil {
		return nil, err
	}
	if s.Channel.Seen(m.ID) {
		s.Channel.SetCursor(rec.Seq)
		return nil, fmt.Errorf("%w: id %s", ErrDuplicate, m.ID)
	}
	s.Channel.MarkSeen(m.ID, rec.Seq)
	s.Channel.SetCursor(rec.Seq)
	return m, nil
}

func (s *Session) decrypt(ctx context.Context, e envelope.Envelope) (plain []byte, err error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	ser := keys.Serializer
	err = envelope.Safe(func() error {
		switch e.Type {
		case envelope.Prekey:
			m, err := protocol.NewPreKeySignalMessageFromBytes(e.Body, ser.PreKeySignalMessage, ser.SignalMessage)
			if err != nil {
				return err
			}
			plain, err = s.cipher.DecryptMessage(ctx, m)
			return err
		case envelope.Msg:
			m, err := protocol.NewSignalMessageFromBytes(e.Body, ser.SignalMessage)
			if err != nil {
				return err
			}
			plain, err = s.cipher.Decrypt(ctx, m)
			return err
		default:
			return ErrNotMessage
		}
	})
	return plain, err
}

// CheckIdentity is the first-contact check of design §3.4: the identity key
// the session was built with must be one the peer's card lists. Run it on
// the card that arrived in-session, before pinning it.
func (s *Session) CheckIdentity(c *card.Card) error {
	got, ok := s.Channel.RemoteIdentity(Addr)
	if !ok {
		return fmt.Errorf("%w: no session identity", ErrIdentity)
	}
	for _, k := range c.Keys {
		raw, err := keys.ParseCurve(k.Identity)
		if err != nil {
			return err
		}
		if raw == got {
			return nil
		}
	}
	return ErrIdentity
}

// PeerCard reads a card the peer sent in-session (kind card): the detached
// signature and card bytes, verified against the root the card itself
// names. Whether that root is the right party is the caller's question —
// the pinned root, or the verification code at first contact.
func PeerCard(m *Message) (*card.Card, *card.Signed, ed25519.PublicKey, error) {
	if m.Kind != KindCard {
		return nil, nil, nil, fmt.Errorf("session: message kind %q, want %s", m.Kind, KindCard)
	}
	body, sig, err := envelope.UnpackCard(m.Body)
	if err != nil {
		return nil, nil, nil, err
	}
	var top struct {
		Party string `json:"party"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, nil, nil, fmt.Errorf("session: card: %w", err)
	}
	root, err := keys.ParsePartyID(top.Party)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("session: card: %w", err)
	}
	signed := &card.Signed{Body: body, Sig: sig}
	c, err := card.Verify(signed, root)
	if err != nil {
		return nil, nil, nil, err
	}
	return c, signed, root, nil
}

// CardMessage packs a signed card as a kind-card message body.
func CardMessage(from, to string, s *card.Signed) (*Message, error) {
	e, err := envelope.PackCard(s.Body, s.Sig)
	if err != nil {
		return nil, err
	}
	return NewMessage(from, to, KindCard, e.Body)
}

// PutError is a Send whose relay put failed after the session state was
// committed: the ciphertext stays in the outbox, marked committed, for
// store.ReplayOutbox; a caller abandoning the channel removes Entry.
type PutError struct {
	Entry *store.Entry
	Err   error
}

func (e *PutError) Error() string { return "session: put after commit: " + e.Err.Error() }
func (e *PutError) Unwrap() error { return e.Err }

// Send runs decision 5's send order: encrypt, outbox, commit the channel,
// put, clear. A commit that finds another host's version drops the
// ciphertext and returns store.ErrConflict — reload the channel and send
// again; a put that fails after the commit returns a *PutError.
func (s *Session) Send(ctx context.Context, outbox *store.Journal, rc *relay.Client, token string, m *Message) (relay.Receipt, error) {
	e, err := s.Encrypt(ctx, m)
	if err != nil {
		return relay.Receipt{}, err
	}
	entry := &store.Entry{ID: m.ID, Channel: s.Channel.Name(), Type: e.Type.String(), Body: e.Body}
	if err := outbox.Add(entry); err != nil {
		return relay.Receipt{}, err
	}
	if err := s.Channel.Commit(ctx); err != nil {
		outbox.Remove(entry)
		return relay.Receipt{}, err
	}
	if err := outbox.MarkCommitted(entry); err != nil {
		return relay.Receipt{}, err
	}
	r, err := rc.Put(ctx, s.Channel.Name(), token, e)
	if err != nil {
		return relay.Receipt{}, &PutError{Entry: entry, Err: err}
	}
	return r, outbox.Remove(entry)
}

// NewPrekeys adds n fresh one-time prekeys to the party keys snapshot and
// returns their public halves for the relay. Each channel gets its own
// keys: a key deposited on two channels could be taken twice, and the
// second PreKey message naming it would find it gone. Commit the keys
// before depositing them.
func NewPrekeys(ctx context.Context, k *store.Keys, n int) ([]relay.Prekey, error) {
	if k.PartyKeys == nil {
		return nil, store.ErrNoKeys
	}
	start := int(k.PartyKeys.NextPrekeyID)
	// GeneratePreKeys' second argument is the inclusive end id.
	recs, err := keyhelper.GeneratePreKeys(start, start+n-1, keys.Serializer.PreKeyRecord)
	if err != nil {
		return nil, err
	}
	out := make([]relay.Prekey, 0, len(recs))
	for _, r := range recs {
		if err := k.StorePreKey(ctx, r.ID().Value, r); err != nil {
			return nil, err
		}
		out = append(out, relay.Prekey{ID: r.ID().Value, Pub: r.KeyPair().PublicKey().Serialize()})
	}
	return out, nil
}

// codeInfo labels the verification code hash; a new value is a new code.
const codeInfo = "peer verification code v1"

// Code is the channel's 8-digit verification code (design §4): both root
// keys, inviter first, hashed under a fixed label. The invitee prints it
// after accept and reads it back over the channel the link came on; the
// inviter types it at confirm.
func Code(inviter, invitee ed25519.PublicKey) string {
	h := sha256.New()
	h.Write([]byte(codeInfo))
	h.Write(inviter)
	h.Write(invitee)
	n := binary.BigEndian.Uint64(h.Sum(nil)[:8]) % 100000000
	return fmt.Sprintf("%08d", n)
}
