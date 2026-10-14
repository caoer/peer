// Package session runs the Signal session of one channel over the store's
// snapshots: X3DH from the peer's card and a one-time prekey, encrypt and
// decrypt with the libsignal Double Ratchet, the plaintext message format,
// the send order of plan decision 5, the accept proof and the 8-digit
// verification code.
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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	signal "go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/signalerror"
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
	// ErrUntrusted is a record built under an identity key the pinned card
	// does not list — what a peer's key rotation looks like from here
	// (design §3.2): its new card comes in a new session, which the old
	// pinned card cannot admit. The record is readable by the version that
	// applies a key change, so a caller parks it rather than consuming it.
	ErrUntrusted = errors.New("session: the record's identity key is not the pinned card's")
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
	if errors.Is(err, signalerror.ErrUntrustedIdentity) {
		return nil, fmt.Errorf("%w (%v)", ErrUntrusted, err)
	}
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

// PrekeyIdentity is the identity key a PreKey record carries in clear — the
// key the sender built its session under, what a key change looks like from
// outside the ciphertext. An envelope of another type, or one the library
// does not read, is an error.
func PrekeyIdentity(e envelope.Envelope) ([32]byte, error) {
	var out [32]byte
	if err := e.Check(); err != nil {
		return out, err
	}
	if e.Type != envelope.Prekey {
		return out, fmt.Errorf("%w: a %s record names no identity key", ErrNotMessage, e.Type)
	}
	ser := keys.Serializer
	err := envelope.Safe(func() error {
		m, err := protocol.NewPreKeySignalMessageFromBytes(e.Body, ser.PreKeySignalMessage, ser.SignalMessage)
		if err != nil {
			return err
		}
		out = m.IdentityKey().PublicKey().PublicKey()
		return nil
	})
	return out, err
}

// CheckIdentity is the first-contact check of design §3.4: the identity key
// the session was built with must be one the peer's card lists and has not
// retired — a key the card voids is no longer the party's (§3.2).  Run it on
// the card that arrived in-session, before pinning it.
func (s *Session) CheckIdentity(c *card.Card) error {
	got, ok := s.Channel.RemoteIdentity(Addr)
	if !ok {
		return fmt.Errorf("%w: no session identity", ErrIdentity)
	}
	now := time.Now()
	for i := range c.Keys {
		if c.Keys[i].Retired(now) {
			continue
		}
		raw, err := keys.ParseCurve(c.Keys[i].Identity)
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
const codeInfo = "peer verification code v2"

// Code is the channel's 8-digit verification code (design §4): the channel
// id, both root keys (inviter first) and the invite link's secret, hashed
// under a fixed label — a new invite is a new code, and nothing public
// derives it. The invitee prints it after accept and reads it back, with its
// party id, over the chat the link came on; the inviter types it at confirm.
// Every input is raw bytes: channelID as its 32 hex characters, the roots as
// 32-byte Ed25519 keys, secret as its 16 decoded bytes.
func Code(channelID string, inviter, invitee ed25519.PublicKey, secret []byte) string {
	h := sha256.New()
	h.Write([]byte(codeInfo))
	h.Write([]byte(channelID))
	h.Write(inviter)
	h.Write(invitee)
	h.Write(secret)
	n := binary.BigEndian.Uint64(h.Sum(nil)[:8]) % 100000000
	return fmt.Sprintf("%08d", n)
}

// CodeMatches compares the typed code with the channel's in constant time.
func CodeMatches(typed, want string) bool {
	return subtle.ConstantTimeCompare([]byte(typed), []byte(want)) == 1
}

// proofInfo labels the accept proof; a new value is a new proof.
const proofInfo = "peer accept proof v1"

// ProofSize is the accept proof's length in bytes.
const ProofSize = sha256.Size

// ErrProof is a first card message whose accept proof is absent or wrong:
// whoever joined does not hold the link's secret.
var ErrProof = errors.New("session: the accept proof does not verify")

// Proof is the guest's accept proof (design §4): HMAC-SHA256 under the link
// secret over the channel id, both roots and both session identity keys, so
// a party that joined with the token alone — the relay operator — cannot
// present it. The identity keys are the Curve25519 points the session was
// built with: on the host its own and Channel.RemoteIdentity; on the guest
// card #0's current key and its own. Inputs are raw bytes as in Code.
func Proof(secret []byte, channelID string, inviterRoot, inviteeRoot ed25519.PublicKey, inviterIdentity, inviteeIdentity [32]byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(proofInfo))
	mac.Write([]byte(channelID))
	mac.Write(inviterRoot)
	mac.Write(inviteeRoot)
	mac.Write(inviterIdentity[:])
	mac.Write(inviteeIdentity[:])
	return mac.Sum(nil)
}

// EncodeProof is the proof as the message carries it: base64url, no padding.
func EncodeProof(proof []byte) string { return base64.RawURLEncoding.EncodeToString(proof) }

// CheckProof verifies the proof m carries against want. A proof that is
// absent, does not decode strictly, has another length or differs is
// ErrProof; the comparison is constant-time.
func CheckProof(m *Message, want []byte) error {
	got, err := base64.RawURLEncoding.Strict().DecodeString(m.Proof)
	if err != nil || len(got) != ProofSize || !hmac.Equal(got, want) {
		return ErrProof
	}
	return nil
}
