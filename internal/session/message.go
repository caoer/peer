package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/envelope"
)

// MessageVersion is the plaintext format version.
const MessageVersion = 1

// Message is the plaintext inside a Signal ciphertext (plan decision 7):
// everything the relay must not see — who, to whom, what kind, when, the
// body. From and To are party ids, or "<party id>/<agent id>".
type Message struct {
	V    int       `json:"v"`
	ID   string    `json:"id"`
	From string    `json:"from"`
	To   string    `json:"to"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
	Body []byte    `json:"body"`
	// Proof is the accept proof (design §4), base64url without padding:
	// present on the guest's first card message alone, not part of the
	// signed card bytes, ignored on every other message. CheckProof reads it.
	Proof string `json:"proof,omitempty"`
}

// The v1 message kinds (design §3.5). A vendor kind is "vnd.<party>.<name>".
const (
	KindText     = "text"
	KindTask     = "task"
	KindQuestion = "question"
	KindAnswer   = "answer"
	KindDoc      = "doc"
	KindFile     = "file"
	KindCard     = "card"
	KindAck      = "ack"
	// KindRoster is a room's membership notice, born from a roster or leave
	// record the fold accepted (deliver.KindRoster); it never travels on a
	// channel.
	KindRoster = deliver.KindRoster
)

// The v2 channel kinds of a room's join and handover (wire contract v2 §
// Kinds): the session's own business, like card, never delivered to an agent.
const (
	KindRoomInvite = "room-invite"
	KindRoomAccept = "room-accept"
	KindRoomSeat   = "room-seat"
	KindRoomJoin   = "room-join"
	KindRoomToken  = "room-token"
	KindRoomAdmin  = "room-admin"
)

var kinds = map[string]bool{
	KindText: true, KindTask: true, KindQuestion: true, KindAnswer: true,
	KindDoc: true, KindFile: true, KindCard: true, KindAck: true, KindRoster: true,
	KindRoomInvite: true, KindRoomAccept: true, KindRoomSeat: true, KindRoomJoin: true, KindRoomToken: true,
	KindRoomAdmin: true,
}

// RoomKind reports whether kind is one of a room's channel kinds.
func RoomKind(kind string) bool {
	switch kind {
	case KindRoomInvite, KindRoomAccept, KindRoomSeat, KindRoomJoin, KindRoomToken, KindRoomAdmin:
		return true
	}
	return false
}

// ErrKind is a message kind outside the v1 set and not a vendor kind.
var ErrKind = errors.New("session: unknown message kind")

// ValidKind reports whether kind is a v1 kind or a vendor kind. The vendor
// branch is the delivery record's grammar — vnd.<party id>.<name> — so a
// kind this admits is one the receiver can write on a frontmatter line.
func ValidKind(kind string) bool { return kinds[kind] || deliver.ValidVendorKind(kind) }

// NewMessage makes a message with a fresh id, stamped now.
func NewMessage(from, to, kind string, body []byte) (*Message, error) {
	if !ValidKind(kind) {
		return nil, fmt.Errorf("%w %q", ErrKind, kind)
	}
	var r [16]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	return &Message{
		V:    MessageVersion,
		ID:   base64.RawURLEncoding.EncodeToString(r[:]),
		From: from,
		To:   to,
		Kind: kind,
		At:   time.Now().UTC().Truncate(time.Millisecond),
		Body: body,
	}, nil
}

// Marshal is the plaintext handed to the cipher; a message whose plaintext
// could not fit a relay record refuses here.
func (m *Message) Marshal() ([]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) > envelope.MaxBody {
		return nil, envelope.ErrTooLarge
	}
	return b, nil
}

// UnmarshalMessage reads a decrypted plaintext.
func UnmarshalMessage(b []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("session: message: %w", err)
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Message) check() error {
	if m.V != MessageVersion {
		return fmt.Errorf("session: message version %d, want %d", m.V, MessageVersion)
	}
	if m.ID == "" {
		return errors.New("session: message has no id")
	}
	if !ValidKind(m.Kind) {
		return fmt.Errorf("%w %q", ErrKind, m.Kind)
	}
	return nil
}
