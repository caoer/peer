// Package envelope is the relay record: a type byte and opaque bytes
// (plan decision 7). A record is either the inviter's plaintext card
// (detached Ed25519 signature + card bytes) or a Signal ciphertext — a
// PreKeySignalMessage or a normal SignalMessage, which the library's own
// wire bytes do not tell apart.
//
// The relay is untrusted and go.mau.fi/libsignal panics on some malformed
// input (ecc.DecodePoint indexes an empty slice) and accepts short or
// low-order keys. Check validates a record before any library call; Safe
// turns a panic that still escapes into an error.
package envelope

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Type is the record's type byte.
type Type byte

const (
	// Card is the plaintext, root-signed card (envelope #0).
	Card Type = 1
	// Prekey is a Signal PreKeySignalMessage (Signal type 3).
	Prekey Type = 2
	// Msg is a Signal SignalMessage (Signal type 2).
	Msg Type = 3
)

// MaxBody is the cap on a record's decoded bytes (1 MiB).
const MaxBody = 1 << 20

// SigSize is the length of the card's detached signature.
const SigSize = ed25519.SignatureSize

var (
	ErrType      = errors.New("envelope: unknown type")
	ErrEmpty     = errors.New("envelope: empty body")
	ErrTooLarge  = errors.New("envelope: body over 1 MiB")
	ErrBase64    = errors.New("envelope: body is not standard base64")
	ErrMalformed = errors.New("envelope: malformed")
	ErrPanic     = errors.New("envelope: library panic")
)

var typeNames = map[Type]string{Card: "card", Prekey: "prekey", Msg: "msg"}

// String is the type's wire name: "card", "prekey" or "msg".
func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("type(%d)", byte(t))
}

// ParseType reads a wire name.
func ParseType(s string) (Type, error) {
	for t, n := range typeNames {
		if n == s {
			return t, nil
		}
	}
	return 0, fmt.Errorf("%w %q", ErrType, s)
}

// Envelope is one relay record.
type Envelope struct {
	Type Type
	Body []byte
}

// Check validates the envelope against its type; a nil result means the
// bytes are safe to hand to the card verifier or to libsignal's
// deserializers.
func (e Envelope) Check() error {
	if _, ok := typeNames[e.Type]; !ok {
		return fmt.Errorf("%w %d", ErrType, byte(e.Type))
	}
	if len(e.Body) == 0 {
		return ErrEmpty
	}
	if len(e.Body) > MaxBody {
		return ErrTooLarge
	}
	switch e.Type {
	case Card:
		_, _, err := UnpackCard(e.Body)
		return err
	case Prekey:
		return CheckPreKeyMessage(e.Body)
	default:
		return CheckSignalMessage(e.Body)
	}
}

// Wire returns the contract's JSON fields: the type name and the body in
// standard padded base64.
func (e Envelope) Wire() (typ, body string) {
	return e.Type.String(), base64.StdEncoding.EncodeToString(e.Body)
}

// FromWire decodes the contract's JSON fields and checks the result.
func FromWire(typ, body string) (Envelope, error) {
	t, err := ParseType(typ)
	if err != nil {
		return Envelope{}, err
	}
	if base64.StdEncoding.DecodedLen(len(body)) > MaxBody+3 {
		return Envelope{}, ErrTooLarge
	}
	// The decoder skips CR and LF even in strict mode; the contract's form has none.
	if strings.ContainsAny(body, "\r\n") {
		return Envelope{}, fmt.Errorf("%w: line break", ErrBase64)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(body)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrBase64, err)
	}
	e := Envelope{Type: t, Body: b}
	if err := e.Check(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// MarshalBinary packs the envelope as its type byte followed by the body,
// the form for local storage (an outbox entry).
func (e Envelope) MarshalBinary() ([]byte, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(e.Body))
	out = append(out, byte(e.Type))
	return append(out, e.Body...), nil
}

// UnmarshalBinary reverses MarshalBinary and checks the result.
func (e *Envelope) UnmarshalBinary(b []byte) error {
	if len(b) < 1 {
		return ErrEmpty
	}
	v := Envelope{Type: Type(b[0]), Body: append([]byte(nil), b[1:]...)}
	if err := v.Check(); err != nil {
		return err
	}
	*e = v
	return nil
}

// PackCard builds a Card body: the detached signature, then the card bytes.
func PackCard(card, sig []byte) (Envelope, error) {
	if len(sig) != SigSize {
		return Envelope{}, fmt.Errorf("%w: signature is %d bytes, want %d", ErrMalformed, len(sig), SigSize)
	}
	if len(card) == 0 {
		return Envelope{}, ErrEmpty
	}
	body := make([]byte, 0, SigSize+len(card))
	body = append(append(body, sig...), card...)
	e := Envelope{Type: Card, Body: body}
	if len(body) > MaxBody {
		return Envelope{}, ErrTooLarge
	}
	return e, nil
}

// UnpackCard splits a Card body into card bytes and signature. It does not
// verify the signature; the card package does, before parsing the bytes.
func UnpackCard(body []byte) (card, sig []byte, err error) {
	if len(body) <= SigSize {
		return nil, nil, fmt.Errorf("%w: card body is %d bytes", ErrMalformed, len(body))
	}
	return body[SigSize:], body[:SigSize], nil
}

// Safe runs fn and returns a panic inside it as an error wrapping ErrPanic.
// Wrap every libsignal deserialize and decrypt call that sees relay bytes.
func Safe(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", ErrPanic, r)
		}
	}()
	return fn()
}
