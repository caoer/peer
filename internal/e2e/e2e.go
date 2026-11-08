// Package e2e implements the Peer Protocol message encryption extension,
// suite peer-e2e-v1: a message body sealed to one or more long-term X25519
// keys with RFC 9180 HPKE, so that only the holder of a listed secret key can
// read it. Seats, relays and hosts carry the envelope and see ciphertext.
//
// The wire format is fixed in docs/protocol.md; the browser renderer
// docs/timeline/index.html implements the same bytes with crypto.subtle.
package e2e

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// Suite is the suite id of this implementation.
	Suite = "peer-e2e-v1"
	// Version is the envelope's "e2e" value and the card's details.readers "v".
	Version = 1

	// PublicPrefix and SecretPrefix tag the text form of a key.
	PublicPrefix = "x25519:"
	SecretPrefix = "x25519-secret:"

	// label is the HPKE info prefix and the body's AAD.
	label = "peer e2e v1"

	keySize = 32 // X25519 key, the HPKE enc and the content key K
	ctSize  = keySize + 16
)

var (
	// ErrMalformed reports an envelope that is not a well-formed peer-e2e-v1
	// envelope.
	ErrMalformed = errors.New("malformed encrypted record")
	// ErrNotRecipient reports an envelope with no stanza for this key.
	ErrNotRecipient = errors.New("encrypted to other keys")
	// ErrDecrypt reports a stanza or body that failed authentication.
	ErrDecrypt = errors.New("does not open with this key")
)

var (
	suiteRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	keyB64  = base64.RawURLEncoding.Strict()
	wireB64 = base64.StdEncoding.Strict()
	kem     = hpke.DHKEM(ecdh.X25519())
	kdf     = hpke.HKDFSHA256()
	aead    = hpke.AES256GCM()
)

// stanza carries the content key to one recipient.
type stanza struct {
	Key string `json:"key"`
	Enc string `json:"enc"`
	CT  string `json:"ct"`
}

// envelope is the message body; the field order is the wire's key order.
type envelope struct {
	E2E   int      `json:"e2e"`
	Suite string   `json:"suite"`
	To    []stanza `json:"to"`
	Body  string   `json:"body"`
}

// DetailsMember is the member of a card's details that holds its Details.
const DetailsMember = "readers"

// Details is the card's details.readers object: the keys a party receives on.
type Details struct {
	V     int      `json:"v"`
	Suite string   `json:"suite"`
	Keys  []string `json:"keys"`
}

// GenerateKey makes a new key pair and returns its text forms.
func GenerateKey() (pub, secret string, err error) {
	k, err := kem.GenerateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	raw, err := k.Bytes()
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	return formatPublic(k.PublicKey()), SecretPrefix + keyB64.EncodeToString(raw), nil
}

func formatPublic(k hpke.PublicKey) string {
	return PublicPrefix + keyB64.EncodeToString(k.Bytes())
}

// ParsePublic decodes a public key string x25519:<43 base64url>.
func ParsePublic(s string) (hpke.PublicKey, error) {
	raw, err := decodeKey(s, PublicPrefix)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	k, err := kem.NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return k, nil
}

// ParseSecret decodes a secret key string x25519-secret:<43 base64url>. Its
// errors never quote the input.
func ParseSecret(s string) (hpke.PrivateKey, error) {
	raw, err := decodeKey(s, SecretPrefix)
	if err != nil {
		return nil, fmt.Errorf("secret key: %w", err)
	}
	k, err := kem.NewPrivateKey(raw)
	if err != nil {
		return nil, errors.New("secret key: not an X25519 key")
	}
	return k, nil
}

func decodeKey(s, prefix string) ([]byte, error) {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return nil, fmt.Errorf("missing %q prefix", prefix)
	}
	raw, err := keyB64.DecodeString(rest)
	if err != nil {
		return nil, errors.New("not base64url without padding")
	}
	if len(raw) != keySize {
		return nil, fmt.Errorf("%d bytes, want %d", len(raw), keySize)
	}
	return raw, nil
}

// Seal encrypts plain to every key in pubs and returns the envelope, which is
// the message body. A fresh content key encrypts plain, so the all-zero body
// nonce is used once per key.
func Seal(plain []byte, pubs []string) ([]byte, error) {
	if len(pubs) == 0 {
		return nil, errors.New("seal: no recipient keys")
	}
	keys := make([]hpke.PublicKey, len(pubs))
	for i, p := range pubs {
		k, err := ParsePublic(p)
		if err != nil {
			return nil, fmt.Errorf("seal: %w", err)
		}
		keys[i] = k
	}

	cek := make([]byte, keySize)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	gcm, err := bodyAEAD(cek)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}

	env := envelope{
		E2E:   Version,
		Suite: Suite,
		To:    make([]stanza, len(keys)),
		Body:  wireB64.EncodeToString(gcm.Seal(nil, make([]byte, gcm.NonceSize()), plain, []byte(label))),
	}
	for i, k := range keys {
		sealed, err := hpke.Seal(k, kdf, aead, info(k), cek)
		if err != nil {
			return nil, fmt.Errorf("seal to %s: %w", pubs[i], err)
		}
		if len(sealed) != keySize+ctSize {
			return nil, fmt.Errorf("seal to %s: %d bytes of HPKE output, want %d", pubs[i], len(sealed), keySize+ctSize)
		}
		env.To[i] = stanza{
			Key: formatPublic(k),
			Enc: wireB64.EncodeToString(sealed[:keySize]),
			CT:  wireB64.EncodeToString(sealed[keySize:]),
		}
	}
	return json.Marshal(env)
}

// Open decrypts an envelope with secret. A failure wraps ErrMalformed,
// ErrNotRecipient or ErrDecrypt.
func Open(env []byte, secret string) ([]byte, error) {
	k, err := ParseSecret(secret)
	if err != nil {
		return nil, err
	}
	suite, ok := Detect(env)
	if !ok {
		return nil, fmt.Errorf("%w: not an e2e envelope", ErrMalformed)
	}
	if suite != Suite {
		return nil, fmt.Errorf("%w: unsupported suite %q", ErrMalformed, suite)
	}
	var e envelope
	if err := json.Unmarshal(env, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	self := formatPublic(k.PublicKey())
	var st *stanza
	for i := range e.To {
		if e.To[i].Key == self {
			st = &e.To[i]
			break
		}
	}
	if st == nil {
		return nil, fmt.Errorf("%w: no stanza for %s", ErrNotRecipient, self)
	}
	enc, err := decodeWire(st.Enc, keySize)
	if err != nil {
		return nil, fmt.Errorf("%w: enc: %v", ErrMalformed, err)
	}
	ct, err := decodeWire(st.CT, ctSize)
	if err != nil {
		return nil, fmt.Errorf("%w: ct: %v", ErrMalformed, err)
	}
	body, err := wireB64.DecodeString(e.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: body: not standard base64", ErrMalformed)
	}

	cek, err := hpke.Open(k, kdf, aead, info(k.PublicKey()), append(enc, ct...))
	if err != nil {
		return nil, ErrDecrypt
	}
	gcm, err := bodyAEAD(cek)
	if err != nil {
		return nil, ErrDecrypt
	}
	plain, err := gcm.Open(nil, make([]byte, gcm.NonceSize()), body, []byte(label))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// Detect reports whether a message body is an e2e envelope and names its
// suite: after leading JSON whitespace it starts {"e2e":, parses as an object
// with "e2e" equal to 1 and "suite" matching [A-Za-z0-9._-]{1,64}. Anything
// else is plain text.
//
// Members are matched exactly, unlike encoding/json's struct decoding, so Go
// and a JSON.parse reader classify the same bytes the same way.
func Detect(body []byte) (suite string, ok bool) {
	b := bytes.TrimLeft(body, " \t\r\n")
	if !bytes.HasPrefix(b, []byte(`{"e2e":`)) {
		return "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return "", false
	}
	var v float64
	if err := json.Unmarshal(fields["e2e"], &v); err != nil || v != Version {
		return "", false
	}
	if err := json.Unmarshal(fields["suite"], &suite); err != nil || !suiteRE.MatchString(suite) {
		return "", false
	}
	return suite, true
}

// ParseDetails reads the readers member of a card's details. It returns nil and
// no error when the card names no e2e keys, and an error when the member is
// present and not a usable v1 key list.
func ParseDetails(details json.RawMessage) (*Details, error) {
	if len(details) == 0 {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(details, &fields); err != nil {
		return nil, fmt.Errorf("card details: %w", err)
	}
	raw, ok := fields[DetailsMember]
	if !ok {
		return nil, nil
	}
	var d Details
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("card details.readers: %w", err)
	}
	if d.V != Version {
		return nil, fmt.Errorf("card details.readers: version %d, want %d", d.V, Version)
	}
	if d.Suite != Suite {
		return nil, fmt.Errorf("card details.readers: suite %q, want %q", d.Suite, Suite)
	}
	if len(d.Keys) == 0 {
		return nil, errors.New("card details.readers: no keys")
	}
	for _, k := range d.Keys {
		if _, err := ParsePublic(k); err != nil {
			return nil, fmt.Errorf("card details.readers: %w", err)
		}
	}
	return &d, nil
}

// info is the HPKE info: the label, then the recipient's raw public key.
func info(k hpke.PublicKey) []byte {
	return append([]byte(label), k.Bytes()...)
}

func bodyAEAD(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func decodeWire(s string, size int) ([]byte, error) {
	b, err := wireB64.DecodeString(s)
	if err != nil {
		return nil, errors.New("not standard base64")
	}
	if len(b) != size {
		return nil, fmt.Errorf("%d bytes, want %d", len(b), size)
	}
	return b, nil
}
