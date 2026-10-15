// Package sealed is the room record's bytes: one message locked under a
// fresh key, that key sealed to every recipient, a signed header that
// commits to the key, and the writer's counter in the header.
//
// The wire form is header ‖ stanzas ‖ body ‖ signature, the first three
// length-prefixed (uint32 big-endian):
//
//   - header: JSON {"v":1,"room":"<32 hex>","idx":k,"ctr":n,"kh":"<base64, 32 bytes>","at":"<RFC 3339 UTC ms>"}
//   - stanzas: count (uint16) ‖ [idx (uint16) ‖ len (uint16) ‖ enc‖ct]*, in idx order;
//     enc‖ct is HPKE single-shot (DHKEM X25519, HKDF-SHA256, AES-256-GCM) of the
//     32-byte body key K to the recipient's seal key, info = "peer room seal v1" ‖
//     room ‖ idx ‖ SHA-256(header)
//   - body: AES-256-GCM under K, nonce twelve zero bytes, AAD = the header bytes
//   - signature: Ed25519 over the length-prefixed header ‖ stanzas ‖ body by the
//     writer's room signing key
//
// kh = SHA-256("peer room key commit v1" ‖ K): the signature commits to the
// body key, so one signed record cannot open to two messages for two members.
// ctr is the writer's own count of records in the room, +1 each.
//
// A receiver runs Parse, Verify under the roster's signing key for the
// header's idx, CheckCtr against the writer's last counter, then Open with its
// own idx and seal keys (the current one first, then each retired one).
package sealed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// Version is the header's v.
const Version = 1

// MaxRecord is the relay's cap on a record's decoded bytes (1 MiB).
const MaxRecord = 1 << 20

// StanzaSize is enc ‖ ct for a 32-byte key under DHKEM(X25519) + AES-256-GCM.
const StanzaSize = 32 + 32 + 16

// AtLayout is the header's at: RFC 3339, UTC, milliseconds.
const AtLayout = "2006-01-02T15:04:05.000Z"

const (
	keySize    = 32
	sigSize    = ed25519.SignatureSize
	stanzaHead = 2 + 2 // idx ‖ len
	infoPrefix = "peer room seal v1"
	khPrefix   = "peer room key commit v1"
)

var (
	ErrMalformed  = errors.New("sealed: malformed")
	ErrTooLarge   = errors.New("sealed: record over 1 MiB")
	ErrSignature  = errors.New("sealed: bad signature")
	ErrUnverified = errors.New("sealed: record not verified")
	ErrNoStanza   = errors.New("sealed: no stanza for this idx")
	ErrStanza     = errors.New("sealed: stanza opens under no key")
	ErrKeyCommit  = errors.New("sealed: key commitment mismatch")
	ErrBody       = errors.New("sealed: body does not open")
	ErrCtrGap     = errors.New("sealed: counter gap")
	ErrCtrBack    = errors.New("sealed: counter step back")
)

// Header is the signed header. Seal fills KH; At is written as UTC
// milliseconds.
type Header struct {
	Room string // 32 lowercase hex
	Idx  uint16 // the writer's index
	Ctr  uint64 // the writer's count of records in this room
	KH   [32]byte
	At   time.Time
}

type wireHeader struct {
	V    int     `json:"v"`
	Room string  `json:"room"`
	Idx  *uint16 `json:"idx"`
	Ctr  *uint64 `json:"ctr"`
	KH   string  `json:"kh"`
	At   string  `json:"at"`
}

// Recipient is one member's X25519 seal key at its index.
type Recipient struct {
	Idx uint16
	Key *ecdh.PublicKey
}

// KeyCommit is kh: SHA-256("peer room key commit v1" ‖ k).
func KeyCommit(k []byte) [32]byte {
	return sha256.Sum256(append([]byte(khPrefix), k...))
}

// CheckCtr compares a verified record's ctr with the writer's last one. A
// gap or a step back is reported for the receiver to log and read on.
func CheckCtr(last, got uint64) error {
	switch {
	case got == last+1:
		return nil
	case got > last+1:
		return fmt.Errorf("%w: %d after %d, %d missing", ErrCtrGap, got, last, got-last-1)
	default:
		return fmt.Errorf("%w: %d after %d", ErrCtrBack, got, last)
	}
}

// Seal locks msg under a fresh key sealed to each recipient and signs the
// record with the writer's room signing key. Recipients may come in any
// order; two at one idx refuse.
func Seal(h Header, msg []byte, to []Recipient, signer ed25519.PrivateKey) ([]byte, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signing key is %d bytes, want %d", ErrMalformed, len(signer), ed25519.PrivateKeySize)
	}
	if len(to) == 0 {
		return nil, fmt.Errorf("%w: no recipients", ErrMalformed)
	}
	if len(msg) > MaxRecord {
		return nil, ErrTooLarge
	}
	to = slices.Clone(to)
	slices.SortFunc(to, func(a, b Recipient) int { return int(a.Idx) - int(b.Idx) })
	for i, r := range to {
		if i > 0 && to[i-1].Idx == r.Idx {
			return nil, fmt.Errorf("%w: two recipients at idx %d", ErrMalformed, r.Idx)
		}
		if r.Key == nil || r.Key.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: recipient %d: seal key is not X25519", ErrMalformed, r.Idx)
		}
	}

	k := make([]byte, keySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	h.KH = KeyCommit(k)
	hdr, err := encodeHeader(h)
	if err != nil {
		return nil, err
	}
	hh := sha256.Sum256(hdr)

	stanzas := binary.BigEndian.AppendUint16(nil, uint16(len(to)))
	for _, r := range to {
		st, err := wrap(h.Room, r.Idx, hh, r.Key, k)
		if err != nil {
			return nil, err
		}
		stanzas = binary.BigEndian.AppendUint16(stanzas, r.Idx)
		stanzas = binary.BigEndian.AppendUint16(stanzas, uint16(len(st)))
		stanzas = append(stanzas, st...)
	}

	body, err := sealBody(k, hdr, msg)
	if err != nil {
		return nil, err
	}
	return assemble(hdr, stanzas, body, signer)
}

// Record is a parsed sealed record.
type Record struct {
	Header Header

	hdr, body, signed, sig []byte
	stanzas                []stanza
	verified               bool
}

type stanza struct {
	idx   uint16
	encct []byte
}

// Parse splits and checks a record's framing and header. It verifies
// nothing: a parsed record is bytes of the right shape.
func Parse(b []byte) (*Record, error) {
	if len(b) > MaxRecord {
		return nil, ErrTooLarge
	}
	rest := b
	var segs [3][]byte
	for i := range segs {
		if len(rest) < 4 {
			return nil, fmt.Errorf("%w: short at segment %d", ErrMalformed, i)
		}
		n := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(n) > uint64(len(rest)) {
			return nil, fmt.Errorf("%w: segment %d claims %d bytes, %d left", ErrMalformed, i, n, len(rest))
		}
		segs[i], rest = rest[:n], rest[n:]
	}
	if len(rest) != sigSize {
		return nil, fmt.Errorf("%w: %d bytes after the body, want a %d-byte signature", ErrMalformed, len(rest), sigSize)
	}
	hdr, stanzaBytes, body, sig := segs[0], segs[1], segs[2], rest

	h, err := parseHeader(hdr)
	if err != nil {
		return nil, err
	}
	stanzas, err := parseStanzas(stanzaBytes)
	if err != nil {
		return nil, err
	}
	if len(body) < 16 {
		return nil, fmt.Errorf("%w: body is %d bytes, under the 16-byte tag", ErrMalformed, len(body))
	}
	return &Record{
		Header:  h,
		hdr:     hdr,
		body:    body,
		signed:  b[:len(b)-sigSize],
		sig:     sig,
		stanzas: stanzas,
	}, nil
}

// Recipients lists the stanza indexes in wire order.
func (r *Record) Recipients() []uint16 {
	out := make([]uint16, len(r.stanzas))
	for i, s := range r.stanzas {
		out[i] = s.idx
	}
	return out
}

// Verify checks the signature under the writer's room signing key — the
// folded roster's key for Header.Idx.
func (r *Record) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signing key is %d bytes, want %d", ErrSignature, len(pub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(pub, r.signed, r.sig) {
		return ErrSignature
	}
	r.verified = true
	return nil
}

// Open finds idx's stanza, unwraps the body key with each seal key in turn
// (the current one first, then each retired one), checks it against the
// header's kh — a mismatch names the writer — and opens the body. It
// refuses a record Verify has not passed.
func (r *Record) Open(idx uint16, keys ...*ecdh.PrivateKey) ([]byte, error) {
	if !r.verified {
		return nil, ErrUnverified
	}
	i := slices.IndexFunc(r.stanzas, func(s stanza) bool { return s.idx == idx })
	if i < 0 {
		return nil, fmt.Errorf("%w: idx %d", ErrNoStanza, idx)
	}
	hh := sha256.Sum256(r.hdr)
	info := sealInfo(r.Header.Room, idx, hh)
	var k []byte
	for _, key := range keys {
		if key == nil {
			continue
		}
		pk, err := hpke.NewDHKEMPrivateKey(key)
		if err != nil {
			continue
		}
		k, err = hpke.Open(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, r.stanzas[i].encct)
		if err == nil && len(k) == keySize {
			break
		}
		k = nil
	}
	if k == nil {
		return nil, fmt.Errorf("%w: idx %d, %d keys tried", ErrStanza, idx, len(keys))
	}
	if KeyCommit(k) != r.Header.KH {
		return nil, fmt.Errorf("%w: writer idx %d", ErrKeyCommit, r.Header.Idx)
	}
	aead, err := gcm(k)
	if err != nil {
		return nil, err
	}
	msg, err := aead.Open(nil, make([]byte, aead.NonceSize()), r.body, r.hdr)
	if err != nil {
		return nil, fmt.Errorf("%w: writer idx %d", ErrBody, r.Header.Idx)
	}
	return msg, nil
}

// --- pieces ---

func checkRoom(room string) error {
	if len(room) != 32 {
		return fmt.Errorf("%w: room id is %d chars, want 32 hex", ErrMalformed, len(room))
	}
	for _, c := range []byte(room) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: room id is not lowercase hex", ErrMalformed)
		}
	}
	return nil
}

func encodeHeader(h Header) ([]byte, error) {
	if err := checkRoom(h.Room); err != nil {
		return nil, err
	}
	idx, ctr := h.Idx, h.Ctr
	return json.Marshal(wireHeader{
		V:    Version,
		Room: h.Room,
		Idx:  &idx,
		Ctr:  &ctr,
		KH:   base64.StdEncoding.EncodeToString(h.KH[:]),
		At:   h.At.UTC().Format(AtLayout),
	})
}

// headerKeys are the header's JSON keys: exactly these, each once.
var headerKeys = []string{"v", "room", "idx", "ctr", "kh", "at"}

func parseHeader(b []byte) (Header, error) {
	if err := exactKeys(b, headerKeys); err != nil {
		return Header{}, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	var w wireHeader
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return Header{}, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Header{}, fmt.Errorf("%w: header: bytes after the JSON", ErrMalformed)
	}
	if w.V != Version {
		return Header{}, fmt.Errorf("%w: header v %d, want %d", ErrMalformed, w.V, Version)
	}
	if err := checkRoom(w.Room); err != nil {
		return Header{}, err
	}
	if w.Idx == nil || w.Ctr == nil {
		return Header{}, fmt.Errorf("%w: header without idx or ctr", ErrMalformed)
	}
	kh, err := base64.StdEncoding.Strict().DecodeString(w.KH)
	if err != nil {
		return Header{}, fmt.Errorf("%w: header kh: %v", ErrMalformed, err)
	}
	if len(kh) != keySize {
		return Header{}, fmt.Errorf("%w: header kh is %d bytes, want %d", ErrMalformed, len(kh), keySize)
	}
	at, err := time.Parse(time.RFC3339, w.At)
	if err != nil {
		return Header{}, fmt.Errorf("%w: header at: %v", ErrMalformed, err)
	}
	h := Header{Room: w.Room, Idx: *w.Idx, Ctr: *w.Ctr, At: at}
	copy(h.KH[:], kh)
	return h, nil
}

// exactKeys walks the top level of a JSON object once and refuses a key
// outside want (matched case-sensitively, unlike encoding/json's field
// match), a repeated key, or a missing one. Bytes that are not an object are
// left to the decoder to name.
func exactKeys(b []byte, want []string) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	seen := make(map[string]bool, len(want))
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil
		}
		k, _ := t.(string)
		switch {
		case !slices.Contains(want, k):
			return fmt.Errorf("unknown key %q", k)
		case seen[k]:
			return fmt.Errorf("repeated key %q", k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil
		}
	}
	for _, k := range want {
		if !seen[k] {
			return fmt.Errorf("missing key %q", k)
		}
	}
	return nil
}

func parseStanzas(b []byte) ([]stanza, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("%w: stanzas segment is %d bytes", ErrMalformed, len(b))
	}
	count := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if want := count * (stanzaHead + StanzaSize); len(b) != want {
		return nil, fmt.Errorf("%w: %d stanzas need %d bytes, segment carries %d", ErrMalformed, count, want, len(b))
	}
	out := make([]stanza, 0, count)
	for i := 0; i < count; i++ {
		idx := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n != StanzaSize {
			return nil, fmt.Errorf("%w: stanza %d is %d bytes, want %d", ErrMalformed, i, n, StanzaSize)
		}
		if i > 0 && idx <= out[i-1].idx {
			return nil, fmt.Errorf("%w: stanza idx %d after %d, want ascending", ErrMalformed, idx, out[i-1].idx)
		}
		out = append(out, stanza{idx: idx, encct: b[stanzaHead : stanzaHead+StanzaSize]})
		b = b[stanzaHead+StanzaSize:]
	}
	return out, nil
}

func sealInfo(room string, idx uint16, hh [32]byte) []byte {
	info := make([]byte, 0, len(infoPrefix)+32+2+32)
	info = append(info, infoPrefix...)
	info = append(info, room...)
	info = binary.BigEndian.AppendUint16(info, idx)
	return append(info, hh[:]...)
}

// wrap seals k to one recipient: enc ‖ ct, StanzaSize bytes.
func wrap(room string, idx uint16, hh [32]byte, pub *ecdh.PublicKey, k []byte) ([]byte, error) {
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("recipient %d: %w", idx, err)
	}
	st, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), sealInfo(room, idx, hh), k)
	if err != nil {
		return nil, fmt.Errorf("recipient %d: %w", idx, err)
	}
	if len(st) != StanzaSize {
		return nil, fmt.Errorf("recipient %d: stanza is %d bytes, want %d", idx, len(st), StanzaSize)
	}
	return st, nil
}

func gcm(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealBody locks msg under k with the header as AAD; one key seals one
// body, so the nonce is zero.
func sealBody(k, hdr, msg []byte) ([]byte, error) {
	aead, err := gcm(k)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, make([]byte, aead.NonceSize()), msg, hdr), nil
}

// assemble length-prefixes the three segments, signs them and appends the
// signature.
func assemble(hdr, stanzas, body []byte, signer ed25519.PrivateKey) ([]byte, error) {
	out := make([]byte, 0, 12+len(hdr)+len(stanzas)+len(body)+sigSize)
	for _, seg := range [][]byte{hdr, stanzas, body} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(seg)))
		out = append(out, seg...)
	}
	out = append(out, ed25519.Sign(signer, out)...)
	if len(out) > MaxRecord {
		return nil, ErrTooLarge
	}
	return out, nil
}
