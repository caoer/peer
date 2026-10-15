// Package room is a party's side of a v2 room: the room card (the contract's
// § Room card), the room state record `rm.<id>` every fleet host shares
// (plan decision 2 — the folded roster, own keys, cursor, seen ids, counters,
// membership version, the add setting; snapshot + Commit under CAS as v1's
// channel record), and the fold (plan decision 4 — rules 7 and 4 of
// results/group-design-chosen.md and the contract's sub-rules in one
// function). It reads verified records (Verified) and never the sealed bytes:
// internal/sealed opens a record, the room commands hand the fold what came
// out.
package room

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"

	"go.mau.fi/libsignal/ecc"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
)

// CardVersion is the room card format version.
const CardVersion = 1

// SigSize is the length of the identity-key signature a room card carries.
const SigSize = 64

// Card is a member's per-room public keys at an idx: the X25519 seal key the
// daily rotation replaces (rule 8) and the long-lived Ed25519 signing key. It
// travels as its JSON bytes followed by the 64-byte XEdDSA signature of the
// party's identity key over them (Signed / Verify), only inside channel
// messages and room records — never in the clear on the relay.
type Card struct {
	V      int       `json:"v"`
	Room   string    `json:"room"`
	Idx    uint16    `json:"idx"`
	Seal   string    `json:"seal"`
	Sign   string    `json:"sign"`
	Issued time.Time `json:"issued"`
}

// Errors a reader can match.
var (
	ErrSignature = errors.New("room card: identity-key signature does not verify")
	ErrMalformed = errors.New("room card: malformed")
)

var roomIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidID reports whether id is a room id: 32 lowercase hex characters.
func ValidID(id string) bool { return roomIDRE.MatchString(id) }

// NewCard builds the card for seal and sign at idx in room, issued at a time
// (kept to the millisecond, UTC, as v1 stamps messages).
func NewCard(room string, idx uint16, seal *ecdh.PublicKey, sign ed25519.PublicKey, issued time.Time) *Card {
	return &Card{
		V:      CardVersion,
		Room:   room,
		Idx:    idx,
		Seal:   base64.StdEncoding.EncodeToString(seal.Bytes()),
		Sign:   base64.StdEncoding.EncodeToString(sign),
		Issued: issued.UTC().Truncate(time.Millisecond),
	}
}

// smallOrder is libsodium's list of the X25519 u-coordinates of small order
// (0, 1, the two points of order 8, p-1, p, p+1), bit 255 clear. A seal key
// among them makes every sender's ECDH to it fail, so the room card refuses
// it at parse (contract § Room card).
var smallOrder = func() [][]byte {
	out := make([][]byte, 0, 7)
	for _, h := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		b, err := hex.DecodeString(h)
		if err != nil {
			panic(err)
		}
		out = append(out, b)
	}
	return out
}()

// SealKey is the card's X25519 seal public key; a small-order point refuses.
func (c *Card) SealKey() (*ecdh.PublicKey, error) {
	raw, err := key32(c.Seal, "seal")
	if err != nil {
		return nil, err
	}
	u := bytes.Clone(raw)
	u[31] &= 0x7f // X25519 ignores bit 255
	for _, p := range smallOrder {
		if bytes.Equal(u, p) {
			return nil, fmt.Errorf("%w: seal: small-order point", ErrMalformed)
		}
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// SignKey is the card's Ed25519 signing public key.
func (c *Card) SignKey() (ed25519.PublicKey, error) {
	raw, err := key32(c.Sign, "sign")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func key32(s, what string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, what, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: %s: %d bytes, want 32", ErrMalformed, what, len(b))
	}
	return b, nil
}

// Signed serializes c and signs the bytes with the party's identity key
// (XEdDSA, as v1 signs a signed prekey): the bytes a room card travels as.
func (c *Card) Signed(id *keys.Identity) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	sig := ecc.CalculateSignature(id.KeyPair.PrivateKey(), body)
	return append(body, sig[:]...), nil
}

// Verify checks signed — a card's JSON bytes followed by its signature —
// against the identity keys the party card lists and has not retired at
// `at`, then parses it. A room card whose signature fails is not parsed.
func Verify(signed []byte, pc *card.Card, at time.Time) (*Card, error) {
	if len(signed) <= SigSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(signed))
	}
	body := signed[:len(signed)-SigSize]
	var sig [SigSize]byte
	copy(sig[:], signed[len(signed)-SigSize:])
	ok := false
	for i := range pc.Keys {
		if pc.Keys[i].Retired(at) {
			continue
		}
		idk, err := pc.Keys[i].IdentityKey()
		if err != nil {
			continue
		}
		if ecc.VerifySignature(idk.PublicKey(), body, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, ErrSignature
	}
	return parse(body)
}

// cardKeys are the room card's JSON keys: exactly these, each once.
var cardKeys = []string{"v", "room", "idx", "seal", "sign", "issued"}

// parse decodes card bytes under the version rule and checks both keys.
func parse(body []byte) (*Card, error) {
	if err := exactKeys(body, cardKeys); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	var c Card
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: bytes after the JSON", ErrMalformed)
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Card) check() error {
	if c.V != CardVersion {
		return fmt.Errorf("%w: version %d, want %d", ErrMalformed, c.V, CardVersion)
	}
	if !ValidID(c.Room) {
		return fmt.Errorf("%w: room %q", ErrMalformed, c.Room)
	}
	if _, err := c.SealKey(); err != nil {
		return err
	}
	if _, err := c.SignKey(); err != nil {
		return err
	}
	if c.Issued.IsZero() {
		return fmt.Errorf("%w: no issued time", ErrMalformed)
	}
	return nil
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

// OwnKeys is the member's own per-room key pairs: the signing key that lives
// as long as the membership (rule 8) and the seal key the daily rotation
// replaces.
type OwnKeys struct {
	Sign ed25519.PrivateKey
	Seal *ecdh.PrivateKey
}

// GenerateKeys makes a fresh signing key and seal key.
func GenerateKeys() (*OwnKeys, error) {
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seal, err := GenerateSealKey()
	if err != nil {
		return nil, err
	}
	return &OwnKeys{Sign: sign, Seal: seal}, nil
}

// GenerateSealKey makes a fresh X25519 seal key, the daily rotation's input.
func GenerateSealKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

// Card is the unsigned room card for the keys at idx in room.
func (k *OwnKeys) Card(room string, idx uint16, issued time.Time) *Card {
	return NewCard(room, idx, k.Seal.PublicKey(), k.Sign.Public().(ed25519.PublicKey), issued)
}
