// Package card builds, signs and verifies a party's card.
//
// A card travels and is stored as its exact bytes plus a detached Ed25519
// signature by the party's root key. The signature is checked over the raw
// bytes before any parsing, so no JSON canonicalization is needed: a card
// whose signature fails is never parsed.
//
// Unknown fields follow SSH certificates: a card names in its top-level
// "critical" list the fields a reader must understand; a critical field this
// reader does not know refuses the whole card, and any other unknown field
// is ignored. The rule applies to top-level fields.
package card

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"

	"github.com/caoer/peer/internal/keys"
)

// Version is the card format version this reader understands.
const Version = 1

// Card is a party's self-signed description: its root key, its operational
// keys, its agents and its relays.
type Card struct {
	V      int       `json:"v"`
	Party  string    `json:"party"`
	Keys   []Key     `json:"keys"`
	Agents []Agent   `json:"agents"`
	Relays []string  `json:"relays"`
	Issued time.Time `json:"issued"`
	// Details is the in-channel extension (receiver types, model, policy);
	// absent from the card placed as envelope #0.
	Details json.RawMessage `json:"details,omitempty"`
	// Critical names the top-level fields a reader must understand.
	Critical []string `json:"critical,omitempty"`
}

// Key is one operational key bundle; the libsignal device id is always keys.DeviceID.
type Key struct {
	Identity       string       `json:"identity"`
	RegistrationID uint32       `json:"registrationId"`
	SignedPrekey   SignedPrekey `json:"signedPrekey"`
	From           time.Time    `json:"from"`
	Until          *time.Time   `json:"until"`
}

// SignedPrekey is the public half of a signed prekey and the identity key's
// XEdDSA signature over its serialized public key.
type SignedPrekey struct {
	ID  uint32 `json:"id"`
	Pub string `json:"pub"`
	Sig []byte `json:"sig"`
}

// Agent is one agent of the party and the message kinds it accepts.
type Agent struct {
	ID      string   `json:"id"`
	Accepts []string `json:"accepts"`
}

// known is every top-level field this reader understands.
var known = map[string]bool{
	"v": true, "party": true, "keys": true, "agents": true, "relays": true,
	"issued": true, "details": true, "critical": true,
}

// Signed is a card as it travels: the exact bytes and the root's detached signature.
type Signed struct {
	Body []byte
	Sig  []byte
}

// Errors a reader can match.
var (
	ErrSignature       = errors.New("card: root signature does not verify")
	ErrCriticalUnknown = errors.New("card: unknown critical field")
	ErrParty           = errors.New("card: party is not the signing root")
)

// New builds a card for a party from its identity and party keys.
func New(id *keys.Identity, pk *keys.PartyKeys, agents []Agent, relays []string, issued time.Time) *Card {
	spk := pk.SignedPrekey
	return &Card{
		V:     Version,
		Party: keys.PartyID(id.Party),
		Keys: []Key{{
			Identity:       keys.CurveText(id.PublicKey()),
			RegistrationID: id.RegistrationID,
			SignedPrekey: SignedPrekey{
				ID:  spk.ID(),
				Pub: keys.CurveText(spk.KeyPair().PublicKey().PublicKey()),
				Sig: sigBytes(spk.Signature()),
			},
			From: issued.UTC(),
		}},
		Agents: agents,
		Relays: relays,
		Issued: issued.UTC(),
	}
}

func sigBytes(s [64]byte) []byte { return s[:] }

// Sign serializes c and signs the bytes with the root key. c.Party must be the root's id.
func Sign(c *Card, root *keys.Root) (*Signed, error) {
	if c.Party != keys.PartyID(root.Public()) {
		return nil, ErrParty
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return &Signed{Body: body, Sig: ed25519.Sign(root.Key, body)}, nil
}

// Verify checks s against the pinned root public key, then parses it. A card
// whose signature fails is not parsed.
func Verify(s *Signed, root ed25519.PublicKey) (*Card, error) {
	if len(root) != ed25519.PublicKeySize || len(s.Sig) != ed25519.SignatureSize || !ed25519.Verify(root, s.Body, s.Sig) {
		return nil, ErrSignature
	}
	c, err := parse(s.Body)
	if err != nil {
		return nil, err
	}
	party, err := keys.ParsePartyID(c.Party)
	if err != nil {
		return nil, fmt.Errorf("card: %w", err)
	}
	if !party.Equal(root) {
		return nil, ErrParty
	}
	return c, nil
}

// parse decodes signed card bytes under the version and critical-unknown rules
// and checks every key's encoding and signed-prekey signature.
func parse(body []byte) (*Card, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("card: %w", err)
	}
	var critical []string
	if raw, ok := top["critical"]; ok {
		if err := json.Unmarshal(raw, &critical); err != nil {
			return nil, fmt.Errorf("card: critical: %w", err)
		}
	}
	for _, name := range critical {
		if !known[name] {
			return nil, fmt.Errorf("%w %q", ErrCriticalUnknown, name)
		}
	}
	var c Card
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("card: %w", err)
	}
	if c.V != Version {
		return nil, fmt.Errorf("card: version %d, want %d", c.V, Version)
	}
	if len(c.Keys) == 0 {
		return nil, errors.New("card: no keys")
	}
	for i := range c.Keys {
		if err := c.Keys[i].check(); err != nil {
			return nil, fmt.Errorf("card: keys[%d]: %w", i, err)
		}
	}
	return &c, nil
}

func (k *Key) check() error {
	idk, err := k.IdentityKey()
	if err != nil {
		return err
	}
	pub, sig, err := k.SignedPrekeyPublic()
	if err != nil {
		return err
	}
	if !ecc.VerifySignature(idk.PublicKey(), pub.Serialize(), sig) {
		return errors.New("signed prekey signature does not verify")
	}
	return nil
}

// Retired reports whether the key's void time has passed — the revocation a
// rotation card carries (design §3.2): the new identity key, and the old
// key's until. A retired key signs nothing and opens nothing from then on.
func (k *Key) Retired(at time.Time) bool {
	return k.Until != nil && !k.Until.After(at)
}

// IdentityKey is the key's libsignal identity public key.
func (k *Key) IdentityKey() (*identity.Key, error) {
	raw, err := keys.ParseCurve(k.Identity)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return identity.NewKey(ecc.NewDjbECPublicKey(raw)), nil
}

// SignedPrekeyPublic is the signed prekey's public key and its signature.
func (k *Key) SignedPrekeyPublic() (ecc.ECPublicKeyable, [64]byte, error) {
	var sig [64]byte
	raw, err := keys.ParseCurve(k.SignedPrekey.Pub)
	if err != nil {
		return nil, sig, fmt.Errorf("signed prekey: %w", err)
	}
	if len(k.SignedPrekey.Sig) != 64 {
		return nil, sig, fmt.Errorf("signed prekey: signature %d bytes, want 64", len(k.SignedPrekey.Sig))
	}
	copy(sig[:], k.SignedPrekey.Sig)
	return ecc.NewDjbECPublicKey(raw), sig, nil
}
