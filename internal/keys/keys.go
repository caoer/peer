// Package keys generates and stores a party's keys: the cold Ed25519 root
// key that signs cards, the identity key pair with its registrationId
// (the identity file, replicated to every fleet host), and the party keys
// record holding the signed prekey and one-time prekeys.
package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/util/keyhelper"
)

// FormatVersion is the version of the root, identity and party keys files.
const FormatVersion = 1

// DeviceID is the libsignal device id of every party: a fleet is one device.
const DeviceID = 1

// Serializer is the libsignal serializer peer uses for records and wire messages.
var Serializer = serialize.NewProtoBufSerializer()

var b64 = base64.RawURLEncoding

// PartyPrefix and CurvePrefix tag the text form of an Ed25519 party key and a
// Curve25519 public key.
const (
	PartyPrefix = "ed25519:"
	CurvePrefix = "curve25519:"
)

// PartyID is the text form of a party's root public key: the party's address.
func PartyID(pub ed25519.PublicKey) string { return PartyPrefix + b64.EncodeToString(pub) }

// ParsePartyID decodes a party id into its root public key.
func ParsePartyID(s string) (ed25519.PublicKey, error) {
	rest, ok := strings.CutPrefix(s, PartyPrefix)
	if !ok {
		return nil, fmt.Errorf("party id %q: missing %q prefix", s, PartyPrefix)
	}
	b, err := b64.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("party id: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("party id: %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// CurveText is the text form of a Curve25519 public key.
func CurveText(pub [32]byte) string { return CurvePrefix + b64.EncodeToString(pub[:]) }

// ParseCurve decodes the text form of a Curve25519 public key. It refuses any
// length but 32 and the all-zero point: the library zero-pads short keys and
// does not reject an all-zero DH result.
func ParseCurve(s string) ([32]byte, error) {
	var out [32]byte
	rest, ok := strings.CutPrefix(s, CurvePrefix)
	if !ok {
		return out, fmt.Errorf("curve key %q: missing %q prefix", s, CurvePrefix)
	}
	b, err := b64.DecodeString(rest)
	if err != nil {
		return out, fmt.Errorf("curve key: %w", err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("curve key: %d bytes, want 32", len(b))
	}
	if bytes.Equal(b, make([]byte, 32)) {
		return out, errors.New("curve key: all-zero point")
	}
	copy(out[:], b)
	return out, nil
}

// Root is the cold root key. It signs cards and nothing else; it lives off the fleet.
type Root struct {
	Key ed25519.PrivateKey
}

// GenerateRoot makes a new root key.
func GenerateRoot() (*Root, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Root{Key: priv}, nil
}

// Public is the root public key, the party's id.
func (r *Root) Public() ed25519.PublicKey { return r.Key.Public().(ed25519.PublicKey) }

type rootFile struct {
	V    int    `json:"v"`
	Seed []byte `json:"seed"`
}

// MarshalJSON writes the root file.
func (r *Root) MarshalJSON() ([]byte, error) {
	return json.Marshal(rootFile{V: FormatVersion, Seed: r.Key.Seed()})
}

// UnmarshalJSON reads the root file.
func (r *Root) UnmarshalJSON(b []byte) error {
	var f rootFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.V != FormatVersion {
		return fmt.Errorf("root file: version %d, want %d", f.V, FormatVersion)
	}
	if len(f.Seed) != ed25519.SeedSize {
		return fmt.Errorf("root file: seed %d bytes, want %d", len(f.Seed), ed25519.SeedSize)
	}
	r.Key = ed25519.NewKeyFromSeed(f.Seed)
	return nil
}

// Identity is the content of the identity file: the party it belongs to, the
// libsignal identity key pair and the registrationId. It is the one secret
// replicated to every fleet host (sops-nix renders it as a plain file).
type Identity struct {
	Party          ed25519.PublicKey
	KeyPair        *identity.KeyPair
	RegistrationID uint32
}

// GenerateIdentity makes a new identity key pair and registrationId for party.
func GenerateIdentity(party ed25519.PublicKey) (*Identity, error) {
	kp, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		return nil, err
	}
	return &Identity{Party: party, KeyPair: kp, RegistrationID: keyhelper.GenerateRegistrationID()}, nil
}

// PublicKey is the raw 32-byte identity public key.
func (id *Identity) PublicKey() [32]byte { return id.KeyPair.PublicKey().PublicKey().PublicKey() }

type identityFile struct {
	V              int    `json:"v"`
	Party          string `json:"party"`
	Public         []byte `json:"public"`
	Private        []byte `json:"private"`
	RegistrationID uint32 `json:"registrationId"`
}

// MarshalJSON writes the identity file.
func (id *Identity) MarshalJSON() ([]byte, error) {
	pub := id.PublicKey()
	priv := id.KeyPair.PrivateKey().Serialize()
	return json.Marshal(identityFile{
		V:              FormatVersion,
		Party:          PartyID(id.Party),
		Public:         pub[:],
		Private:        priv[:],
		RegistrationID: id.RegistrationID,
	})
}

// UnmarshalJSON reads the identity file.
func (id *Identity) UnmarshalJSON(b []byte) error {
	var f identityFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.V != FormatVersion {
		return fmt.Errorf("identity file: version %d, want %d", f.V, FormatVersion)
	}
	party, err := ParsePartyID(f.Party)
	if err != nil {
		return fmt.Errorf("identity file: %w", err)
	}
	if len(f.Public) != 32 || len(f.Private) != 32 {
		return fmt.Errorf("identity file: key lengths %d/%d, want 32/32", len(f.Public), len(f.Private))
	}
	var pub, priv [32]byte
	copy(pub[:], f.Public)
	copy(priv[:], f.Private)
	id.Party = party
	id.KeyPair = identity.NewKeyPair(identity.NewKey(ecc.NewDjbECPublicKey(pub)), ecc.NewDjbECPrivateKey(priv))
	id.RegistrationID = f.RegistrationID
	return nil
}

// PartyKeys is the party keys record: the current signed prekey, the one it
// replaced, and the unused one-time prekeys. It is shared by every fleet host
// through the store.
type PartyKeys struct {
	SignedPrekey *record.SignedPreKey
	// PreviousSignedPrekey is the signed prekey the last rotation replaced,
	// nil before the first rotation. A peer that built its session from the
	// card announcing it may not have sent its first message yet, so the key
	// opens that message until the next rotation retires it.
	PreviousSignedPrekey *record.SignedPreKey
	Prekeys              []*record.PreKey
	// NextPrekeyID is the id the next generated one-time prekey takes.
	NextPrekeyID uint32
}

// SignedPrekeyIssued is when the current signed prekey was generated.
func (pk *PartyKeys) SignedPrekeyIssued() time.Time {
	return time.Unix(pk.SignedPrekey.Timestamp(), 0)
}

// RotateSignedPrekey replaces the signed prekey with a fresh one under the
// next id, signed by the identity key (design §3.2: serve rotates it, no
// human), and keeps the replaced one as PreviousSignedPrekey. The caller
// commits the record, then announces the new key with the card.
func (pk *PartyKeys) RotateSignedPrekey(id *Identity) error {
	spk, err := keyhelper.GenerateSignedPreKey(id.KeyPair, pk.SignedPrekey.ID()+1, Serializer.SignedPreKeyRecord)
	if err != nil {
		return err
	}
	pk.PreviousSignedPrekey, pk.SignedPrekey = pk.SignedPrekey, spk
	return nil
}

// InitialPrekeys is how many one-time prekeys init generates.
const InitialPrekeys = 100

// GeneratePartyKeys makes signed prekey 1, signed by the identity key, and
// one-time prekeys 1..n.
func GeneratePartyKeys(id *Identity, n int) (*PartyKeys, error) {
	spk, err := keyhelper.GenerateSignedPreKey(id.KeyPair, 1, Serializer.SignedPreKeyRecord)
	if err != nil {
		return nil, err
	}
	// GeneratePreKeys' second argument is the inclusive end id, not a count.
	pks, err := keyhelper.GeneratePreKeys(1, n, Serializer.PreKeyRecord)
	if err != nil {
		return nil, err
	}
	return &PartyKeys{SignedPrekey: spk, Prekeys: pks, NextPrekeyID: uint32(n) + 1}, nil
}

// The party keys record stores raw 32-byte keys and rebuilds libsignal
// records from them. It does not store libsignal's record bytes:
// NewPreKeyFromBytes and NewSignedPreKeyFromBytes (v0.2.2) read the 33-byte
// serialized public key (0x05 || key) into 32 bytes, so a reloaded record
// carries a corrupted public key.
type prekeyJSON struct {
	ID      uint32 `json:"id"`
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

type signedPrekeyJSON struct {
	prekeyJSON
	Signature []byte `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

type partyKeysFile struct {
	V                    int               `json:"v"`
	SignedPrekey         signedPrekeyJSON  `json:"signedPrekey"`
	PreviousSignedPrekey *signedPrekeyJSON `json:"previousSignedPrekey,omitempty"`
	Prekeys              []prekeyJSON      `json:"prekeys"`
	NextPrekeyID         uint32            `json:"nextPrekeyId"`
}

func rawPair(kp *ecc.ECKeyPair) (pub, priv []byte) {
	p, s := kp.PublicKey().PublicKey(), kp.PrivateKey().Serialize()
	return p[:], s[:]
}

func signedPrekeyOf(s *record.SignedPreKey) signedPrekeyJSON {
	pub, priv := rawPair(s.KeyPair())
	sig := s.Signature()
	return signedPrekeyJSON{prekeyJSON{s.ID(), pub, priv}, sig[:], s.Timestamp()}
}

// record rebuilds the libsignal signed prekey record.
func (s signedPrekeyJSON) record() (*record.SignedPreKey, error) {
	kp, err := s.keyPair()
	if err != nil {
		return nil, err
	}
	if len(s.Signature) != 64 {
		return nil, fmt.Errorf("signature %d bytes, want 64", len(s.Signature))
	}
	var sig [64]byte
	copy(sig[:], s.Signature)
	return record.NewSignedPreKey(s.ID, s.Timestamp, kp, sig, Serializer.SignedPreKeyRecord), nil
}

// keyPair rebuilds a key pair and checks the public key is the private key's.
func (p prekeyJSON) keyPair() (*ecc.ECKeyPair, error) {
	if len(p.Public) != 32 || len(p.Private) != 32 {
		return nil, fmt.Errorf("key %d: lengths %d/%d, want 32/32", p.ID, len(p.Public), len(p.Private))
	}
	priv, err := ecdh.X25519().NewPrivateKey(p.Private)
	if err != nil {
		return nil, fmt.Errorf("key %d: %w", p.ID, err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), p.Public) {
		return nil, fmt.Errorf("key %d: public key does not match private key", p.ID)
	}
	var pub, sec [32]byte
	copy(pub[:], p.Public)
	copy(sec[:], p.Private)
	return ecc.NewECKeyPair(ecc.NewDjbECPublicKey(pub), ecc.NewDjbECPrivateKey(sec)), nil
}

// MarshalJSON writes the party keys record.
func (pk *PartyKeys) MarshalJSON() ([]byte, error) {
	f := partyKeysFile{
		V:            FormatVersion,
		SignedPrekey: signedPrekeyOf(pk.SignedPrekey),
		Prekeys:      make([]prekeyJSON, 0, len(pk.Prekeys)),
		NextPrekeyID: pk.NextPrekeyID,
	}
	if pk.PreviousSignedPrekey != nil {
		prev := signedPrekeyOf(pk.PreviousSignedPrekey)
		f.PreviousSignedPrekey = &prev
	}
	for _, p := range pk.Prekeys {
		pub, priv := rawPair(p.KeyPair())
		f.Prekeys = append(f.Prekeys, prekeyJSON{p.ID().Value, pub, priv})
	}
	return json.Marshal(f)
}

// UnmarshalJSON reads the party keys record.
func (pk *PartyKeys) UnmarshalJSON(b []byte) error {
	var f partyKeysFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.V != FormatVersion {
		return fmt.Errorf("party keys: version %d, want %d", f.V, FormatVersion)
	}
	spk, err := f.SignedPrekey.record()
	if err != nil {
		return fmt.Errorf("party keys: signed prekey: %w", err)
	}
	var prev *record.SignedPreKey
	if f.PreviousSignedPrekey != nil {
		if prev, err = f.PreviousSignedPrekey.record(); err != nil {
			return fmt.Errorf("party keys: previous signed prekey: %w", err)
		}
	}
	pks := make([]*record.PreKey, 0, len(f.Prekeys))
	for _, p := range f.Prekeys {
		kp, err := p.keyPair()
		if err != nil {
			return fmt.Errorf("party keys: prekey: %w", err)
		}
		pks = append(pks, record.NewPreKey(p.ID, kp, Serializer.PreKeyRecord))
	}
	pk.SignedPrekey, pk.PreviousSignedPrekey, pk.Prekeys, pk.NextPrekeyID = spk, prev, pks, f.NextPrekeyID
	return nil
}
