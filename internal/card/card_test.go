package card

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/caoer/peer/internal/keys"
)

func newParty(t *testing.T) (*keys.Root, *Card) {
	t.Helper()
	root, err := keys.GenerateRoot()
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.GenerateIdentity(root.Public())
	if err != nil {
		t.Fatal(err)
	}
	pk, err := keys.GeneratePartyKeys(id, 2)
	if err != nil {
		t.Fatal(err)
	}
	c := New(id, pk, []Agent{{ID: "advisor", Accepts: []string{"text", "task"}}}, []string{"https://example.test/peer"}, time.Unix(1_760_000_000, 0))
	return root, c
}

// signRaw signs arbitrary card bytes, for cards this package would not produce.
func signRaw(root *keys.Root, body []byte) *Signed {
	return &Signed{Body: body, Sig: ed25519.Sign(root.Key, body)}
}

func TestSignVerify(t *testing.T) {
	root, c := newParty(t)
	s, err := Sign(c, root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(s, root.Public())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Party != c.Party || got.Keys[0].Identity != c.Keys[0].Identity || got.Agents[0].ID != "advisor" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if _, err := got.Keys[0].IdentityKey(); err != nil {
		t.Fatal(err)
	}
}

func TestFlippedByteFails(t *testing.T) {
	root, c := newParty(t)
	s, err := Sign(c, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, len(s.Body) / 2, len(s.Body) - 1} {
		body := append([]byte(nil), s.Body...)
		body[i] ^= 0x01
		if _, err := Verify(&Signed{Body: body, Sig: s.Sig}, root.Public()); !errors.Is(err, ErrSignature) {
			t.Errorf("body byte %d flipped: err = %v, want ErrSignature", i, err)
		}
	}
	sig := append([]byte(nil), s.Sig...)
	sig[10] ^= 0x80
	if _, err := Verify(&Signed{Body: s.Body, Sig: sig}, root.Public()); !errors.Is(err, ErrSignature) {
		t.Errorf("sig flipped: err = %v, want ErrSignature", err)
	}
}

func TestWrongRootFails(t *testing.T) {
	root, c := newParty(t)
	s, err := Sign(c, root)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := keys.GenerateRoot()
	if _, err := Verify(s, other.Public()); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
	// A card naming another party, signed by this root, is refused.
	c.Party = keys.PartyID(other.Public())
	body, _ := json.Marshal(c)
	if _, err := Verify(signRaw(root, body), root.Public()); !errors.Is(err, ErrParty) {
		t.Fatalf("err = %v, want ErrParty", err)
	}
}

// withFields marshals c and adds extra top-level fields.
func withFields(t *testing.T, c *Card, extra map[string]any) []byte {
	t.Helper()
	b, _ := json.Marshal(c)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range extra {
		m[k] = v
	}
	out, _ := json.Marshal(m)
	return out
}

func TestCriticalUnknownRefused(t *testing.T) {
	root, c := newParty(t)
	body := withFields(t, c, map[string]any{"groups": []string{"g1"}, "critical": []string{"groups"}})
	if _, err := Verify(signRaw(root, body), root.Public()); !errors.Is(err, ErrCriticalUnknown) {
		t.Fatalf("err = %v, want ErrCriticalUnknown", err)
	}
}

func TestNonCriticalUnknownIgnored(t *testing.T) {
	root, c := newParty(t)
	body := withFields(t, c, map[string]any{"groups": []string{"g1"}, "critical": []string{"keys"}})
	got, err := Verify(signRaw(root, body), root.Public())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Party != c.Party {
		t.Fatal("party mismatch")
	}
}

func TestBadKeysRefused(t *testing.T) {
	root, c := newParty(t)
	cases := map[string]func(k *Key){
		"short identity":     func(k *Key) { k.Identity = keys.CurvePrefix + "AAEC" },
		"zero identity":      func(k *Key) { k.Identity = keys.CurveText([32]byte{}) },
		"prekey sig flipped": func(k *Key) { k.SignedPrekey.Sig[0] ^= 1 },
	}
	for name, mutate := range cases {
		cc := *c
		cc.Keys = []Key{c.Keys[0]}
		cc.Keys[0].SignedPrekey.Sig = append([]byte(nil), c.Keys[0].SignedPrekey.Sig...)
		mutate(&cc.Keys[0])
		s, err := Sign(&cc, root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(s, root.Public()); err == nil {
			t.Errorf("%s: verified, want refusal", name)
		}
	}
}

func TestUnknownVersionRefused(t *testing.T) {
	root, c := newParty(t)
	c.V = 2
	s, err := Sign(c, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s, root.Public()); err == nil {
		t.Fatal("v2 card verified")
	}
}
