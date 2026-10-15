package room_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mau.fi/libsignal/ecc"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/room"
)

func partyCard(t *testing.T, p *party) *card.Card {
	t.Helper()
	pc, err := card.Verify(p.card, p.root.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func TestCardSignedVerify(t *testing.T) {
	m := newMember(t, 3)
	signed := m.roomCard(t, t0)
	got, err := room.Verify(signed, partyCard(t, m.party), at)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	seal, err := got.SealKey()
	if err != nil {
		t.Fatal(err)
	}
	sign, err := got.SignKey()
	if err != nil {
		t.Fatal(err)
	}
	if got.Room != roomID || got.Idx != 3 || !got.Issued.Equal(t0) ||
		!seal.Equal(m.keys.Seal.PublicKey()) || !sign.Equal(m.keys.Sign.Public()) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestCardWrongIdentityRefused(t *testing.T) {
	m, other := newMember(t, 3), newParty(t)
	signed := m.roomCard(t, t0)
	if _, err := room.Verify(signed, partyCard(t, other), at); !errors.Is(err, room.ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
	for _, i := range []int{0, len(signed) / 2, len(signed) - 1} {
		b := append([]byte(nil), signed...)
		b[i] ^= 0x01
		if _, err := room.Verify(b, partyCard(t, m.party), at); !errors.Is(err, room.ErrSignature) {
			t.Errorf("byte %d flipped: err = %v, want ErrSignature", i, err)
		}
	}
}

func TestCardRetiredIdentityKeyRefused(t *testing.T) {
	m := newMember(t, 3)
	signed := m.roomCard(t, t0)
	pc := partyCard(t, m.party)
	until := at.Add(-time.Minute)
	pc.Keys[0].Until = &until
	if _, err := room.Verify(signed, pc, at); !errors.Is(err, room.ErrSignature) {
		t.Fatalf("a key retired before the record: err = %v, want ErrSignature", err)
	}
	if _, err := room.Verify(signed, pc, until.Add(-time.Hour)); err != nil {
		t.Fatalf("the same key before its retirement: %v", err)
	}
}

func TestCardMalformedRefused(t *testing.T) {
	m := newMember(t, 3)
	pc := partyCard(t, m.party)
	good := m.keys.Card(roomID, 3, t0)
	cases := map[string]func(c *room.Card){
		"version":   func(c *room.Card) { c.V = 2 },
		"room id":   func(c *room.Card) { c.Room = "ROOM" },
		"seal len":  func(c *room.Card) { c.Seal = "AAEC" },
		"seal zero": func(c *room.Card) { c.Seal = strings.Repeat("A", 43) + "=" },
		"sign len":  func(c *room.Card) { c.Sign = "AAEC" },
		"no issued": func(c *room.Card) { c.Issued = time.Time{} },
	}
	for name, mutate := range cases {
		c := *good
		mutate(&c)
		if _, err := c.Signed(m.id); !errors.Is(err, room.ErrMalformed) {
			t.Errorf("%s: Signed err = %v, want ErrMalformed", name, err)
		}
		// The same card hand-signed: Verify refuses it after the signature passes.
		body, _ := json.Marshal(&c)
		signed := signRaw(m, body)
		if _, err := room.Verify(signed, pc, at); !errors.Is(err, room.ErrMalformed) {
			t.Errorf("%s: Verify err = %v, want ErrMalformed", name, err)
		}
	}
	for name, b := range map[string][]byte{"empty": nil, "short": make([]byte, 64), "not json": signRaw(m, []byte("{"))} {
		if _, err := room.Verify(b, pc, at); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// signRaw signs arbitrary bytes with the member's identity key, for cards this package would not produce.
func signRaw(m *member, body []byte) []byte {
	sig := ecc.CalculateSignature(m.id.KeyPair.PrivateKey(), body)
	return append(append([]byte(nil), body...), sig[:]...)
}
