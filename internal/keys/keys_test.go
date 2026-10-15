package keys

import (
	"encoding/json"
	"testing"
)

func TestFilesRoundTrip(t *testing.T) {
	root, err := GenerateRoot()
	if err != nil {
		t.Fatal(err)
	}
	id, err := GenerateIdentity(root.Public())
	if err != nil {
		t.Fatal(err)
	}
	pk, err := GeneratePartyKeys(id, 5)
	if err != nil {
		t.Fatal(err)
	}

	var root2 Root
	roundTrip(t, root, &root2)
	if !root2.Key.Equal(root.Key) {
		t.Fatal("root key changed")
	}

	var id2 Identity
	roundTrip(t, id, &id2)
	if id2.PublicKey() != id.PublicKey() || id2.KeyPair.PrivateKey().Serialize() != id.KeyPair.PrivateKey().Serialize() ||
		id2.RegistrationID != id.RegistrationID || !id2.Party.Equal(root.Public()) {
		t.Fatal("identity changed")
	}

	var pk2 PartyKeys
	roundTrip(t, pk, &pk2)
	if len(pk2.Prekeys) != 5 || pk2.NextPrekeyID != 6 || pk2.SignedPrekey.ID() != 1 {
		t.Fatalf("party keys: %d prekeys, next %d, spk %d", len(pk2.Prekeys), pk2.NextPrekeyID, pk2.SignedPrekey.ID())
	}
	if pk2.Prekeys[0].ID().Value != 1 || pk2.Prekeys[4].ID().Value != 5 {
		t.Fatal("prekey ids not 1..5")
	}
	if pk2.SignedPrekey.Signature() != pk.SignedPrekey.Signature() ||
		pk2.SignedPrekey.KeyPair().PublicKey().PublicKey() != pk.SignedPrekey.KeyPair().PublicKey().PublicKey() {
		t.Fatal("signed prekey changed")
	}
	if pk2.Prekeys[3].KeyPair().PublicKey().PublicKey() != pk.Prekeys[3].KeyPair().PublicKey().PublicKey() {
		t.Fatal("prekey public key changed")
	}
}

func roundTrip(t *testing.T, in json.Marshaler, out json.Unmarshaler) {
	t.Helper()
	b, err := in.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := out.UnmarshalJSON(b); err != nil {
		t.Fatal(err)
	}
}

func TestParseCurveRefuses(t *testing.T) {
	for _, s := range []string{"x25519:AAAA", CurvePrefix + "AAEC", CurveText([32]byte{}), CurvePrefix + "!!"} {
		if _, err := ParseCurve(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
	var k [32]byte
	k[0] = 9
	if _, err := ParseCurve(CurveText(k)); err != nil {
		t.Fatal(err)
	}
}
