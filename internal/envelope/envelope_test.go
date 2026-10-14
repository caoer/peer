package envelope

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/tests"
	"go.mau.fi/libsignal/util/keyhelper"
	"go.mau.fi/libsignal/util/optional"
	"google.golang.org/protobuf/encoding/protowire"
)

var ser = serialize.NewProtoBufSerializer()

// realMessages runs a real X3DH + first reply and returns the initiator's
// PreKeySignalMessage and the responder's SignalMessage, serialized.
func realMessages(t testing.TB) (pre, msg []byte) {
	t.Helper()
	ctx := context.Background()
	aliceAddr := protocol.NewSignalAddress("alice", 1)
	bobAddr := protocol.NewSignalAddress("bob", 1)

	newStores := func(peer *protocol.SignalAddress) (*session.Builder, func() *prekey.Bundle) {
		ik, err := keyhelper.GenerateIdentityKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		reg := keyhelper.GenerateRegistrationID()
		pks, err := keyhelper.GeneratePreKeys(1, 1, ser.PreKeyRecord)
		if err != nil {
			t.Fatal(err)
		}
		spk, err := keyhelper.GenerateSignedPreKey(ik, 7, ser.SignedPreKeyRecord)
		if err != nil {
			t.Fatal(err)
		}
		pkStore := tests.NewInMemoryPreKey()
		spkStore := tests.NewInMemorySignedPreKey()
		pkStore.StorePreKey(ctx, pks[0].ID().Value, record.NewPreKey(pks[0].ID().Value, pks[0].KeyPair(), ser.PreKeyRecord))
		spkStore.StoreSignedPreKey(ctx, spk.ID(), record.NewSignedPreKey(spk.ID(), spk.Timestamp(), spk.KeyPair(), spk.Signature(), ser.SignedPreKeyRecord))
		b := session.NewBuilder(tests.NewInMemorySession(ser), pkStore, spkStore,
			tests.NewInMemoryIdentityKey(ik, reg), peer, ser)
		bundle := func() *prekey.Bundle {
			return prekey.NewBundle(reg, 1, optional.NewOptionalUint32(pks[0].ID().Value), spk.ID(),
				pks[0].KeyPair().PublicKey(), spk.KeyPair().PublicKey(), spk.Signature(), ik.PublicKey())
		}
		return b, bundle
	}
	aliceB, _ := newStores(bobAddr)
	bobB, bobBundle := newStores(aliceAddr)

	if err := aliceB.ProcessBundle(ctx, bobBundle()); err != nil {
		t.Fatal(err)
	}
	aliceC := session.NewCipher(aliceB, bobAddr)
	bobC := session.NewCipher(bobB, aliceAddr)

	m1, err := aliceC.Encrypt(ctx, []byte("hello bob"))
	if err != nil {
		t.Fatal(err)
	}
	if m1.Type() != protocol.PREKEY_TYPE {
		t.Fatalf("first message type %d, want prekey", m1.Type())
	}
	pm, err := protocol.NewPreKeySignalMessageFromBytes(m1.Serialize(), ser.PreKeySignalMessage, ser.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bobC.DecryptMessage(ctx, pm); err != nil {
		t.Fatal(err)
	}
	m2, err := bobC.Encrypt(ctx, []byte("hello alice"))
	if err != nil {
		t.Fatal(err)
	}
	if m2.Type() != protocol.WHISPER_TYPE {
		t.Fatalf("reply type %d, want normal", m2.Type())
	}
	return m1.Serialize(), m2.Serialize()
}

func TestRealMessagesPass(t *testing.T) {
	pre, msg := realMessages(t)
	for _, e := range []Envelope{{Prekey, pre}, {Msg, msg}} {
		if err := e.Check(); err != nil {
			t.Fatalf("%s: %v", e.Type, err)
		}
		typ, body := e.Wire()
		got, err := FromWire(typ, body)
		if err != nil || got.Type != e.Type || !bytes.Equal(got.Body, e.Body) {
			t.Fatalf("%s: wire round trip: %v", e.Type, err)
		}
		bin, err := e.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var back Envelope
		if err := back.UnmarshalBinary(bin); err != nil || back.Type != e.Type || !bytes.Equal(back.Body, e.Body) {
			t.Fatalf("%s: binary round trip: %v", e.Type, err)
		}
	}
	// Each type's bytes refused under the other type.
	if (Envelope{Msg, pre}).Check() == nil || (Envelope{Prekey, msg}).Check() == nil {
		t.Fatal("cross-typed message accepted")
	}
}

func TestCardPacking(t *testing.T) {
	sig := bytes.Repeat([]byte{9}, SigSize)
	e, err := PackCard([]byte(`{"v":1}`), sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Check(); err != nil {
		t.Fatal(err)
	}
	card, gotSig, err := UnpackCard(e.Body)
	if err != nil || string(card) != `{"v":1}` || !bytes.Equal(gotSig, sig) {
		t.Fatalf("unpack: %q %v", card, err)
	}
	if _, err := PackCard([]byte("x"), sig[:63]); err == nil {
		t.Fatal("63-byte signature accepted")
	}
	if _, err := PackCard(nil, sig); err == nil {
		t.Fatal("empty card accepted")
	}
}

// --- builders for hand-made Signal wire bytes ---

func key(b ...byte) []byte {
	k := make([]byte, 33)
	k[0] = 0x05
	for i := 1; i < 33; i++ {
		k[i] = byte(i)
	}
	copy(k, b)
	return k
}

func bytesField(num protowire.Number, v []byte) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func varintField(num protowire.Number, v uint64) []byte {
	b := protowire.AppendTag(nil, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func signalMsg(fields ...[]byte) []byte {
	return cat([]byte{0x33}, cat(fields...), make([]byte, 8))
}

func goodSM() []byte {
	return signalMsg(bytesField(1, key()), varintField(2, 0), varintField(3, 0), bytesField(4, make([]byte, 16)))
}

func preKeyMsg(fields ...[]byte) []byte { return cat([]byte{0x33}, cat(fields...)) }

func goodPKFields() [][]byte {
	return [][]byte{varintField(5, 42), varintField(1, 1), varintField(6, 7),
		bytesField(2, key()), bytesField(3, key(0x05, 0xaa)), bytesField(4, goodSM())}
}

func TestHandMadeValid(t *testing.T) {
	if err := CheckSignalMessage(goodSM()); err != nil {
		t.Fatal(err)
	}
	if err := CheckPreKeyMessage(preKeyMsg(goodPKFields()...)); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedRefused(t *testing.T) {
	order8 := append([]byte{0x05}, lowOrder[2][:]...)
	order8High := append([]byte(nil), order8...)
	order8High[32] |= 0x80
	pk := func(drop int, extra ...[]byte) []byte {
		f := goodPKFields()
		f = append(f[:drop], f[drop+1:]...)
		return preKeyMsg(append(f, extra...)...)
	}
	cases := []struct {
		name string
		e    Envelope
	}{
		{"unknown type byte", Envelope{Type(0), goodSM()}},
		{"type byte 4", Envelope{Type(4), goodSM()}},
		{"empty body", Envelope{Msg, nil}},
		{"oversized", Envelope{Msg, make([]byte, MaxBody+1)}},
		{"card too short", Envelope{Card, make([]byte, SigSize)}},
		{"sm short", Envelope{Msg, []byte{0x33, 1, 2}}},
		{"sm version 2", Envelope{Msg, append([]byte{0x23}, goodSM()[1:]...)}},
		{"sm empty ratchet key (library panics)", Envelope{Msg, signalMsg(bytesField(1, nil), bytesField(4, []byte{1}))}},
		{"sm 1-byte ratchet key (library zero-pads)", Envelope{Msg, signalMsg(bytesField(1, []byte{5}), bytesField(4, []byte{1}))}},
		{"sm 34-byte key", Envelope{Msg, signalMsg(bytesField(1, append(key(), 0)), bytesField(4, []byte{1}))}},
		{"sm key type 0x06", Envelope{Msg, signalMsg(bytesField(1, key(0x06)), bytesField(4, []byte{1}))}},
		{"sm all-zero key", Envelope{Msg, signalMsg(bytesField(1, append([]byte{5}, make([]byte, 32)...)), bytesField(4, []byte{1}))}},
		{"sm order-8 key", Envelope{Msg, signalMsg(bytesField(1, order8), bytesField(4, []byte{1}))}},
		{"sm order-8 key, bit 255 set", Envelope{Msg, signalMsg(bytesField(1, order8High), bytesField(4, []byte{1}))}},
		{"sm no ratchet key", Envelope{Msg, signalMsg(bytesField(4, []byte{1}))}},
		{"sm no ciphertext", Envelope{Msg, signalMsg(bytesField(1, key()))}},
		{"sm empty ciphertext", Envelope{Msg, signalMsg(bytesField(1, key()), bytesField(4, nil))}},
		{"sm repeated ratchet key", Envelope{Msg, signalMsg(bytesField(1, key()), bytesField(1, nil), bytesField(4, []byte{1}))}},
		{"sm unknown field", Envelope{Msg, signalMsg(bytesField(1, key()), bytesField(4, []byte{1}), varintField(9, 1))}},
		{"sm counter over uint32", Envelope{Msg, signalMsg(bytesField(1, key()), varintField(2, 1<<33), bytesField(4, []byte{1}))}},
		{"sm fixed32 wire type", Envelope{Msg, signalMsg(protowire.AppendFixed32(protowire.AppendTag(nil, 2, protowire.Fixed32Type), 1), bytesField(1, key()), bytesField(4, []byte{1}))}},
		{"sm truncated length", Envelope{Msg, signalMsg(bytesField(1, key()), []byte{0x22, 0x7f, 1})}},
		{"sm truncated varint", Envelope{Msg, signalMsg(bytesField(1, key()), bytesField(4, []byte{1}), []byte{0x10, 0xff})}},
		{"pk short", Envelope{Prekey, []byte{0x33}}},
		{"pk version 4", Envelope{Prekey, append([]byte{0x43}, preKeyMsg(goodPKFields()...)[1:]...)}},
		{"pk empty base key (library panics)", Envelope{Prekey, pk(3, bytesField(2, nil))}},
		{"pk empty identity key (library panics)", Envelope{Prekey, pk(4, bytesField(3, nil))}},
		{"pk no base key", Envelope{Prekey, pk(3)}},
		{"pk no identity key", Envelope{Prekey, pk(4)}},
		{"pk no message", Envelope{Prekey, pk(5)}},
		{"pk inner empty ratchet key", Envelope{Prekey, pk(5, bytesField(4, signalMsg(bytesField(1, nil), bytesField(4, []byte{1}))))}},
		{"pk repeated base key", Envelope{Prekey, preKeyMsg(append(goodPKFields(), bytesField(2, key()))...)}},
		{"pk low-order identity key", Envelope{Prekey, pk(4, bytesField(3, order8))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			if panicked := Safe(func() error { err = c.e.Check(); return nil }); panicked != nil {
				t.Fatalf("Check panicked: %v", panicked)
			}
			if err == nil {
				t.Fatal("accepted")
			}
			known := []error{ErrType, ErrEmpty, ErrTooLarge, ErrMalformed}
			ok := false
			for _, k := range known {
				ok = ok || errors.Is(err, k)
			}
			if !ok {
				t.Fatalf("error %v wraps no sentinel", err)
			}
		})
	}
}

// The inputs the libsignal measurement found panicking still panic in the
// library; Safe turns that into ErrPanic.
func TestSafeCatchesLibraryPanic(t *testing.T) {
	bad := signalMsg(bytesField(1, nil), bytesField(4, []byte{1}))
	err := Safe(func() error {
		_, err := protocol.NewSignalMessageFromBytes(bad, ser.SignalMessage)
		return err
	})
	if !errors.Is(err, ErrPanic) {
		t.Fatalf("got %v, want ErrPanic (has the library stopped panicking?)", err)
	}
	if err := Safe(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("x")
	if err := Safe(func() error { return sentinel }); err != sentinel {
		t.Fatal(err)
	}
}

func TestFromWireRefuses(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(goodSM())
	cases := map[string][2]string{
		"unknown type":       {"blob", good},
		"empty type":         {"", good},
		"url alphabet":       {"msg", strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, 30)))},
		"no padding":         {"card", base64.RawStdEncoding.EncodeToString(make([]byte, 70))},
		"not base64":         {"msg", "@@@@"},
		"embedded newline":   {"msg", good[:8] + "\n" + good[8:]},
		"empty body":         {"msg", ""},
		"oversized decoded":  {"card", base64.StdEncoding.EncodeToString(make([]byte, MaxBody+1))},
		"valid b64, bad msg": {"msg", base64.StdEncoding.EncodeToString([]byte{0x33, 0, 0})},
	}
	for name, c := range cases {
		if _, err := FromWire(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var e Envelope
	if e.UnmarshalBinary(nil) == nil || e.UnmarshalBinary([]byte{9, 1, 2}) == nil {
		t.Fatal("bad binary accepted")
	}
}

// Every lowOrder entry really yields an all-zero X25519 output.
func TestLowOrderList(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, u := range lowOrder {
		pub, err := ecdh.X25519().NewPublicKey(u[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := priv.ECDH(pub); err == nil {
			t.Errorf("lowOrder[%d] gives a non-zero secret", i)
		}
	}
}

// FuzzCheck: Check never panics, and whatever it accepts libsignal's
// deserializers take without panicking (no Safe around them here).
func FuzzCheck(f *testing.F) {
	pre, msg := realMessages(f)
	f.Add(byte(Prekey), pre)
	f.Add(byte(Msg), msg)
	f.Add(byte(Msg), goodSM())
	f.Add(byte(Prekey), preKeyMsg(goodPKFields()...))
	f.Add(byte(Msg), signalMsg(bytesField(1, nil), bytesField(4, []byte{1})))
	f.Add(byte(Card), make([]byte, 80))
	f.Fuzz(func(t *testing.T, typ byte, body []byte) {
		e := Envelope{Type(typ), body}
		if e.Check() != nil {
			return
		}
		switch e.Type {
		case Msg:
			protocol.NewSignalMessageFromBytes(body, ser.SignalMessage)
		case Prekey:
			protocol.NewPreKeySignalMessageFromBytes(body, ser.PreKeySignalMessage, ser.SignalMessage)
		}
	})
}
