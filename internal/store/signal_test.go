package store_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/session"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

// party is one side of a channel: its identity, its store and its address.
type party struct {
	root  *keys.Root
	id    *keys.Identity
	store *store.Store
	addr  *protocol.SignalAddress
}

func fileBackend(t *testing.T) store.Backend {
	t.Helper()
	b, err := file.New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newParty(t *testing.T, name string, b store.Backend) *party {
	t.Helper()
	root, err := keys.GenerateRoot()
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.GenerateIdentity(root.Public())
	if err != nil {
		t.Fatal(err)
	}
	return &party{root: root, id: id, store: store.New(b, id), addr: protocol.NewSignalAddress(name, keys.DeviceID)}
}

// load opens the party's channel and keys snapshots, as a fresh process would.
func (p *party) load(t *testing.T, ctx context.Context, channel string) (*store.Channel, *store.Keys) {
	t.Helper()
	ch, err := p.store.Channel(ctx, channel)
	if err != nil {
		t.Fatal(err)
	}
	k, err := p.store.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ch, k
}

func commit(t *testing.T, ctx context.Context, c interface{ Commit(context.Context) error }) {
	t.Helper()
	if err := c.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// The four stores carry a Signal session from X3DH through a reply, across a
// reload from the backend between every step.
func TestSignalSessionThroughTheStores(t *testing.T) {
	ctx := context.Background()
	alice := newParty(t, "alice", fileBackend(t))
	bob := newParty(t, "bob", fileBackend(t))
	ser := keys.Serializer

	// Bob seeds his party keys record from init's output and commits.
	_, bk := bob.load(t, ctx, "c1")
	if bk.PartyKeys != nil {
		t.Fatal("keys record present before seeding")
	}
	pk, err := keys.GeneratePartyKeys(bob.id, 3)
	if err != nil {
		t.Fatal(err)
	}
	bk.PartyKeys = pk
	commit(t, ctx, bk)

	// Alice builds Bob's bundle (card facts + a one-time prekey from the relay)
	// and sends the first message.
	opk := pk.Prekeys[0]
	bundle := prekey.NewBundle(bob.id.RegistrationID, keys.DeviceID, opk.ID(), pk.SignedPrekey.ID(),
		opk.KeyPair().PublicKey(), pk.SignedPrekey.KeyPair().PublicKey(), pk.SignedPrekey.Signature(), bob.id.KeyPair.PublicKey())
	ach, ak := alice.load(t, ctx, "c1")
	ab := session.NewBuilder(ach, ak, ak, ach, bob.addr, ser)
	if err := ab.ProcessBundle(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	ac := session.NewCipher(ab, bob.addr)
	m1, err := ac.Encrypt(ctx, []byte("hello bob"))
	if err != nil {
		t.Fatal(err)
	}
	if m1.Type() != protocol.PREKEY_TYPE {
		t.Fatalf("first message type %d, want PreKey", m1.Type())
	}
	commit(t, ctx, ach)
	if ach.Version() != 1 {
		t.Fatalf("alice channel version %d, want 1", ach.Version())
	}

	// Bob decrypts from a fresh load; the one-time prekey leaves his snapshot.
	bch, bk := bob.load(t, ctx, "c1")
	bb := session.NewBuilder(bch, bk, bk, bch, alice.addr, ser)
	bc := session.NewCipher(bb, alice.addr)
	pkm, err := protocol.NewPreKeySignalMessageFromBytes(m1.Serialize(), ser.PreKeySignalMessage, ser.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	out, err := bc.DecryptMessage(ctx, pkm)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello bob" {
		t.Fatalf("decrypted %q", out)
	}
	if ok, _ := bk.ContainsPreKey(ctx, opk.ID().Value); ok {
		t.Fatal("used one-time prekey still held")
	}
	if raw, ok := bch.RemoteIdentity(alice.addr); !ok || raw != alice.id.PublicKey() {
		t.Fatal("remote identity not recorded as alice's")
	}
	commit(t, ctx, bch)
	commit(t, ctx, bk)
	if bk.Version() != 2 {
		t.Fatalf("bob keys version %d, want 2", bk.Version())
	}

	// Bob replies from another fresh load; Alice reads it from hers.
	bch, bk = bob.load(t, ctx, "c1")
	if n := len(bk.PartyKeys.Prekeys); n != 2 {
		t.Fatalf("%d prekeys after reload, want 2", n)
	}
	bc = session.NewCipher(session.NewBuilder(bch, bk, bk, bch, alice.addr, ser), alice.addr)
	r1, err := bc.Encrypt(ctx, []byte("hi alice"))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Type() != protocol.WHISPER_TYPE {
		t.Fatalf("reply type %d, want Whisper", r1.Type())
	}
	commit(t, ctx, bch)

	ach, ak = alice.load(t, ctx, "c1")
	ac = session.NewCipher(session.NewBuilder(ach, ak, ak, ach, bob.addr, ser), bob.addr)
	sm, err := protocol.NewSignalMessageFromBytes(r1.Serialize(), ser.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	if out, err = ac.Decrypt(ctx, sm); err != nil || string(out) != "hi alice" {
		t.Fatalf("alice decrypt: %q, %v", out, err)
	}
	commit(t, ctx, ach)
	m3, err := ac.Encrypt(ctx, []byte("again"))
	if err != nil {
		t.Fatal(err)
	}
	if m3.Type() != protocol.WHISPER_TYPE {
		t.Fatalf("message after the reply has type %d, want Whisper", m3.Type())
	}

	// The committed state refuses the reply a second time: the message key is gone.
	ach, ak = alice.load(t, ctx, "c1")
	ac = session.NewCipher(session.NewBuilder(ach, ak, ak, ach, bob.addr, ser), bob.addr)
	if _, err := ac.Decrypt(ctx, sm); err == nil {
		t.Fatal("replayed ciphertext decrypted against committed state")
	}
}

// A pinned card gates IsTrustedIdentity: anything before the pin, only the
// card's identity keys after, across a reload.
func TestPinnedCardGatesIdentity(t *testing.T) {
	ctx := context.Background()
	alice := newParty(t, "alice", fileBackend(t))
	bob := newParty(t, "bob", fileBackend(t))
	apk, err := keys.GeneratePartyKeys(alice.id, 1)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := card.Sign(card.New(alice.id, apk, nil, nil, time.Now()), alice.root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := keys.GenerateIdentity(alice.root.Public())
	if err != nil {
		t.Fatal(err)
	}

	bch, _ := bob.load(t, ctx, "c1")
	if ok, err := bch.IsTrustedIdentity(ctx, alice.addr, other.KeyPair.PublicKey()); err != nil || !ok {
		t.Fatalf("before the pin: trusted=%v err=%v, want any key trusted", ok, err)
	}
	bch.PinRoot(alice.root.Public())
	bch.PinCard(signed)
	commit(t, ctx, bch)

	bch, _ = bob.load(t, ctx, "c1")
	if !bytes.Equal(bch.Root(), alice.root.Public()) || !bytes.Equal(bch.Card().Body, signed.Body) || !bytes.Equal(bch.Card().Sig, signed.Sig) {
		t.Fatal("pinned root or card changed by the round trip")
	}
	if ok, err := bch.IsTrustedIdentity(ctx, alice.addr, alice.id.KeyPair.PublicKey()); err != nil || !ok {
		t.Fatalf("card's identity: trusted=%v err=%v", ok, err)
	}
	if ok, err := bch.IsTrustedIdentity(ctx, alice.addr, other.KeyPair.PublicKey()); err != nil || ok {
		t.Fatalf("another identity: trusted=%v err=%v, want refused", ok, err)
	}
}

// A rotation card lists the new identity key and the old key's void time
// (design §3.2). Once that time is past, whoever holds the old key — the
// case rotation exists to answer — is refused, while the new key is admitted
// from the same card.
func TestRetiredKeyIsNotTrusted(t *testing.T) {
	ctx := context.Background()
	alice := newParty(t, "alice", fileBackend(t))
	bob := newParty(t, "bob", fileBackend(t))

	// The key bundle alice rotated away from, and the one in force; both are
	// the same party, so one root signs the card that lists both.
	oldID, err := keys.GenerateIdentity(alice.root.Public())
	if err != nil {
		t.Fatal(err)
	}
	oldPK, err := keys.GeneratePartyKeys(oldID, 1)
	if err != nil {
		t.Fatal(err)
	}
	newPK, err := keys.GeneratePartyKeys(alice.id, 1)
	if err != nil {
		t.Fatal(err)
	}
	rotated := card.New(alice.id, newPK, nil, nil, time.Now())
	void := time.Now().Add(-time.Hour)
	retired := card.New(oldID, oldPK, nil, nil, time.Now().Add(-2*time.Hour)).Keys[0]
	retired.Until = &void
	rotated.Keys = append([]card.Key{retired}, rotated.Keys...)
	signed, err := card.Sign(rotated, alice.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := card.Verify(signed, alice.root.Public()); err != nil {
		t.Fatalf("the rotation card does not verify: %v", err)
	}

	bch, _ := bob.load(t, ctx, "c1")
	bch.PinRoot(alice.root.Public())
	bch.PinCard(signed)
	commit(t, ctx, bch)

	bch, _ = bob.load(t, ctx, "c1")
	if ok, err := bch.IsTrustedIdentity(ctx, alice.addr, oldID.KeyPair.PublicKey()); err != nil || ok {
		t.Errorf("the retired identity key: trusted=%v err=%v, want refused", ok, err)
	}
	if ok, err := bch.IsTrustedIdentity(ctx, alice.addr, alice.id.KeyPair.PublicKey()); err != nil || !ok {
		t.Errorf("the card's key in force: trusted=%v err=%v", ok, err)
	}
}

func TestChannelRecordBasics(t *testing.T) {
	ctx := context.Background()
	p := newParty(t, "p", fileBackend(t))
	ch, _ := p.load(t, ctx, "c1")
	if ch.Cursor() != -1 || ch.Version() != 0 {
		t.Fatalf("fresh channel cursor %d version %d", ch.Cursor(), ch.Version())
	}
	for i := 0; i < store.MaxSeen+5; i++ {
		ch.MarkSeen(string(rune('a'+i%26))+string(rune('0'+i/26%10))+string(rune('0'+i/260)), int64(i))
	}
	ch.SetCursor(42)
	commit(t, ctx, ch)
	ch, _ = p.load(t, ctx, "c1")
	if ch.Cursor() != 42 || ch.Version() != 1 {
		t.Fatalf("cursor %d version %d after reload", ch.Cursor(), ch.Version())
	}
	if ch.Seen("a00") || !ch.Seen("f00") {
		t.Fatal("seen set did not keep the newest MaxSeen ids")
	}
	if _, err := p.store.Channel(ctx, "../x"); err == nil {
		t.Fatal("channel name with a slash accepted")
	}
}
