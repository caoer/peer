package store_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

// A rotation keeps the signed prekey it replaced: both ids answer, the next
// rotation retires the older one, and the record round-trips with both.
func TestRotationKeepsThePreviousSignedPrekey(t *testing.T) {
	ctx := context.Background()
	b, err := file.New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	bob := newParty(t, "bob", b)
	pk, err := keys.GeneratePartyKeys(bob.id, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := pk.RotateSignedPrekey(bob.id); err != nil {
		t.Fatal(err)
	}
	k, _ := bob.store.Keys(ctx)
	k.PartyKeys = pk
	commit(t, ctx, k)

	k2, err := bob.store.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint32{1, 2} {
		if r, _ := k2.LoadSignedPreKey(ctx, id); r == nil || r.ID() != id {
			t.Fatalf("signed prekey %d does not answer after reload", id)
		}
	}
	if all, _ := k2.LoadSignedPreKeys(ctx); len(all) != 2 || all[0].ID() != 2 || all[1].ID() != 1 {
		t.Fatalf("signed prekeys %v, want current 2 then previous 1", all)
	}
	if k2.PartyKeys.SignedPrekeyIssued().After(time.Now()) || k2.PartyKeys.SignedPrekeyIssued().Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("signed prekey issued %s", k2.PartyKeys.SignedPrekeyIssued())
	}
	prevPub := k2.PartyKeys.PreviousSignedPrekey.KeyPair().PublicKey().PublicKey()
	if prevPub != pk.PreviousSignedPrekey.KeyPair().PublicKey().PublicKey() {
		t.Fatal("the previous signed prekey's public key changed on reload")
	}
	if err := k2.PartyKeys.RotateSignedPrekey(bob.id); err != nil {
		t.Fatal(err)
	}
	if r, _ := k2.LoadSignedPreKey(ctx, 1); r != nil {
		t.Fatal("signed prekey 1 survives two rotations")
	}
	if r, _ := k2.LoadSignedPreKey(ctx, 3); r == nil {
		t.Fatal("signed prekey 3 is not the current one")
	}
}

// The channel record carries the held card with its seq, the deposit count
// and the announced signed prekey through a reload; a snapshot that admits
// any identity reads everything and commits nothing.
func TestChannelHoldsACardAndCounts(t *testing.T) {
	ctx := context.Background()
	b, err := file.New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	bob, alice := newParty(t, "bob", b), newParty(t, "alice", b)
	apk, _ := keys.GeneratePartyKeys(alice.id, 1)
	signed, err := card.Sign(card.New(alice.id, apk, nil, nil, time.Now()), alice.root)
	if err != nil {
		t.Fatal(err)
	}
	ch, _ := bob.store.Channel(ctx, "0123456789abcdef0123456789abcdef")
	ch.PinRoot(alice.root.Public())
	ch.PinCard(signed)
	ch.Hold(signed, 7)
	ch.SetDeposited(10)
	ch.SpendDeposit()
	ch.SetAnnounced(3)
	commit(t, ctx, ch)

	ch2, _ := bob.store.Channel(ctx, ch.Name())
	held, seq := ch2.Held()
	if held == nil || seq != 7 || !bytes.Equal(held.Body, signed.Body) || !bytes.Equal(held.Sig, signed.Sig) {
		t.Fatalf("held %v at #%d after reload", held != nil, seq)
	}
	if ch2.Deposited() != 9 || ch2.Announced() != 3 {
		t.Fatalf("deposited %d announced %d", ch2.Deposited(), ch2.Announced())
	}
	for i := 0; i < 12; i++ {
		ch2.SpendDeposit()
	}
	if ch2.Deposited() != 0 {
		t.Fatalf("deposited %d below zero", ch2.Deposited())
	}
	ch2.ClearHeld()
	commit(t, ctx, ch2)
	ch3, _ := bob.store.Channel(ctx, ch.Name())
	if held, _ := ch3.Held(); held != nil {
		t.Fatal("the held card survives ClearHeld")
	}

	// The probe snapshot: a key the card does not list is admitted, and
	// Commit refuses.
	stranger, _ := keys.GenerateIdentity(alice.root.Public())
	key := identity.NewKey(ecc.NewDjbECPublicKey(stranger.PublicKey()))
	if ok, _ := ch3.IsTrustedIdentity(ctx, bob.addr, key); ok {
		t.Fatal("a pinned card admits a key it does not list")
	}
	ch3.AdmitAnyIdentity()
	if ok, _ := ch3.IsTrustedIdentity(ctx, bob.addr, key); !ok {
		t.Fatal("the probe snapshot refuses a key")
	}
	if err := ch3.Commit(ctx); !errors.Is(err, store.ErrProbe) {
		t.Fatalf("probe commit: %v, want ErrProbe", err)
	}
}
