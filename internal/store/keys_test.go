package store_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.mau.fi/libsignal/util/keyhelper"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

// The party keys record round-trips through the store with its raw keys:
// a reloaded prekey's public key is the one generated and the private key's.
func TestPartyKeysRoundTripRawKeys(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	b, err := file.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	bob := newParty(t, "bob", b)
	pk, err := keys.GeneratePartyKeys(bob.id, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := pk.Prekeys[2].KeyPair().PublicKey().PublicKey() // id 3, before the record is mutated
	wantSPK, wantSig := pk.SignedPrekey.KeyPair().PublicKey().PublicKey(), pk.SignedPrekey.Signature()

	k, err := bob.store.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Commit(ctx); !errors.Is(err, store.ErrNoKeys) {
		t.Fatalf("commit of an absent record: %v, want ErrNoKeys", err)
	}
	k.PartyKeys = pk
	commit(t, ctx, k)
	if err := k.RemovePreKey(ctx, 2); err != nil {
		t.Fatal(err)
	}
	commit(t, ctx, k)

	k2, err := bob.store.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Version() != 2 {
		t.Fatalf("version %d, want 2", k2.Version())
	}
	if p, _ := k2.LoadPreKey(ctx, 2); p != nil {
		t.Fatal("removed prekey 2 came back")
	}
	p3, err := k2.LoadPreKey(ctx, 3)
	if err != nil || p3 == nil {
		t.Fatalf("prekey 3: %v, %v", p3, err)
	}
	if got := p3.KeyPair().PublicKey().PublicKey(); got != want {
		t.Fatalf("prekey 3 public key changed: %x != %x", got, want)
	}
	priv := p3.KeyPair().PrivateKey().Serialize()
	xp, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(xp.PublicKey().Bytes(), want[:]) {
		t.Fatal("reloaded public key is not the private key's")
	}
	spk, err := k2.LoadSignedPreKey(ctx, 1)
	if err != nil || spk == nil {
		t.Fatalf("signed prekey 1: %v, %v", spk, err)
	}
	if spk.KeyPair().PublicKey().PublicKey() != wantSPK || spk.Signature() != wantSig {
		t.Fatal("signed prekey changed")
	}
	if spk, _ := k2.LoadSignedPreKey(ctx, 9); spk != nil {
		t.Fatal("unknown signed prekey id answered")
	}
	if list, _ := k2.LoadSignedPreKeys(ctx); len(list) != 1 {
		t.Fatalf("%d signed prekeys listed, want 1", len(list))
	}

	// The file holds raw 32-byte keys, not libsignal record bytes.
	raw, err := os.ReadFile(filepath.Join(dir, store.KeysKey+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version int64 `json:"version"`
		Data    struct {
			Prekeys []struct {
				ID     uint32 `json:"id"`
				Public []byte `json:"public"`
			} `json:"prekeys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 2 || len(f.Data.Prekeys) != 3 || len(f.Data.Prekeys[0].Public) != 32 {
		t.Fatalf("file: version %d, %d prekeys, first public %d bytes", f.Version, len(f.Data.Prekeys), len(f.Data.Prekeys[0].Public))
	}

	// StorePreKey appends and moves NextPrekeyID past the new id.
	np, err := keyhelper.GeneratePreKeys(7, 7, keys.Serializer.PreKeyRecord) // inclusive end: id 7 alone
	if err != nil || len(np) != 1 {
		t.Fatalf("GeneratePreKeys(7, 7): %d keys, %v", len(np), err)
	}
	if err := k2.StorePreKey(ctx, 7, np[0]); err != nil {
		t.Fatal(err)
	}
	if k2.PartyKeys.NextPrekeyID != 8 {
		t.Fatalf("NextPrekeyID %d, want 8", k2.PartyKeys.NextPrekeyID)
	}
	commit(t, ctx, k2)
	k3, _ := bob.store.Keys(ctx)
	if ok, _ := k3.ContainsPreKey(ctx, 7); !ok {
		t.Fatal("stored prekey 7 missing after reload")
	}
}
