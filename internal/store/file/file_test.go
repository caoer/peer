package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/caoer/peer/internal/store"
)

func TestCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	b, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	data, v, err := b.Load(ctx, "keys")
	if err != nil || data != nil || v != 0 {
		t.Fatalf("absent: %q %d %v", data, v, err)
	}
	if v, err = b.Store(ctx, "keys", []byte(`{"a":1}`), 0); err != nil || v != 1 {
		t.Fatalf("first store: %d %v", v, err)
	}
	_, err = b.Store(ctx, "keys", []byte(`{"a":2}`), 0)
	var ce *store.ConflictError
	if !errors.As(err, &ce) || !errors.Is(err, store.ErrConflict) || ce.Found != 1 || ce.Expected != 0 || ce.Key != "keys" {
		t.Fatalf("stale store: %v", err)
	}
	if data, v, err = b.Load(ctx, "keys"); err != nil || string(data) != `{"a":1}` || v != 1 {
		t.Fatalf("after stale store: %q %d %v", data, v, err)
	}
	if v, err = b.Store(ctx, "keys", []byte(`{"a":2}`), 1); err != nil || v != 2 {
		t.Fatalf("second store: %d %v", v, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestRefusals(t *testing.T) {
	ctx := context.Background()
	b, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"../x", "a/b", ".hidden", "", "Upper"} {
		if _, err := b.Store(ctx, key, []byte(`{}`), 0); err == nil {
			t.Errorf("key %q accepted", key)
		}
	}
	if _, err := b.Store(ctx, "k", []byte("not json"), 0); err == nil {
		t.Error("non-JSON data accepted")
	}
	if _, err := os.Stat(filepath.Join(b.dir, "k.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused store left a file")
	}
}
