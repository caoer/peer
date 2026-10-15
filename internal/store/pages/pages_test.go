package pages_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

const (
	slug   = "state-0123456789abcdef"
	bearer = "zt:token"
)

func identity(t *testing.T) *keys.Identity {
	t.Helper()
	root, err := keys.GenerateRoot()
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.GenerateIdentity(root.Public())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A sealed record round-trips through the page, which holds the schema and
// one base64 string of the sealed bytes — never the plaintext.
func TestSealedRecordOnThePage(t *testing.T) {
	ctx := context.Background()
	srv := pagestest.New(slug, bearer)
	defer srv.Close()
	b := store.Sealed(pages.New(srv.URL, slug, bearer, nil), store.SealKey(identity(t)))

	plain := []byte(`{"v":1,"hello":"world"}`)
	v, err := b.Store(ctx, "ss.c1", plain, 0)
	if err != nil || v != 1 {
		t.Fatalf("store: %d %v", v, err)
	}
	got, v, err := b.Load(ctx, "ss.c1")
	if err != nil || v != 1 || !bytes.Equal(got, plain) {
		t.Fatalf("load: %q %d %v", got, v, err)
	}

	rec, ok := srv.Record("ss.c1")
	if !ok || rec.Schema != pages.Schema || rec.Version != 1 {
		t.Fatalf("page holds %+v", rec)
	}
	var s string
	if err := json.Unmarshal(rec.Data, &s); err != nil {
		t.Fatalf("data is not a JSON string: %s", rec.Data)
	}
	blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	// Base64 once and sealed once: the decoded bytes are nonce + ciphertext + tag.
	if len(blob) != len(plain)+12+16 {
		t.Fatalf("blob %d bytes, want %d", len(blob), len(plain)+28)
	}
	if bytes.Contains(blob, []byte("hello")) {
		t.Fatal("plaintext on the page")
	}

	_, err = b.Store(ctx, "ss.c1", plain, 0)
	var ce *store.ConflictError
	if !errors.As(err, &ce) || !errors.Is(err, store.ErrConflict) || ce.Found != 1 {
		t.Fatalf("stale store: %v", err)
	}
	if got, v, err := b.Load(ctx, "ss.none"); err != nil || got != nil || v != 0 {
		t.Fatalf("absent: %q %d %v", got, v, err)
	}

	// A blob tampered with on the page does not open.
	flipped := append([]byte(nil), blob...)
	flipped[len(flipped)-1] ^= 1
	data, _ := json.Marshal(base64.StdEncoding.EncodeToString(flipped))
	srv.Set("ss.c1", pagestest.Record{Schema: pages.Schema, Data: data, Version: 1})
	if _, _, err := b.Load(ctx, "ss.c1"); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("tampered blob: %v, want ErrCorrupt", err)
	}

	// A record under another key does not open under this one.
	srv.Set("ss.c2", pagestest.Record{Schema: pages.Schema, Data: rec.Data, Version: 1})
	if _, _, err := b.Load(ctx, "ss.c2"); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("moved blob: %v, want ErrCorrupt", err)
	}

	bad := pages.New(srv.URL, slug, "zt:wrong", nil)
	var pe *pages.Error
	if _, _, err := bad.Load(ctx, "ss.c1"); !errors.As(err, &pe) || pe.Status != 401 || pe.Code != "bad_token" {
		t.Fatalf("wrong bearer: %v", err)
	}
}

// The size guard answers too_large: here before the request, and from the
// page's own 413.
func TestTooLarge(t *testing.T) {
	ctx := context.Background()
	srv := pagestest.New(slug, bearer)
	defer srv.Close()
	b := pages.New(srv.URL, slug, bearer, nil)

	big := bytes.Repeat([]byte("x"), pages.MaxEnvelope) // base64 alone is over the cap
	if _, err := b.Store(ctx, "ss.big", big, 0); !errors.Is(err, store.ErrTooLarge) {
		t.Fatalf("local guard: %v", err)
	}
	if srv.Puts() != 0 {
		t.Fatal("an over-cap envelope was sent")
	}
	srv.MaxEnvelope = 1024
	if _, err := b.Store(ctx, "ss.mid", bytes.Repeat([]byte("x"), 2048), 0); !errors.Is(err, store.ErrTooLarge) {
		t.Fatalf("page's 413: %v", err)
	}
	if srv.Puts() != 1 {
		t.Fatalf("%d puts, want 1", srv.Puts())
	}
	if _, ok := srv.Record("ss.mid"); ok {
		t.Fatal("refused record stored")
	}
}
