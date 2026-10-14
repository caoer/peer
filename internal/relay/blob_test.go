package relay_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// A blob goes up as raw bytes and comes back to the other side alone; the
// side that put it, an unknown id and an oversized blob are refused.
func TestBlobRoutes(t *testing.T) {
	ctx := context.Background()
	const login = "zt:owner-secret"
	_, rc, _ := relaytest.Start(t, login)
	ch, err := rc.Create(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := rc.Join(ctx, ch.ID, ch.InviteToken)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0, 1, 2, 0xff}, 1<<18)
	b, err := rc.PutBlob(ctx, ch.ID, ch.HostToken, data)
	if err != nil || !relay.ValidBlobID(b.ID) || b.Size != int64(len(data)) {
		t.Fatalf("put: %+v %v", b, err)
	}
	got, err := rc.GetBlob(ctx, ch.ID, guest, b.ID)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("get: %d bytes, %v", len(got), err)
	}
	if _, err := rc.GetBlob(ctx, ch.ID, ch.HostToken, b.ID); !errors.Is(err, relay.ErrNoSuchBlob) {
		t.Fatalf("own side's get: %v", err)
	}
	if _, err := rc.GetBlob(ctx, ch.ID, guest, "0123456789abcdef0123456789abcdef"); !errors.Is(err, relay.ErrNoSuchBlob) {
		t.Fatalf("unknown blob: %v", err)
	}
	if _, err := rc.PutBlob(ctx, ch.ID, ch.HostToken, make([]byte, relay.MaxBlob+1)); !errors.Is(err, relay.ErrTooLarge) {
		t.Fatalf("oversized put: %v", err)
	}
	if _, err := rc.PutBlob(ctx, ch.ID, ch.HostToken, nil); err == nil {
		t.Fatal("an empty put went out")
	}
}
