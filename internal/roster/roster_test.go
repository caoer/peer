package roster_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

func backend(t *testing.T) store.Backend {
	t.Helper()
	b, err := file.New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTripAndLookups(t *testing.T) {
	ctx := context.Background()
	b := backend(t)
	r, err := roster.Load(ctx, b)
	if err != nil || r.Version() != 0 || len(r.Peers) != 0 {
		t.Fatalf("fresh roster: %+v %v", r, err)
	}
	r.Set(roster.Peer{Name: "ancan", Channel: "c1", Relay: "https://x/peer", Side: roster.Host, Token: "t1", State: roster.Invited})
	r.Set(roster.Peer{Name: "zt", Channel: "c2", Relay: "https://y/peer", Side: roster.Guest, Token: "t2", State: roster.Accepted})
	r.Set(roster.Peer{Name: "ancan", Channel: "c3", Relay: "https://x/peer", Side: roster.Host, Token: "t3", State: roster.Invited})
	if err := r.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r, err = roster.Load(ctx, b)
	if err != nil || r.Version() != 1 || len(r.Peers) != 2 {
		t.Fatalf("reloaded: %+v %v", r, err)
	}
	if p := r.ByName("ancan"); p == nil || p.Channel != "c3" || p.Token != "t3" {
		t.Fatalf("Set did not replace by name: %+v", p)
	}
	if p := r.ByChannel("c2"); p == nil || p.Name != "zt" || p.Side != roster.Guest {
		t.Fatalf("ByChannel: %+v", p)
	}
	if r.ByName("nobody") != nil || r.ByChannel("c1") != nil {
		t.Fatal("stale lookups answered")
	}
}

// Two hosts change the roster from the same version: Update reloads the
// loser and reapplies, and both changes land.
func TestUpdateRetriesOnConflict(t *testing.T) {
	ctx := context.Background()
	b := backend(t)
	stale, _ := roster.Load(ctx, b)
	if err := roster.Update(ctx, b, func(r *roster.Roster) error {
		r.Set(roster.Peer{Name: "a", Channel: "c1", State: roster.Invited})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stale.Set(roster.Peer{Name: "b", Channel: "c2", State: roster.Invited})
	if err := stale.Commit(ctx); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale commit: %v, want ErrConflict", err)
	}
	applied := 0
	if err := roster.Update(ctx, b, func(r *roster.Roster) error {
		applied++
		r.Set(roster.Peer{Name: "b", Channel: "c2", State: roster.Invited})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r, _ := roster.Load(ctx, b)
	if len(r.Peers) != 2 || r.ByName("a") == nil || r.ByName("b") == nil || applied != 1 {
		t.Fatalf("after update: %+v, applied %d", r.Peers, applied)
	}
	if err := roster.Update(ctx, b, func(*roster.Roster) error { return errors.New("no") }); err == nil || err.Error() != "no" {
		t.Fatalf("fn error: %v", err)
	}
}
