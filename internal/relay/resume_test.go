package relay_test

import (
	"context"
	"testing"
	"time"

	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// A socket opened at a cursor carries the rows past it, then Synced; one
// opened without a cursor, or on a relay from before resume, carries only
// what is put while it is open.
func TestResumeCarriesTheCatchUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const login = "zt:owner-secret"
	srv, rc, _ := relaytest.Start(t, login)
	ch, err := rc.Create(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := rc.Join(ctx, ch.ID, ch.InviteToken)
	if err != nil {
		t.Fatal(err)
	}
	card, _ := envelope.PackCard([]byte(`{"v":1}`), make([]byte, envelope.SigSize))
	for i := 0; i < 3; i++ {
		if _, err := rc.Put(ctx, ch.ID, guest, card); err != nil {
			t.Fatal(err)
		}
	}
	next := func(s *relay.Socket) relay.Record {
		t.Helper()
		rec, err := s.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}

	s, err := rc.Resume(ctx, ch.ID, ch.HostToken, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Resumed() {
		t.Fatal("a resuming relay's socket not Resumed")
	}
	if a, b, c := next(s), next(s), next(s); a.Seq != 1 || b.Seq != 2 || a.Synced || b.Synced || !c.Synced || c.More || c.Seq != 2 {
		t.Fatalf("catch-up: %+v %+v %+v", a, b, c)
	}
	if _, err := rc.Put(ctx, ch.ID, guest, card); err != nil {
		t.Fatal(err)
	}
	if r := next(s); r.Seq != 3 || r.Synced || r.Err != nil {
		t.Fatalf("live frame after the catch-up: %+v", r)
	}
	s.Close()

	// Without a cursor, as a client from before resume opens it: nothing
	// until a put, and no Synced.
	old, err := rc.Subscribe(ctx, ch.ID, ch.HostToken)
	if err != nil {
		t.Fatal(err)
	}
	if old.Resumed() {
		t.Fatal("a socket opened without a cursor is Resumed")
	}
	if _, err := rc.Put(ctx, ch.ID, guest, card); err != nil {
		t.Fatal(err)
	}
	if r := next(old); r.Seq != 4 || r.Synced {
		t.Fatalf("first frame without a cursor: %+v", r)
	}
	old.Close()

	// A relay from before resume ignores the cursor: not Resumed.
	srv.NoResume(true)
	s, err = rc.Resume(ctx, ch.ID, ch.HostToken, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Resumed() {
		t.Fatal("an old relay's socket taken as Resumed")
	}
}
