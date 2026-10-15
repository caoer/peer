package status

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/store/file"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// The heartbeat rule against a fixed clock: 3 × beat is still fresh, a
// second more is stale.
func TestRowStale(t *testing.T) {
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	r := &Row{Beat: 30, At: at}
	for _, c := range []struct {
		after time.Duration
		stale bool
	}{{0, false}, {90 * time.Second, false}, {91 * time.Second, true}, {time.Hour, true}} {
		if got := r.Stale(at.Add(c.after)); got != c.stale {
			t.Errorf("%v after the write: stale %v, want %v", c.after, got, c.stale)
		}
	}
}

func TestRowKey(t *testing.T) {
	root := ed25519.PublicKey(make([]byte, 32))
	root[0], root[31] = 0xAB, 0x01
	k := RowKey(root)
	if k != "peer.ab"+strings.Repeat("00", 30)+"01" {
		t.Fatalf("key %q", k)
	}
}

// The newest message by seq is the last one; an ack is not unread; a send
// clears unread.
func TestActivity(t *testing.T) {
	ctx := context.Background()
	b, err := file.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	a, v, err := LoadActivity(ctx, b, "ch1")
	if err != nil || v != 0 || !a.LastAt.IsZero() || a.Unread != 0 {
		t.Fatalf("absent record: %+v v%d %v", a, v, err)
	}
	for _, n := range []struct {
		seq  int64
		at   time.Time
		kind string
	}{{3, t0, "text"}, {5, t0.Add(2 * time.Second), "ack"}, {4, t0.Add(time.Second), "task"}} {
		if err := NoteIn(ctx, b, "ch1", n.seq, n.at, n.kind); err != nil {
			t.Fatal(err)
		}
	}
	a, v, _ = LoadActivity(ctx, b, "ch1")
	if a.LastSeq != 5 || a.LastKind != "ack" || !a.LastAt.Equal(t0.Add(2*time.Second)) || a.Unread != 2 || v != 3 {
		t.Fatalf("after three notes: %+v v%d", a, v)
	}
	if err := NoteOut(ctx, b, "ch1", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	a, _, _ = LoadActivity(ctx, b, "ch1")
	if a.Unread != 0 || !a.SentAt.Equal(t0.Add(time.Minute)) || a.LastKind != "ack" {
		t.Fatalf("after a send: %+v", a)
	}
	if other, _, _ := LoadActivity(ctx, b, "ch2"); other.Unread != 0 {
		t.Fatalf("another channel shares the record: %+v", other)
	}
}

// One PUT per write once the version is known; a row another writer holds
// is taken over at the version the conflict names; a wrong login refuses.
func TestPage(t *testing.T) {
	ctx := context.Background()
	ps := pagestest.New("roster-0123456789abcdef", "zt:roster")
	defer ps.Close()
	p := NewPage(ps.URL, ps.Slug, ps.Bearer, nil)
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	row := &Row{Name: "ancan", Party: "ed25519:x", State: "confirmed", Beat: 30, At: at}
	for i := 1; i <= 2; i++ {
		if err := p.Put(ctx, "peer.aa", row); err != nil {
			t.Fatal(err)
		}
		if rec, _ := ps.Record("peer.aa"); rec.Version != int64(i) || rec.Schema != RowSchema {
			t.Fatalf("write %d: %+v", i, rec)
		}
	}
	if ps.Puts() != 2 {
		t.Fatalf("%d PUTs for two writes", ps.Puts())
	}
	ps.Set("peer.bb", pagestest.Record{Schema: RowSchema, Data: []byte(`{}`), Version: 7})
	if err := p.Put(ctx, "peer.bb", row); err != nil {
		t.Fatal(err)
	}
	if rec, _ := ps.Record("peer.bb"); rec.Version != 8 {
		t.Fatalf("taken over at %d, want 8", rec.Version)
	}
	got, err := NewPage(ps.URL, ps.Slug, ps.Bearer, nil).Get(ctx, "peer.aa")
	if err != nil || got == nil || got.Name != "ancan" || !got.At.Equal(at) || got.LastAt != nil {
		t.Fatalf("get: %+v %v", got, err)
	}
	if got, err := p.Get(ctx, "peer.cc"); got != nil || err != nil {
		t.Fatalf("absent row: %+v %v", got, err)
	}
	var pe *Error
	if err := NewPage(ps.URL, ps.Slug, "zt:wrong", nil).Put(ctx, "peer.aa", row); !errors.As(err, &pe) || pe.Status != 401 {
		t.Fatalf("wrong login: %v", err)
	}
}
