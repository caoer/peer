package pages

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// watched is a page, a backend watching it and another writing to it as a
// second host would, with reconnects in milliseconds.
func watched(t *testing.T) (*pagestest.Server, *Backend, *Backend) {
	t.Helper()
	oldMin, oldMax := liveBackoffMin, liveBackoffMax
	liveBackoffMin, liveBackoffMax = 10*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { liveBackoffMin, liveBackoffMax = oldMin, oldMax })
	ps := pagestest.New("state-0123456789abcdef", "zt:token")
	t.Cleanup(ps.Close)
	b := New(ps.URL, ps.Slug, ps.Bearer, nil)
	w := New(ps.URL, ps.Slug, ps.Bearer, nil)
	return ps, b, w
}

func watch(t *testing.T, b *Backend) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Watch(ctx, io.Discard)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	until(t, "the live socket to sync", b.Live)
}

func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func load(t *testing.T, b *Backend, key string) ([]byte, int64) {
	t.Helper()
	data, v, err := b.Load(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return data, v
}

func put(t *testing.T, b *Backend, key, data string, expect int64) {
	t.Helper()
	if _, err := b.Store(context.Background(), key, []byte(data), expect); err != nil {
		t.Fatal(err)
	}
}

// A record held from the hello, an absent key, and another host's write
// pushed while the socket is open are all answered with no read.
func TestWatchAnswersFromPushes(t *testing.T) {
	ps, b, w := watched(t)
	put(t, w, "keys", "one", 0)
	watch(t, b)
	gets := ps.Gets("")
	if data, v := load(t, b, "keys"); string(data) != "one" || v != 1 {
		t.Fatalf("keys = %q v%d", data, v)
	}
	if data, v := load(t, b, "absent"); data != nil || v != 0 {
		t.Fatalf("absent = %q v%d", data, v)
	}
	put(t, w, "keys", "two", 1)
	put(t, w, "ss.c", "new", 0)
	until(t, "the pushed writes", func() bool {
		a, _ := load(t, b, "keys")
		c, _ := load(t, b, "ss.c")
		return string(a) == "two" && string(c) == "new"
	})
	// Its own write is held too: the next load reads nothing.
	put(t, b, "keys", "three", 2)
	if data, v := load(t, b, "keys"); string(data) != "three" || v != 3 {
		t.Fatalf("keys after its own write = %q v%d", data, v)
	}
	if n := ps.Gets("") - gets; n != 0 {
		t.Fatalf("%d page reads while the socket was synced, want 0", n)
	}
}

// A dropped socket reads the page until it is back; it resumes from its
// cursor with only what changed, and answers from it again.
func TestWatchResumesAfterADrop(t *testing.T) {
	ps, b, w := watched(t)
	put(t, w, "keys", "one", 0)
	put(t, w, "peers", "p1", 0)
	watch(t, b)

	ps.NoLive(true)
	ps.CloseLive()
	until(t, "the socket to drop", func() bool { return !b.Live() })
	put(t, w, "keys", "two", 1)
	gets := ps.Gets("keys")
	if data, _ := load(t, b, "keys"); string(data) != "two" {
		t.Fatalf("keys while down = %q", data)
	}
	if ps.Gets("keys") != gets+1 {
		t.Fatal("a load with the socket down did not read the page")
	}
	put(t, w, "keys", "three", 2)

	ps.NoLive(false)
	until(t, "the socket to resume", b.Live)
	if _, resumed := ps.Upgrades(); resumed != 1 {
		t.Fatalf("%d resumed upgrades, want 1", resumed)
	}
	gets = ps.Gets("")
	if data, v := load(t, b, "keys"); string(data) != "three" || v != 3 {
		t.Fatalf("keys after the resume = %q v%d", data, v)
	}
	if data, _ := load(t, b, "peers"); string(data) != "p1" {
		t.Fatalf("peers after the resume = %q", data)
	}
	if n := ps.Gets("") - gets; n != 0 {
		t.Fatalf("%d page reads after the resume, want 0", n)
	}
}

// A record too large to push inline is read from the page; a write that
// finds another version there makes the next load read the page.
func TestWatchReadsRefsAndConflicts(t *testing.T) {
	ps, b, w := watched(t)
	ps.InlineMax = 16
	put(t, w, "big", string(bytes.Repeat([]byte("x"), 64)), 0)
	put(t, w, "keys", "one", 0)
	watch(t, b)

	gets := ps.Gets("big")
	if data, _ := load(t, b, "big"); len(data) != 64 {
		t.Fatalf("big = %d bytes", len(data))
	}
	if ps.Gets("big") != gets+1 {
		t.Fatal("a ref was not read from the page")
	}

	// Another version is on the page before its push lands here: the
	// conflict, then one read.
	ps.Set("keys", pagestest.Record{Schema: Schema, Data: []byte(`"dHdv"`), Version: 2}) // "two", unpushed
	_, err := b.Store(context.Background(), "keys", []byte("mine"), 1)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("store over another version: %v", err)
	}
	gets = ps.Gets("keys")
	if data, v := load(t, b, "keys"); string(data) != "two" || v != 2 {
		t.Fatalf("keys after the conflict = %q v%d", data, v)
	}
	if ps.Gets("keys") != gets+1 {
		t.Fatal("the load after a conflict did not read the page")
	}
}

// A change whose prev is not the last seq held is a hole: the socket ends
// and resumes from what it holds.
func TestApplyRefusesAHole(t *testing.T) {
	b := &Backend{}
	b.live = &live{}
	epoch := "0123456789abcdef"
	if _, err := b.apply(liveFrame{Type: "hello", Epoch: &epoch, Seq: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.apply(liveFrame{Type: "put", Key: "k", Seq: 5, Prev: 4}); !errors.Is(err, errLiveHole) {
		t.Fatalf("put after a hole: %v", err)
	}
	if _, err := b.apply(liveFrame{Type: "seq", From: 5, Seq: 6}); !errors.Is(err, errLiveHole) {
		t.Fatalf("seq after a hole: %v", err)
	}
	if ok, err := b.apply(liveFrame{Type: "seq", From: 4, Seq: 6}); err != nil || !ok || b.live.seq != 6 {
		t.Fatalf("seq in order: %v %v seq %d", ok, err, b.live.seq)
	}
}
