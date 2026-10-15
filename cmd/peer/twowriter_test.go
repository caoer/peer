package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/sealed"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// holdFront fronts the fake relay; hold arms it to stop the next request of
// method whose path ends in suffix until release closes, entered closing as
// that request arrives. One request is held per arming.
type holdFront struct {
	proxy            http.Handler
	mu               sync.Mutex
	method, suffix   string
	entered, release chan struct{}
}

func (f *holdFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	entered, release := f.entered, f.release
	held := entered != nil && r.Method == f.method && strings.HasSuffix(r.URL.Path, f.suffix)
	if held {
		f.entered, f.release = nil, nil
	}
	f.mu.Unlock()
	if held {
		close(entered)
		<-release
	}
	f.proxy.ServeHTTP(w, r)
}

func (f *holdFront) hold(method, suffix string) (entered, release chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.method, f.suffix = method, suffix
	f.entered, f.release = make(chan struct{}), make(chan struct{})
	return f.entered, f.release
}

func startHoldFront(t *testing.T) (*relaytest.Server, string, *holdFront) {
	t.Helper()
	srv, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	f := &holdFront{proxy: httputil.NewSingleHostReverseProxy(target)}
	front := httptest.NewServer(f)
	t.Cleanup(front.Close)
	return srv, front.URL + "/peer", f
}

// whileHeld runs first until its request of method and suffix is held at the
// relay, then second to its end, then lets the held request go: second runs
// entirely inside first's window. It returns both outputs.
func whileHeld(t *testing.T, f *holdFront, method, suffix string, first, second []string) (string, string) {
	t.Helper()
	entered, release := f.hold(method, suffix)
	var once sync.Once
	let := func() { once.Do(func() { close(release) }) }
	defer let()
	type result struct {
		code      int
		out, errb string
	}
	done := make(chan result, 1)
	go func() {
		code, out, errb := cmd(t, first...)
		done <- result{code, out, errb}
	}()
	select {
	case <-entered:
	case r := <-done:
		t.Fatalf("peer %s ended (exit %d) with no %s …%s held:\n%s%s", strings.Join(first, " "), r.code, method, suffix, r.out, r.errb)
	case <-time.After(time.Minute):
		t.Fatalf("peer %s sent no %s …%s", strings.Join(first, " "), method, suffix)
	}
	out2 := mustOK(t, second...)
	let()
	r := <-done
	if r.code != 0 {
		t.Fatalf("peer %s: exit %d: %s", strings.Join(first, " "), r.code, r.errb)
	}
	return r.out, out2
}

func serveOnce(dir string) []string { return []string{"serve", "--dir", dir, "--once"} }

// onePerCtr fails when the relay holds two records of one writer at one ctr.
func onePerCtr(t *testing.T, srv *relaytest.Server, id string) {
	t.Helper()
	seen := map[[2]uint64]int64{}
	for _, r := range srv.RoomRecords(id) {
		rec, err := sealed.Parse(mustB64(t, r.Body))
		if err != nil {
			t.Fatal(err)
		}
		k := [2]uint64{uint64(r.Idx), rec.Header.Ctr}
		if prev, ok := seen[k]; ok {
			t.Errorf("relay #%d and #%d both carry idx %d ctr %d", prev, r.Seq, r.Idx, rec.Header.Ctr)
		}
		seen[k] = r.Seq
	}
}

// Party A serves room r1 from two hosts on one state and adds bob, then
// carol. Each add's accept and join are pulled by both hosts at once: the
// second host's serve runs to its end while the first host's mint, then its
// roster put, is held at the relay. Each add mints once and posts one roster
// record, the relay's members are exactly the folded roster — no live seat
// that nobody holds — and every roster notice a member births names a change,
// bob's one for carol's join (C9 finding 1).
func TestTwoHostsAddMintsOnce(t *testing.T) {
	for _, kind := range []string{"file", "pages"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			srv, base, f := startHoldFront(t)
			cfg := config{}
			switch kind {
			case "file":
				cfg.State.Dir = filepath.Join(t.TempDir(), "shared-state")
			case "pages":
				ps := pagestest.New("state-0123456789abcdef", "zt:token")
				t.Cleanup(ps.Close)
				cfg.State = stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}
			}
			a, b, c := newDir(t, cfg), newDir(t, config{}), newDir(t, config{})
			handshakeNamed(t, a, b, base, "bob", "alice")
			handshakeNamed(t, a, c, base, "carol", "alice")
			id := createRoom(t, a, base, "r1")
			a2 := secondHost(t, a)
			for _, n := range []struct{ dir, name string }{{b, "bob"}, {c, "carol"}} {
				mustOK(t, "room", "add", "--dir", a, "r1", n.name)
				mustOK(t, serveOnce(n.dir)...) // the invite; the accept goes back
				whileHeld(t, f, http.MethodPost, "/members", serveOnce(a), serveOnce(a2))
				mustOK(t, serveOnce(n.dir)...) // the seat; the join goes back
				whileHeld(t, f, http.MethodPost, "/records", serveOnce(a), serveOnce(a2))
				if out := mustOK(t, serveOnce(n.dir)...); !strings.Contains(out, "joined room") {
					t.Fatalf("%s did not join:\n%s", n.name, out)
				}
			}
			mustOK(t, serveOnce(b)...) // bob reads carol's roster record

			if n := len(slices.DeleteFunc(srv.RoomRecords(id), func(r relaytest.RoomRow) bool { return r.Idx != 0 })); n != 3 {
				t.Errorf("A put %d records, want 3: the create and one roster record per add", n)
			}
			onePerCtr(t, srv, id)
			_, aref, ast := roomOf(t, a, "r1")
			ms, err := relay.New(base, nil).ListMembers(ctx, id, aref.Token)
			if err != nil {
				t.Fatal(err)
			}
			var minted, folded []int
			for _, m := range ms.Members {
				minted = append(minted, m.Idx)
				if m.Revoked {
					t.Errorf("relay idx %d is revoked: a seat was minted and taken back", m.Idx)
				}
			}
			for _, m := range ast.Members() {
				folded = append(folded, int(m.Idx))
			}
			if !slices.Equal(minted, []int{0, 1, 2}) || !slices.Equal(folded, minted) {
				t.Errorf("relay members %v, A's fold %v: want both [0 1 2]", minted, folded)
			}
			for _, d := range []string{b, c} {
				for mid, body := range rosterNotices(t, deliverDirOf(d)) {
					if strings.HasPrefix(body, "members of room ") {
						t.Errorf("%s: roster notice %s names no change:\n%s", d, mid, body)
					}
				}
			}
			joined := 0
			for _, body := range rosterNotices(t, deliverDirOf(b)) {
				if strings.Contains(body, "idx 2 ") && strings.Contains(body, " joined") {
					joined++
				}
			}
			if joined != 1 {
				t.Errorf("bob birthed %d roster notices of carol's join, want 1", joined)
			}
		})
	}
}

// Bob's peer send runs while bob's serve round runs on the same host: the
// send's put is held at the relay while the round flushes the room outbox.
// The record is put once at its ctr, the send's receipt names its seq, and
// the receiver births it once with no step back (C9 finding 2).
func TestRoomSendBesideServePutsOnce(t *testing.T) {
	srv, base, f := startHoldFront(t)
	a, b := newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	mustOK(t, serveOnce(a)...)
	_, n0 := lastCtr(t, srv, id, 1)
	out, _ := whileHeld(t, f, http.MethodPost, "/records",
		[]string{"send", "--dir", b, "--text", "beside serve", id[:8]}, serveOnce(b))
	m := roomSentRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the send printed no receipt:\n%s", out)
	}
	if _, n := lastCtr(t, srv, id, 1); n != n0+1 {
		t.Errorf("bob's records on the relay %d → %d, want one put", n0, n)
	}
	onePerCtr(t, srv, id)
	got := mustOK(t, serveOnce(a)...)
	if strings.Contains(got, "step back") || strings.Count(got, "delivered text "+m[1]) != 1 {
		t.Errorf("alice's serve:\n%s", got)
	}
}
