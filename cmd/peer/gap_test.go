package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// gapRelay fronts the fake relay and hides one seq from one pull answer,
// then answers honestly — a page with a hole in it, which the contract does
// not forbid and a proxy, a cache or a partial write can produce.
type gapRelay struct {
	s    *relaytest.Server
	hide atomic.Int64
}

func (g *gapRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/envelopes") && g.hide.Load() >= 0 {
		rec := httptest.NewRecorder()
		g.s.ServeHTTP(rec, r)
		var rows []relaytest.Row
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			g.s.ServeHTTP(w, r)
			return
		}
		out := []relaytest.Row{}
		for _, row := range rows {
			if row.Seq == g.hide.Load() {
				g.hide.Store(-1)
				continue
			}
			out = append(out, row)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}
	g.s.ServeHTTP(w, r)
}

// One page that skips a seq used to carry the cursor past that envelope for
// good — Pull only ever asks for what is after the cursor — though the relay
// still held it and the ratchet still had its message key. The gap is now
// asked for again, and both messages are delivered.
func TestServeAsksAgainForAGapPage(t *testing.T) {
	g := &gapRelay{s: relaytest.New(login)}
	g.hide.Store(-1)
	ts := httptest.NewServer(g)
	t.Cleanup(ts.Close)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), ts.URL+"/peer")

	first, _ := sendOK(t, p.guestDir, "--text", "first", "zt/advisor")
	second, _ := sendOK(t, p.guestDir, "--text", "second", "zt/advisor")
	rows := g.s.Envelopes(p.channel, "g2h")
	hidden := rows[len(rows)-2].Seq
	g.hide.Store(hidden)

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if g.hide.Load() != -1 {
		t.Fatal("the relay never hid the envelope")
	}
	if !strings.Contains(out, "asking again") {
		t.Fatalf("serve did not ask again for the gap:\n%s", out)
	}
	in := records(t, deliverDirOf(p.hostDir), deliver.Inbox)
	for _, id := range []string{first, second} {
		if _, ok := in[id]; !ok {
			t.Errorf("%s was not delivered (inbox %d records); serve said:\n%s", id, len(in), out)
		}
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if hch.Cursor() != rows[len(rows)-1].Seq {
		t.Fatalf("cursor %d, want %d", hch.Cursor(), rows[len(rows)-1].Seq)
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); out != "" {
		t.Fatalf("a quiet serve printed:\n%s", out)
	}
}

// A gap the relay answers twice is its own — a row it dropped — and must not
// stop the channel: it is reported once and the envelopes after it are
// delivered.
func TestServeGoesOnWhenAGapIsTheRelays(t *testing.T) {
	g := &alwaysGapRelay{s: relaytest.New(login)}
	g.hide.Store(-1)
	ts := httptest.NewServer(g)
	t.Cleanup(ts.Close)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), ts.URL+"/peer")

	lost, _ := sendOK(t, p.guestDir, "--text", "the row the relay dropped", "zt/advisor")
	after, _ := sendOK(t, p.guestDir, "--text", "the one behind it", "zt/advisor")
	rows := g.s.Envelopes(p.channel, "g2h")
	g.hide.Store(rows[len(rows)-2].Seq)

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "are not on the relay") {
		t.Fatalf("serve did not report the relay's gap:\n%s", out)
	}
	in := records(t, deliverDirOf(p.hostDir), deliver.Inbox)
	if _, ok := in[after]; !ok {
		t.Errorf("%s behind the gap was not delivered:\n%s", after, out)
	}
	if _, ok := in[lost]; ok {
		t.Errorf("%s was delivered though the relay never answered it", lost)
	}
}

// alwaysGapRelay hides one seq from every pull answer.
type alwaysGapRelay struct {
	s    *relaytest.Server
	hide atomic.Int64
}

func (g *alwaysGapRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/envelopes") && g.hide.Load() >= 0 {
		rec := httptest.NewRecorder()
		g.s.ServeHTTP(rec, r)
		var rows []relaytest.Row
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			g.s.ServeHTTP(w, r)
			return
		}
		out := []relaytest.Row{}
		for _, row := range rows {
			if row.Seq != g.hide.Load() {
				out = append(out, row)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}
	g.s.ServeHTTP(w, r)
}
