package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/timeline"
)

// fieldOrder is a JSON object's top-level keys in their order.
func fieldOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", raw)
	}
	var keys []string
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// sentSeq is the relay seq a send printed.
func sentSeq(t *testing.T, out string) int64 {
	t.Helper()
	m := sentRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no receipt:\n%s", out)
	}
	n, _ := strconv.ParseInt(m[4], 10, 64)
	return n
}

var fieldsInOrder = []string{"id", "dir", "kind", "from", "to", "at", "body"}

// A spooled message born by the next start's replay — the serve cut after
// the commit, before the birth — is forwarded then, once.
func TestForwardSpooledBirth(t *testing.T) {
	ctx := context.Background()
	p, h, _ := forwardPair(t)
	before := h.count()
	id, _ := sendOK(t, p.hostDir, "--text", "replayed", "ancan")
	sv, err := openServer(p.guestDir, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cut := errors.New("cut before the birth")
	sv.beforeBirth = func(*store.Entry) error { return cut }
	if err := sv.round(ctx); !errors.Is(err, cut) {
		t.Fatalf("round: %v", err)
	}
	if h.count() != before {
		t.Fatal("forwarded before the birth")
	}
	sv2, err := openServer(p.guestDir, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv2.start(ctx); err != nil {
		t.Fatal(err)
	}
	if h.count() != before+1 {
		t.Fatalf("%d POSTs after the replay, want one", h.count()-before)
	}
	if r, raw := h.post(t, before); r.ID != id || r.Dir != timeline.In || string(r.Body) != `"replayed"` {
		t.Fatalf("record %s", raw)
	}
}

// A sent message whose put failed after its commit has no relay seq yet: it
// waits beside the outbox, and the replay's put forwards it once, as out,
// and clears it.
func TestTimelineSentAfterOutboxReplay(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	fr := &flakyRelay{proxy: httputil.NewSingleHostReverseProxy(target)}
	proxy := httptest.NewServer(fr)
	t.Cleanup(proxy.Close)
	p, h, _ := forwardPairOn(t, proxy.URL+"/peer")
	before := h.count()

	fr.refusePuts.Store(true)
	code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--text", "queued", "zt/advisor")
	m := regexp.MustCompile(`peer send: (\S+) is committed but the relay did not take it`).FindStringSubmatch(errb)
	if code != 1 || m == nil {
		t.Fatalf("send with the relay down: exit %d, stderr %q", code, errb)
	}
	pending := filepath.Join(p.guestDir, timelinePendingDir, m[1]+".json")
	if _, err := os.Stat(pending); err != nil {
		t.Fatal(err)
	}
	fr.refusePuts.Store(false)
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending record left: %v", err)
	}
	if h.count() != before+1 {
		t.Fatalf("%d POSTs for the replayed send, want one", h.count()-before)
	}
	if r, raw := h.post(t, before); r.ID != m[1] || r.Dir != timeline.Out || r.Peer != p.hostParty || string(r.Body) != `"queued"` {
		t.Fatalf("record %s", raw)
	}
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != before+1 {
		t.Fatalf("%d POSTs after a later round, want one", h.count()-before)
	}
}

// forwardSecret is the guest's forward bearer in forwardPair.
const forwardSecret = "fwd-secret-0123456789"

// forwardPair is a handshake whose guest forwards its messages with the host
// ("zt") to a hook answering code (-1 hangs until the POST gives up). The
// hook has had the handshake's card by the time it returns.
func forwardPair(t *testing.T) (p *pair, h *hookServer, code *atomic.Int32) {
	t.Helper()
	return forwardPairOn(t, "")
}

// forwardPairOn is forwardPair on the relay at base, a fresh one when "".
func forwardPairOn(t *testing.T, base string) (p *pair, h *hookServer, code *atomic.Int32) {
	t.Helper()
	if base == "" {
		_, _, base = relaytest.Start(t, login)
	}
	code = &atomic.Int32{}
	code.Store(http.StatusOK)
	h = newHook(t, func(_ int, r *http.Request) int {
		c := int(code.Load())
		if c == -1 {
			<-r.Context().Done()
			return 0
		}
		return c
	})
	trustHooks(t, h)
	cfg := config{Forward: &forwardConfig{URL: h.URL, Secret: forwardSecret}}
	return handshake(t, newDir(t, hostCfg()), newDir(t, cfg), base), h, code
}

// forwardedRecord is a POST's record with its truncated mark, and the
// POST's peer.
type forwardedRecord struct {
	timeline.Record
	Truncated bool   `json:"truncated"`
	Peer      string `json:"-"`
}

// parseForward is a POST's record and the raw bytes of its data, the
// body's fields and schema checked.
func parseForward(t *testing.T, post []byte) (*forwardedRecord, []byte) {
	t.Helper()
	var body struct {
		Peer   string `json:"peer"`
		Record struct {
			Schema string          `json:"schema"`
			Data   json.RawMessage `json:"data"`
		} `json:"record"`
	}
	if err := json.Unmarshal(post, &body); err != nil {
		t.Fatalf("%v\n%s", err, post)
	}
	if order := fieldOrder(t, post); strings.Join(order, ",") != "peer,record" {
		t.Fatalf("POST fields %v: %s", order, post)
	}
	if body.Record.Schema != timeline.Schema {
		t.Fatalf("schema %q: %s", body.Record.Schema, post)
	}
	var r forwardedRecord
	if err := json.Unmarshal(body.Record.Data, &r); err != nil {
		t.Fatalf("%v\n%s", err, post)
	}
	r.Peer = body.Peer
	return &r, body.Record.Data
}

// post is the hook's i'th POST, parsed, and the raw bytes of its data.
func (h *hookServer) post(t *testing.T, i int) (*forwardedRecord, []byte) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if i >= len(h.posts) {
		t.Fatalf("POST %d of %d", i, len(h.posts))
	}
	return parseForward(t, h.posts[i])
}

func forwardFailures(t *testing.T, dir, id string) int {
	t.Helper()
	var e forwardEntry
	b, err := os.ReadFile(filepath.Join(dir, forwardPendingDir, id+".json"))
	if err == nil {
		err = json.Unmarshal(b, &e)
	}
	if err != nil {
		t.Fatal(err)
	}
	return e.Failures
}

func forwardPending(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, forwardPendingDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// A received and a sent message each reach <url>/forward once, with the
// bearer, as {peer, record}: the counterpart's party id, no chat. A 5xx keeps
// the record, one POST a round with the inbox record already written, and
// the 2xx clears the file.
func TestForwardOnceRetriedAndCleared(t *testing.T) {
	p, h, code := forwardPair(t)
	before := h.count()
	if before == 0 {
		t.Fatal("the handshake's card was not forwarded")
	}
	id, _ := sendOK(t, p.hostDir, "--text", "hello", "ancan")
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != before+1 {
		t.Fatalf("%d POSTs, want one", h.count()-before)
	}
	r, raw := h.post(t, before)
	if order := fieldOrder(t, raw); strings.Join(order, ",") != strings.Join(fieldsInOrder, ",") {
		t.Errorf("field order %v: %s", order, raw)
	}
	if r.ID != id || r.Dir != timeline.In || r.Kind != "text" || r.Peer != p.hostParty || string(r.Body) != `"hello"` || r.Truncated {
		t.Errorf("record %s", raw)
	}
	h.mu.Lock()
	auth, path, post := h.auths[before], h.paths[before], h.posts[before]
	h.mu.Unlock()
	if auth != "Bearer "+forwardSecret || path != "/forward" || bytes.Contains(post, []byte("chat")) || bytes.Contains(post, []byte("topic")) {
		t.Errorf("POST %s with %q: %s", path, auth, post)
	}
	if q := forwardPending(t, p.guestDir); len(q) != 0 {
		t.Errorf("pending after a 2xx: %v", q)
	}
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != before+1 {
		t.Fatalf("%d POSTs after a later round, want one", h.count()-before)
	}
	sid, _ := sendOK(t, p.guestDir, "--kind", "answer", "--text", "sent", "zt/advisor")
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != before+2 {
		t.Fatalf("%d POSTs after a send and a round, want two", h.count()-before)
	}
	if r, raw := h.post(t, before+1); r.ID != sid || r.Dir != timeline.Out || r.Kind != "answer" || r.Peer != p.hostParty || r.To != p.hostParty+"/advisor" || string(r.Body) != `"sent"` {
		t.Errorf("sent record %s", raw)
	}

	code.Store(http.StatusServiceUnavailable)
	out := mustOK(t, "send", "--dir", p.hostDir, "--text", "again", "ancan")
	id2 := sentRE.FindStringSubmatch(out)[1]
	base := h.count()
	out = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != base+1 || !strings.Contains(out, "forward zt: "+id2+": answered 503") {
		t.Fatalf("%d POSTs on the 503 round:\n%s", h.count()-base, out)
	}
	if n := forwardFailures(t, p.guestDir, id2); n != 1 {
		t.Errorf("failures %d, want 1", n)
	}
	if records(t, deliverDirOf(p.guestDir), "inbox")[id2] == nil {
		t.Error("no inbox record while the forward waits")
	}
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != base+2 || forwardFailures(t, p.guestDir, id2) != 2 {
		t.Fatalf("%d POSTs after the second 503 round, want 2", h.count()-base)
	}
	code.Store(http.StatusOK)
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != base+3 {
		t.Fatalf("%d POSTs after the 200, want 3", h.count()-base)
	}
	if r, raw := h.post(t, base+2); r.ID != id2 || string(r.Body) != `"again"` {
		t.Errorf("retried record %s", raw)
	}
	if q := forwardPending(t, p.guestDir); len(q) != 0 {
		t.Errorf("pending after the 2xx: %v", q)
	}
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != base+3 {
		t.Fatalf("%d POSTs after the clear, want 3", h.count()-base)
	}
}

// A config with no forward sends nothing, and serve says so at start.
func TestForwardOffSendsNothing(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	h := newHook(t, func(int, *http.Request) int { return http.StatusOK })
	trustHooks(t, h)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	id, _ := sendOK(t, p.hostDir, "--text", "plain", "ancan")
	out := mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.HasPrefix(out, "forward: off\n") {
		t.Errorf("serve:\n%s", out)
	}
	sendOK(t, p.guestDir, "--text", "back", "zt")
	if records(t, deliverDirOf(p.guestDir), "inbox")[id] == nil {
		t.Error("no inbox record")
	}
	if h.count() != 0 {
		t.Errorf("%d POSTs", h.count())
	}
	if _, err := os.Stat(filepath.Join(p.guestDir, forwardPendingDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pending directory: %v", err)
	}
}

// A 204 is the worker's word that it has no chat for this peer: logged once,
// not kept, not retried.
func TestForward204NotRetried(t *testing.T) {
	p, h, code := forwardPair(t)
	code.Store(http.StatusNoContent)
	before := h.count()
	id, _ := sendOK(t, p.hostDir, "--text", "nobody's", "ancan")
	out := mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.HasPrefix(out, "forward: "+h.URL+"\n") || !strings.Contains(out, "forward zt: "+id+": no target") || h.count() != before+1 {
		t.Fatalf("%d POSTs:\n%s", h.count()-before, out)
	}
	if q := forwardPending(t, p.guestDir); len(q) != 0 {
		t.Errorf("pending after a 204: %v", q)
	}
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != before+1 {
		t.Errorf("%d POSTs after another round, want one", h.count()-before)
	}
}

// A config that still has timelines, U2b's per-peer forward map, or a
// forward without its url and secret refuses to load, naming the key.
func TestForwardConfigRefusesOldKeys(t *testing.T) {
	for name, tc := range map[string]struct{ key, raw, want string }{
		"timelines":    {"timelines", `{"zt":{"forward":"https://x/h"}}`, "timelines"},
		"per-peer map": {"forward", `{"zt":"https://x/h"}`, "forward.zt"},
		"no secret":    {"forward", `{"url":"https://x"}`, "url and secret"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := newDir(t, config{})
			path := filepath.Join(dir, configFile)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var top map[string]json.RawMessage
			if err := json.Unmarshal(b, &top); err != nil {
				t.Fatal(err)
			}
			top[tc.key] = json.RawMessage(tc.raw)
			if err := os.WriteFile(path, mustJSON(t, top), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"status", "--dir", dir}, {"serve", "--dir", dir, "--once"}} {
				code, _, errb := cmd(t, args...)
				if code != 1 || !strings.Contains(errb, tc.want) {
					t.Fatalf("peer %s: exit %d: %s", args[0], code, errb)
				}
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The body is cut where its JSON form reaches 60,000 bytes, on a rune
// boundary, and marked; the whole POST fits the handler lane's 64 KiB
// however much of the body JSON has to escape.
func TestForwardCutsBody(t *testing.T) {
	a := func(n int) string { return strings.Repeat("a", n) }
	for _, tc := range []struct {
		name, body, want string
		cut              bool
	}{
		{"short", "short", "short", false},
		{"at the limit", a(60000), a(60000), false},
		{"one over", a(60001), a(60000), true},
		{"a rune across the limit", a(59999) + "é" + "bbb", a(59999), true},
		{"escapes count", strings.Repeat("<\n", 60000), strings.Repeat("<\n", 7500), true},
		{"a megabyte", a(1 << 20), a(60000), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := forwardBytes(timeline.In, &session.Message{V: 1, ID: "m1", From: "a", To: "b", Kind: "text", At: time.Now(), Body: []byte(tc.body)})
			if err != nil {
				t.Fatal(err)
			}
			if len(b) > 64*1024 {
				t.Errorf("POST is %d bytes", len(b))
			}
			r, data := parseForward(t, b)
			var body string
			if err := json.Unmarshal(r.Body, &body); err != nil {
				t.Fatal(err)
			}
			if body != tc.want || r.Truncated != tc.cut {
				t.Errorf("body %d bytes, truncated %v; want %d bytes, %v", len(body), r.Truncated, len(tc.want), tc.cut)
			}
			if order := fieldOrder(t, data); tc.cut != (order[len(order)-1] == "truncated") {
				t.Errorf("fields %v", order)
			}
		})
	}
}

// A long message is cut on its way through serve, and only the copy is:
// the inbox record keeps the whole body.
func TestForwardLongMessageThroughServe(t *testing.T) {
	p, h, _ := forwardPair(t)
	before := h.count()
	long := strings.Repeat("a", 70000)
	id, _ := sendOK(t, p.hostDir, "--text", long, "ancan")
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	r, raw := h.post(t, before)
	if r.ID != id || !r.Truncated || len(r.Body) != 60002 || !bytes.Contains(raw, []byte(`"truncated":true`)) {
		t.Errorf("record of %d bytes, body %d, truncated %v", len(raw), len(r.Body), r.Truncated)
	}
	if rec := records(t, deliverDirOf(p.guestDir), "inbox")[id]; rec == nil || !bytes.Contains(rec, []byte(long)) {
		t.Error("the inbox record lost the long body")
	}
}

// A URL that keeps failing gets the first attempt and 20 retries, then the
// record goes with a log line.
func TestForwardDroppedAfterRetries(t *testing.T) {
	p, h, code := forwardPair(t)
	code.Store(http.StatusInternalServerError)
	before := h.count()
	id, _ := sendOK(t, p.hostDir, "--text", "lost", "ancan")
	var out string
	for range forwardRetries + 1 {
		out = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	}
	if h.count() != before+forwardRetries+1 {
		t.Fatalf("%d POSTs, want %d", h.count()-before, forwardRetries+1)
	}
	if want := fmt.Sprintf("forward zt: %s: answered 500 Internal Server Error; dropped after %d retries", id, forwardRetries); !strings.Contains(out, want) {
		t.Fatalf("no %q in:\n%s", want, out)
	}
	if q := forwardPending(t, p.guestDir); len(q) != 0 {
		t.Errorf("pending after the drop: %v", q)
	}
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != before+forwardRetries+1 {
		t.Errorf("POSTed after the drop")
	}
}

// A URL that never answers holds the round for one timeout, not one per
// record, and the journal line does not carry the forward secret.
func TestForwardDeadURLOneTimeout(t *testing.T) {
	p, h, code := forwardPair(t)
	code.Store(-1)
	const n = 8
	for i := range n {
		sendOK(t, p.hostDir, "--text", fmt.Sprint("m", i), "ancan")
	}
	sum := func() (total int) {
		for _, q := range forwardPending(t, p.guestDir) {
			total += forwardFailures(t, p.guestDir, strings.TrimSuffix(filepath.Base(q), ".json"))
		}
		return total
	}
	before := h.count()
	for round := 1; round <= 2; round++ {
		start := time.Now()
		out := mustOK(t, "serve", "--dir", p.guestDir, "--once")
		took := time.Since(start)
		if posts := h.count() - before; posts != round || took >= n/2*serviceTimeout {
			t.Errorf("round %d: %d POSTs in all, took %v", round, posts, took)
		}
		if strings.Contains(out, forwardSecret) {
			t.Errorf("the log carries the forward secret:\n%s", out)
		}
		if q := forwardPending(t, p.guestDir); len(q) != n || sum() != round {
			t.Errorf("round %d: %d pending, %d failures in all", round, len(q), sum())
		}
	}
}
