package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// A serve child trusts the test's TLS service through PEER_SERVICE_CA, the
// certificate's PEM file (the parent sets serviceClient itself).
func init() {
	f := os.Getenv("PEER_SERVICE_CA")
	if f == "" {
		return
	}
	b, err := os.ReadFile(f)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)
	serviceClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
}

// hookServer is a service: answer is called with the 1-based count of POSTs
// it has had and returns the status; every POST is kept.
type hookServer struct {
	*httptest.Server
	mu     sync.Mutex
	posts  [][]byte
	ctypes []string
}

func newHook(t *testing.T, answer func(n int, r *http.Request) int) *hookServer {
	t.Helper()
	h := &hookServer{}
	h.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.posts = append(h.posts, b)
		h.ctypes = append(h.ctypes, r.Header.Get("Content-Type"))
		n := len(h.posts)
		h.mu.Unlock()
		if code := answer(n, r); code != 0 {
			w.WriteHeader(code)
		}
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hookServer) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.posts)
}

// trustHooks points serviceClient at the test's TLS certificate — every
// httptest TLS server serves the same one — and shortens the POST timeout,
// both restored at the end of the test.
func trustHooks(t *testing.T, h *hookServer) {
	t.Helper()
	client, timeout := serviceClient, serviceTimeout
	serviceClient = &http.Client{Transport: h.Client().Transport, CheckRedirect: client.CheckRedirect}
	serviceTimeout = 300 * time.Millisecond
	t.Cleanup(func() { serviceClient, serviceTimeout = client, timeout })
}

// serviceMap writes a map at root with the leader seat and one service row
// per label → URL, each taking text.
func serviceMap(t *testing.T, root string, hooks map[string]string) {
	t.Helper()
	serviceMapAccepts(t, root, "text", hooks)
}

// serviceMapAccepts is serviceMap with every service row taking accepts.
func serviceMapAccepts(t *testing.T, root, accepts string, hooks map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# Seats\n\n| label | to | accepts |\n|---|---|---|\n")
	b.WriteString("| leader | [[" + uccSession + "/rosters/leader-peer-v1]] | text |\n")
	for label, u := range hooks {
		fmt.Fprintf(&b, "| %s | service %s | %s |\n", label, u, accepts)
	}
	if err := os.WriteFile(filepath.Join(root, "peers", "seats.md"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func serviceQueue(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, serviceDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// A service row is a callback: the record's five keys and body POSTed as
// JSON once, 2xx the delivery. A 500 then a 200 is delivered on the second
// round, one POST a round. A URL that never answers is tried each round up
// to ucc.serviceRetries, then becomes a local quarantine record naming the
// URL and the error — the cursor long past it, the channel's later message
// delivered in the first round. Nothing is born under the root for a
// service.
func TestServeUCCService(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	hook := newHook(t, func(int, *http.Request) int { return http.StatusOK })
	flaky := newHook(t, func(n int, _ *http.Request) int {
		if n == 1 {
			return http.StatusInternalServerError
		}
		return http.StatusOK
	})
	dead := newHook(t, func(_ int, r *http.Request) int { <-r.Context().Done(); return 0 })
	trustHooks(t, hook)

	root := uccRoot(t)
	serviceMap(t, root, map[string]string{"hook": hook.URL + "/peer/hook", "flaky": flaky.URL, "dead": dead.URL})
	cfg := uccCfg(root)
	cfg.UCC.ServiceRetries = 2
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)

	ids := map[string]string{}
	for _, l := range []string{"hook", "flaky", "dead", "leader"} {
		ids[l], _ = sendOK(t, p.guestDir, "--text", "body of "+l, "zt/"+l)
	}

	// Round 1: hook delivered, flaky and dead queued, the leader's message
	// behind them delivered.
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "delivered text "+ids["hook"]+" → "+hook.URL+"/peer/hook") {
		t.Errorf("hook not reported delivered:\n%s", out)
	}
	if hook.count() != 1 || hook.ctypes[0] != "application/json" {
		t.Fatalf("hook had %d POSTs (%v), want one application/json", hook.count(), hook.ctypes)
	}
	t.Logf("POST body: %s", hook.posts[0])
	var post map[string]any
	if err := json.Unmarshal(hook.posts[0], &post); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range post {
		keys = append(keys, k)
	}
	at, _ := post["at"].(string)
	if _, err := time.Parse(time.RFC3339Nano, at); err != nil || len(post) != 6 ||
		post["from"] != p.guestParty || post["to"] != p.hostParty+"/hook" || post["kind"] != "text" ||
		post["verified"] != true || post["body"] != "body of hook" {
		t.Errorf("POST body %s: keys %v", hook.posts[0], keys)
	}
	if !strings.Contains(out, "retry 1 of 2 next round") || flaky.count() != 1 || dead.count() != 1 {
		t.Errorf("flaky %d, dead %d POSTs after round 1:\n%s", flaky.count(), dead.count(), out)
	}
	if _, ok := sessionRecords(t, root, deliver.Inbox)[ids["leader"]]; !ok {
		t.Errorf("the leader's message behind the failed POSTs was not delivered:\n%s", out)
	}
	if _, hch, _ := channelOf(t, p.hostDir, "ancan"); hch.Cursor() != 5 {
		t.Errorf("cursor %d after round 1, want 5", hch.Cursor())
	}
	if q := serviceQueue(t, p.hostDir); len(q) != 2 {
		t.Errorf("service queue %v, want flaky and dead", q)
	}

	// Round 2: flaky's second POST lands; dead fails its first retry.
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "delivered text "+ids["flaky"]+" → "+flaky.URL) || flaky.count() != 2 {
		t.Errorf("flaky not delivered on round 2 (%d POSTs):\n%s", flaky.count(), out)
	}
	if hook.count() != 1 || dead.count() != 2 || !strings.Contains(out, "retry 2 of 2 next round") {
		t.Errorf("round 2: hook %d, dead %d POSTs:\n%s", hook.count(), dead.count(), out)
	}

	// Round 3: dead's last retry fails — the local quarantine record.
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if dead.count() != 3 || flaky.count() != 2 {
		t.Errorf("round 3: dead %d, flaky %d POSTs", dead.count(), flaky.count())
	}
	rec, ok := records(t, deliverDirOf(p.hostDir), deliver.Quarantine)[ids["dead"]]
	if !ok {
		t.Fatalf("no local quarantine record for dead:\n%s", out)
	}
	fm, _, body := parseRecord(t, rec)
	if fm["to"] != p.hostParty+"/dead" || !strings.HasPrefix(body, "body of dead\n\nnot delivered to "+dead.URL+": ") {
		t.Errorf("quarantine record %v:\n%s", fm, body)
	}
	if q := serviceQueue(t, p.hostDir); len(q) != 0 {
		t.Errorf("service queue %v after the quarantine", q)
	}
	for _, l := range []string{"hook", "flaky", "dead"} {
		if bornAnywhere(t, root, ids[l]) {
			t.Errorf("%s was born under the root", l)
		}
	}

	// Round 4: nothing left to do.
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); strings.Contains(out, "delivered") || dead.count() != 3 {
		t.Errorf("round 4 did something (dead %d POSTs):\n%s", dead.count(), out)
	}
}

// A doc or file whose service retries are spent is a local quarantine record
// with its descriptor first and the reason last, so peer fetch <id> — the
// retry its status line names — fetches the content once the blob is whole.
func TestServeServiceQuarantineFetches(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	hook := newHook(t, func(int, *http.Request) int { return http.StatusInternalServerError })
	trustHooks(t, hook)
	root := uccRoot(t)
	serviceMapAccepts(t, root, "text file", map[string]string{"hook": hook.URL})
	cfg := uccCfg(root)
	cfg.UCC.ServiceRetries = 1
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	path, data := writeFile(t, "notes.txt", 4096)
	id, _ := sendOK(t, p.guestDir, "--kind", "file", "--file", path, "zt/hook")
	blobID := srv.Blobs(p.channel)[0]
	orig := srv.Blob(p.channel, blobID)
	bad := append([]byte(nil), orig...)
	bad[10] ^= 0x80 // stands in for any fetch failure: relay 5xx, deploy, timeout
	srv.SetBlob(p.channel, blobID, bad)

	mustOK(t, "serve", "--dir", p.hostDir, "--once") // the POST fails: queued
	mustOK(t, "serve", "--dir", p.hostDir, "--once") // its one retry fails: quarantined
	rec, ok := records(t, deliverDirOf(p.hostDir), deliver.Quarantine)[id]
	if !ok {
		t.Fatal("no local quarantine record")
	}
	if _, body := descriptorOf(t, rec); !strings.HasSuffix(body, "; peer fetch "+id+" tries again\n\nnot delivered to "+hook.URL+": answered 500 Internal Server Error\n") {
		t.Errorf("record body:\n%s", body)
	}
	srv.SetBlob(p.channel, blobID, orig) // the relay is healthy again
	mustOK(t, "fetch", "--dir", p.hostDir, id)
	got, err := os.ReadFile(filepath.Join(deliverDirOf(p.hostDir), string(deliver.Quarantine), id, "notes.txt"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("peer fetch kept %d bytes: %v", len(got), err)
	}
}

// A doc or file posted to a service row with its content not fetched is
// also a local quarantine record, so peer fetch <id> — the retry the posted
// body names — fetches the content once the relay is healthy. One whose
// content was fetched is posted and has no record.
func TestServeServiceUnfetchedAttachmentFetches(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	hook := newHook(t, func(int, *http.Request) int { return http.StatusOK })
	trustHooks(t, hook)
	root := uccRoot(t)
	serviceMapAccepts(t, root, "text file", map[string]string{"hook": hook.URL})
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)
	path, data := writeFile(t, "notes.txt", 4096)
	id, _ := sendOK(t, p.guestDir, "--kind", "file", "--file", path, "zt/hook")
	blobID := srv.Blobs(p.channel)[0]
	orig := srv.Blob(p.channel, blobID)
	bad := append([]byte(nil), orig...)
	bad[10] ^= 0x80 // stands in for any fetch failure: relay 5xx, deploy, timeout
	srv.SetBlob(p.channel, blobID, bad)
	fetchedPath, _ := writeFile(t, "fetched.txt", 4096)
	fetched, _ := sendOK(t, p.guestDir, "--kind", "file", "--file", fetchedPath, "zt/hook")

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if hook.count() != 2 || !strings.Contains(string(hook.posts[0]), "peer fetch "+id+" tries again") {
		t.Fatalf("hook posts %d: %s", hook.count(), hook.posts)
	}
	recs := records(t, deliverDirOf(p.hostDir), deliver.Quarantine)
	if _, ok := recs[fetched]; ok {
		t.Errorf("the file whose content was fetched has a local record:\n%s", out)
	}
	rec, ok := recs[id]
	if !ok {
		t.Fatalf("no local quarantine record for the file not fetched:\n%s", out)
	}
	if _, body := descriptorOf(t, rec); !strings.HasSuffix(body, "tries again\n\ncontent not fetched; the record was posted to "+hook.URL+"\n") {
		t.Errorf("record body:\n%s", body)
	}
	srv.SetBlob(p.channel, blobID, orig) // the relay is healthy again
	mustOK(t, "fetch", "--dir", p.hostDir, id)
	got, err := os.ReadFile(filepath.Join(deliverDirOf(p.hostDir), string(deliver.Quarantine), id, "notes.txt"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("peer fetch kept %d bytes: %v", len(got), err)
	}
}

// A URL whose queued POST fails is not tried again in the round: one that
// never answers holds the round, and the leader's message behind it, for
// one timeout, not one per queued message; the rest of its queue keeps its
// failure counts for the next round.
func TestServeServiceQueueSkipsAFailedURL(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	dead := newHook(t, func(_ int, r *http.Request) int { <-r.Context().Done(); return 0 })
	trustHooks(t, dead)
	root := uccRoot(t)
	serviceMap(t, root, map[string]string{"dead": dead.URL})
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)
	const n = 8
	for i := range n {
		sendOK(t, p.guestDir, "--text", fmt.Sprint("m", i), "zt/dead")
	}
	mustOK(t, "serve", "--dir", p.hostDir, "--once") // each of the n POSTs fails: queued
	if q := serviceQueue(t, p.hostDir); len(q) != n {
		t.Fatalf("service queue %d, want %d", len(q), n)
	}
	id, _ := sendOK(t, p.guestDir, "--text", "urgent", "zt/leader")
	start := time.Now()
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	took := time.Since(start)
	if !strings.Contains(out, id) {
		t.Fatalf("the leader's message was not delivered:\n%s", out)
	}
	if posts := dead.count() - n; posts != 1 || took >= n/2*serviceTimeout {
		t.Errorf("the round made %d POSTs to the dead URL in %v, want one, about one %v timeout", posts, took, serviceTimeout)
	}
	var failures []int
	for _, q := range serviceQueue(t, p.hostDir) {
		var e serviceEntry
		b, err := os.ReadFile(q)
		if err == nil {
			err = json.Unmarshal(b, &e)
		}
		if err != nil {
			t.Fatal(err)
		}
		failures = append(failures, e.Failures)
	}
	slices.Sort(failures)
	if want := append(slices.Repeat([]int{1}, n-1), 2); !slices.Equal(failures, want) {
		t.Errorf("failure counts %v, want %v", failures, want)
	}
}

// Two OS processes serve one shared state (the file backend): one POST per
// message, none lost, both spools and queues empty.
func TestTwoHostsServeService(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	hook := newHook(t, func(int, *http.Request) int { return http.StatusOK })
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hook.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PEER_SERVICE_CA", ca)

	root := uccRoot(t)
	serviceMap(t, root, map[string]string{"hook": hook.URL})
	cfg := uccCfg(root)
	cfg.State.Dir = filepath.Join(t.TempDir(), "shared-state")
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	for i := 1; i <= 3; i++ {
		sendOK(t, p.guestDir, "--text", fmt.Sprintf("message %d", i), "zt/hook")
	}
	hostB := filepath.Join(t.TempDir(), "peer")
	if err := os.MkdirAll(hostB, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{rootFile, identityFile, partyKeysFile, configFile} {
		b, err := os.ReadFile(filepath.Join(p.hostDir, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(hostB, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, b := startServeChild(t, p.hostDir), startServeChild(t, hostB)
	a.readUntil(t, "ready")
	b.readUntil(t, "ready")
	for _, c := range []*serveProc{a, b} {
		if _, err := io.WriteString(c.stdin, "go\n"); err != nil {
			t.Fatal(err)
		}
	}
	a.readUntil(t, "done")
	b.readUntil(t, "done")
	for _, c := range []*serveProc{a, b} {
		if err := c.cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}

	var bodies []string
	for _, raw := range hook.posts {
		var post struct{ Body string }
		if err := json.Unmarshal(raw, &post); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, post.Body)
	}
	if want := []string{"message 1", "message 2", "message 3"}; !reflect.DeepEqual(bodies, want) {
		t.Errorf("POSTs %q, want each message once, in order", bodies)
	}
	if a.delivered+b.delivered != 3 || a.conflicts+b.conflicts < 1 {
		t.Errorf("children delivered %d+%d with %d conflicts, want 3 and a race", a.delivered, b.delivered, a.conflicts+b.conflicts)
	}
	for _, d := range []string{p.hostDir, hostB} {
		if q := serviceQueue(t, d); len(q) != 0 {
			t.Errorf("%s: service queue %v", d, q)
		}
	}
	if _, hch, _ := channelOf(t, p.hostDir, "ancan"); hch.Cursor() != 4 {
		t.Errorf("cursor %d, want 4", hch.Cursor())
	}
}

// A bare human names no seat to relay to: the whole map is refused, serve
// does not open, and nothing is consumed.
func TestServeUCCBareHuman(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	root := uccRoot(t)
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)
	id, _ := sendOK(t, p.guestDir, "--kind", "question", "--text", "hello", "zt/zt")
	bare := "# Seats\n\n| label | to | accepts |\n|---|---|---|\n| zt | human | text question answer |\n"
	if err := os.WriteFile(filepath.Join(root, "peers", "seats.md"), []byte(bare), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, `label "zt": to "human" is none of`, "serve", "--dir", p.hostDir, "--once")
	if bornAnywhere(t, root, id) {
		t.Error("born under a refused map")
	}
	writeSeats(t, root) // channelOf opens the party, which reads the map
	if _, hch, _ := channelOf(t, p.hostDir, "ancan"); hch.Cursor() != 1 {
		t.Errorf("cursor %d, want 1: nothing consumed", hch.Cursor())
	}
}
