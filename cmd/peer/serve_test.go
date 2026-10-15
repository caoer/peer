package main

import (
	"bufio"
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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.mau.fi/libsignal/protocol"
	signal "go.mau.fi/libsignal/session"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// The test binary doubles as a second serving host: with PEER_SERVE_CHILD
// set it runs serveChild instead of the tests (U5's two-process pattern).
func TestMain(m *testing.M) {
	if os.Getenv("PEER_SERVE_CHILD") != "" {
		os.Exit(serveChild())
	}
	os.Exit(m.Run())
}

var sentRE = regexp.MustCompile(`(?m)^sent (\S+) to (\S+) \((\S+), #(\d+)\)$`)

// hostCfg is the host party's config: one agent, advisor, taking text and task.
func hostCfg() config {
	return config{
		Agents:  []card.Agent{{ID: "advisor", Accepts: []string{"text", "task"}}},
		Details: json.RawMessage(`{"advisor":{"type":"claude-code"}}`),
	}
}

// pair is a host (named "zt" by the guest) and a guest (named "ancan" by the
// host) that finished invite → accept → confirm and one serve each, so both
// hold the other's card with details and the host's cursor is past the
// guest's card.
type pair struct {
	hostDir, guestDir     string
	hostRoot, guestRoot   *keys.Root
	hostParty, guestParty string
	channel               string
}

func handshake(t *testing.T, hostDir, guestDir, base string) *pair {
	t.Helper()
	return handshakeNamed(t, hostDir, guestDir, base, "ancan", "zt")
}

// handshakeNamed is handshake with the petnames chosen: the host calls the
// guest guestName, the guest calls the host hostName.
func handshakeNamed(t *testing.T, hostDir, guestDir, base, guestName, hostName string) *pair {
	t.Helper()
	p := &pair{hostDir: hostDir, guestDir: guestDir, hostRoot: rootOf(t, hostDir), guestRoot: rootOf(t, guestDir)}
	p.hostParty, p.guestParty = keys.PartyID(p.hostRoot.Public()), keys.PartyID(p.guestRoot.Public())
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, guestName)
	link, _, _ := strings.Cut(out, "\n")
	l, err := invite.Parse(link, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.channel = l.Channel
	out = mustOK(t, "accept", "--dir", guestDir, "--name", hostName, link)
	code := codeRE.FindStringSubmatch(out)
	if code == nil {
		t.Fatalf("accept printed no code:\n%s", out)
	}
	mustOK(t, "confirm", "--dir", hostDir, "--code", code[1], guestName)
	// The guest's serve takes the host's details card and answers with its
	// own; the host's serve takes that one.
	out = mustOK(t, "serve", "--dir", guestDir, "--once")
	if !strings.Contains(out, "confirmed "+hostName+": their card with details is pinned, yours went out") {
		t.Fatalf("guest serve:\n%s", out)
	}
	out = mustOK(t, "serve", "--dir", hostDir, "--once")
	if !strings.Contains(out, "card from "+guestName+" pinned") {
		t.Fatalf("host serve:\n%s", out)
	}
	return p
}

// deliverDirOf is a peer directory's default delivery directory.
func deliverDirOf(dir string) string { return filepath.Join(dir, deliverDir) }

// records lists <dir>/<place>/*.md by message id.
func records(t *testing.T, dir string, place deliver.Place) map[string][]byte {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, string(place), "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(filepath.Base(n), ".md")] = b
	}
	return out
}

// parseRecord splits a record into its frontmatter (values and key order) and body.
func parseRecord(t *testing.T, b []byte) (map[string]string, []string, string) {
	t.Helper()
	s := string(b)
	if !strings.HasPrefix(s, "---\n") {
		t.Fatalf("record does not open with frontmatter:\n%s", s)
	}
	rest := s[4:]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		t.Fatalf("record frontmatter does not close:\n%s", s)
	}
	fm := map[string]string{}
	var order []string
	for _, line := range strings.Split(rest[:end], "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			t.Fatalf("frontmatter line %q", line)
		}
		fm[k] = v
		order = append(order, k)
	}
	return fm, order, rest[end+5:]
}

func sendOK(t *testing.T, dir string, args ...string) (id, to string) {
	t.Helper()
	out := mustOK(t, append([]string{"send", "--dir", dir}, args...)...)
	m := sentRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("send printed no receipt:\n%s", out)
	}
	return m[1], m[2]
}

// A message each way through the CLI: the inbox record carries exactly
// from, to, kind, verified, at and the body; a replayed envelope is refused
// and nothing born.
func TestSendServeBothWays(t *testing.T) {
	ctx := context.Background()
	srv, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)

	_, gch, gpe := channelOf(t, p.guestDir, "zt")
	if gpe.State != roster.Confirmed {
		t.Fatalf("guest state %s after serve, want confirmed", gpe.State)
	}
	if c, err := card.Verify(gch.Card(), p.hostRoot.Public()); err != nil || string(c.Details) != `{"advisor":{"type":"claude-code"}}` {
		t.Fatalf("guest holds the host's details card: %v %s", err, c.Details)
	}
	if rows := srv.Envelopes(p.channel, "g2h"); len(rows) != 2 || rows[0].Type != "prekey" || rows[1].Type != "msg" {
		t.Fatalf("relay g2h after the handshake: %+v", rows)
	}

	// Guest → host: text from the guest's legal agent to the host's advisor.
	start := time.Now().Add(-time.Second)
	id, to := sendOK(t, p.guestDir, "--kind", "text", "--from", "legal", "--text", "hello from legal", "zt/advisor")
	if to != p.hostParty+"/advisor" {
		t.Fatalf("sent to %s, want %s/advisor", to, p.hostParty)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "delivered text "+id+" → ") {
		t.Fatalf("host serve:\n%s", out)
	}
	inbox := records(t, deliverDirOf(p.hostDir), deliver.Inbox)
	rec, ok := inbox[id]
	if !ok || len(inbox) != 1 {
		t.Fatalf("host inbox holds %d records, %s present: %v", len(inbox), id, ok)
	}
	fm, order, body := parseRecord(t, rec)
	if strings.Join(order, " ") != "from to kind verified at" {
		t.Fatalf("frontmatter keys %v", order)
	}
	if fm["from"] != p.guestParty+"/legal" || fm["to"] != p.hostParty+"/advisor" || fm["kind"] != "text" || fm["verified"] != "true" {
		t.Fatalf("frontmatter %v", fm)
	}
	at, err := time.Parse(time.RFC3339Nano, fm["at"])
	if err != nil || at.Before(start) || at.After(time.Now()) {
		t.Fatalf("at %q: %v", fm["at"], err)
	}
	if body != "hello from legal" {
		t.Fatalf("body %q", body)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if !hch.Seen(id) || hch.Cursor() != 2 {
		t.Fatalf("host channel: seen %v cursor %d", hch.Seen(id), hch.Cursor())
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Quarantine)); n != 0 {
		t.Fatalf("%d records in quarantine", n)
	}

	// Host → guest: a task from a file, to the party itself, delivered into --deliver.
	f := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(f, []byte("# do\n\nthe thing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id2, to2 := sendOK(t, p.hostDir, "--kind", "task", "--from", "advisor", "--file", f, "ancan")
	if to2 != p.guestParty {
		t.Fatalf("sent to %s, want %s", to2, p.guestParty)
	}
	custom := filepath.Join(t.TempDir(), "mail")
	out = mustOK(t, "serve", "--dir", p.guestDir, "--deliver", custom, "--once")
	if !strings.Contains(out, "delivered task "+id2) {
		t.Fatalf("guest serve:\n%s", out)
	}
	fm, _, body = parseRecord(t, records(t, custom, deliver.Inbox)[id2])
	if fm["from"] != p.hostParty+"/advisor" || fm["to"] != p.guestParty || fm["kind"] != "task" || body != "# do\n\nthe thing\n" {
		t.Fatalf("task record %v %q", fm, body)
	}

	// The guest's text put a second time: the ratchet refuses the replay,
	// nothing is born, the cursor moves past it.
	rows := srv.Envelopes(p.channel, "g2h")
	env, err := envelope.FromWire(rows[len(rows)-1].Type, rows[len(rows)-1].Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Put(ctx, p.channel, gpe.Token, env); err != nil {
		t.Fatal(err)
	}
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "skip ancan #3: ") || strings.Contains(out, "delivered") {
		t.Fatalf("host serve on a replay:\n%s", out)
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Inbox)); n != 1 {
		t.Fatalf("replay born a record: %d in the inbox", n)
	}
	_, hch, _ = channelOf(t, p.hostDir, "ancan")
	if hch.Cursor() != 3 {
		t.Fatalf("cursor %d after the replay, want 3", hch.Cursor())
	}
	if out = mustOK(t, "serve", "--dir", p.hostDir, "--once"); out != "" {
		t.Fatalf("a quiet serve printed:\n%s", out)
	}
}

// doc and file land in quarantine; so does a kind the agent's row does not
// accept; a vendor kind to the party itself is the inbox.
func TestServeQuarantine(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	vendor := "vnd." + p.guestParty + ".ping"
	ids := map[string]string{}
	for kind, to := range map[string]string{"doc": "zt/advisor", "file": "zt/advisor", "question": "zt/advisor", vendor: "zt", "text": "zt/advisor"} {
		if isAttachment(kind) {
			f := filepath.Join(t.TempDir(), kind+".md")
			os.WriteFile(f, []byte("body of "+kind), 0o600)
			ids[kind], _ = sendOK(t, p.guestDir, "--kind", kind, "--file", f, to)
			continue
		}
		ids[kind], _ = sendOK(t, p.guestDir, "--kind", kind, "--text", "body of "+kind, to)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	q := records(t, deliverDirOf(p.hostDir), deliver.Quarantine)
	in := records(t, deliverDirOf(p.hostDir), deliver.Inbox)
	for _, kind := range []string{"doc", "file", "question"} {
		if _, ok := q[ids[kind]]; !ok {
			t.Errorf("%s is not in quarantine; serve said:\n%s", kind, out)
		}
		if !strings.Contains(out, "quarantined "+kind+" "+ids[kind]) {
			t.Errorf("serve did not report %s quarantined:\n%s", kind, out)
		}
	}
	for _, kind := range []string{vendor, "text"} {
		if _, ok := in[ids[kind]]; !ok {
			t.Errorf("%s is not in the inbox; serve said:\n%s", kind, out)
		}
	}
	if len(q) != 3 || len(in) != 2 {
		t.Fatalf("%d quarantined, %d in the inbox", len(q), len(in))
	}
	fm, _, _ := parseRecord(t, q[ids["doc"]])
	content, err := os.ReadFile(filepath.Join(deliverDirOf(p.hostDir), string(deliver.Quarantine), ids["doc"], "doc.md"))
	if fm["kind"] != "doc" || fm["verified"] != "true" || string(content) != "body of doc" {
		t.Fatalf("doc record %v, content %q %v", fm, content, err)
	}
}

// Refusals name their reason and keep nothing: no peer, no session yet, an
// unknown kind, a card through send; at serve an unknown kind or a forged
// from inside a real ciphertext is skipped, nothing born, the cursor past it.
func TestSendServeRefusals(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	hostDir := newDir(t, hostCfg())
	mustRefuse(t, "no peer named ancan", "send", "--dir", hostDir, "--text", "x", "ancan")
	mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	mustRefuse(t, "no session with ancan yet", "send", "--dir", hostDir, "--text", "x", "ancan")
	mustRefuse(t, "unknown message kind", "send", "--dir", hostDir, "--kind", "bogus", "--text", "x", "ancan")
	mustRefuse(t, "card publish", "send", "--dir", hostDir, "--kind", "card", "--text", "x", "ancan")
	hp, _ := openParty(hostDir)
	if es, _ := hp.outbox.Entries(); len(es) != 0 {
		t.Fatalf("a refused send left %d outbox entries", len(es))
	}

	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	gp, gch, gpe := channelOf(t, p.guestDir, "zt")
	gk, _ := gp.store.Keys(ctx)
	cipher := signal.NewCipher(signal.NewBuilder(gch, gk, gk, gch, session.Addr, keys.Serializer), session.Addr)
	putRaw := func(plain string) {
		t.Helper()
		ct, err := cipher.Encrypt(ctx, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		typ := envelope.Msg
		if ct.Type() == protocol.PREKEY_TYPE {
			typ = envelope.Prekey
		}
		if err := gch.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := rc.Put(ctx, p.channel, gpe.Token, envelope.Envelope{Type: typ, Body: ct.Serialize()}); err != nil {
			t.Fatal(err)
		}
	}
	other, _ := keys.GenerateRoot()
	putRaw(`{"v":1,"id":"bogus-kind","from":"` + p.guestParty + `","to":"` + p.hostParty + `","kind":"bogus","at":"2026-10-14T00:00:00Z","body":""}`)
	putRaw(`{"v":1,"id":"forged-from","from":"` + keys.PartyID(other.Public()) + `/x","to":"` + p.hostParty + `","kind":"text","at":"2026-10-14T00:00:00Z","body":""}`)
	putRaw(`{"v":1,"id":"../escape","from":"` + p.guestParty + `","to":"` + p.hostParty + `","kind":"text","at":"2026-10-14T00:00:00Z","body":""}`)
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	for _, want := range []string{"skip ancan #2: session: unknown message kind \"bogus\"", "skip ancan #3: from \"" + keys.PartyID(other.Public()) + "/x\" is not the channel's party", "skip ancan #4: message id \"../escape\" cannot name a file"} {
		if !strings.Contains(out, want) {
			t.Errorf("serve did not say %q:\n%s", want, out)
		}
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Inbox)) + len(records(t, deliverDirOf(p.hostDir), deliver.Quarantine)); n != 0 {
		t.Fatalf("%d records born from refused messages", n)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if hch.Cursor() != 4 {
		t.Fatalf("cursor %d, want 4", hch.Cursor())
	}
}

// Neither party holds its root key on the host that runs the handshake: the
// card every command sends is the one on the state (signed at init and card
// publish), the code and the proof take the party from identity.json, so
// invite, accept, confirm and the guest's answer card all run without
// root.json. The hosts' roots are removed after their card publish, and the
// details cards pinned on both sides are the ones the states hold.
func TestServeWithoutRootConfirms(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, config{})
	hostRoot := rootOf(t, hostDir)
	for _, dir := range []string{hostDir, guestDir} {
		if err := os.Remove(filepath.Join(dir, rootFile)); err != nil {
			t.Fatal(err)
		}
	}
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	l, _ := invite.Parse(link, time.Now())
	out = mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	mustOK(t, "confirm", "--dir", hostDir, "--code", codeRE.FindStringSubmatch(out)[1], "ancan")
	out = mustOK(t, "serve", "--dir", guestDir, "--once")
	if !strings.Contains(out, "confirmed zt: their card with details is pinned, yours went out") {
		t.Fatalf("guest serve without the root:\n%s", out)
	}
	gp, gch, gpe := channelOf(t, guestDir, "zt")
	if gpe.State != roster.Confirmed || gch.Cursor() != 1 {
		t.Fatalf("guest state %s cursor %d", gpe.State, gch.Cursor())
	}
	if c, err := card.Verify(gch.Card(), hostRoot.Public()); err != nil || len(c.Details) == 0 {
		t.Fatalf("the host's details card is not pinned: %v", err)
	}
	// What the guest answered with is its state's details card, not a fresh signature.
	own, _, announced, err := gp.ownCard(ctx, true)
	if err != nil || gch.Announced() != announced {
		t.Fatalf("guest card on the state: %v; announced %d, want %d", err, gch.Announced(), announced)
	}
	if rows := srv.Envelopes(l.Channel, "g2h"); len(rows) != 2 {
		t.Fatalf("the guest put %d envelopes, want its card and its answer", len(rows))
	}
	out = mustOK(t, "serve", "--dir", hostDir, "--once")
	if !strings.Contains(out, "card from ancan pinned") {
		t.Fatalf("host serve without the root:\n%s", out)
	}
	_, hch, _ := channelOf(t, hostDir, "ancan")
	if !bytes.Equal(hch.Card().Body, own.Body) {
		t.Fatal("the host pinned another card than the guest's state holds")
	}
	if out := mustOK(t, "serve", "--dir", guestDir, "--once"); out != "" {
		t.Fatalf("a second serve printed:\n%s", out)
	}
	// Without a card on the state, invite refuses with the publish rule.
	bare := filepath.Join(t.TempDir(), "bare")
	if _, err := initDir(bare); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(bare, stateDir)); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "no card on the state: run peer card publish where root.json is", "invite", "--dir", bare, "--relay", base, "--login", login, "x")
}

// flakyRelay fronts the fake relay and, when told, refuses every envelope put.
type flakyRelay struct {
	proxy      http.Handler
	refusePuts atomic.Bool
}

func (f *flakyRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.refusePuts.Load() && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/envelopes") {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"relay down (test)","code":"down"}`))
		return
	}
	f.proxy.ServeHTTP(w, r)
}

// A put that fails after the commit leaves the message in the outbox,
// committed; the next serve puts it, and the peer receives it once.
func TestOutboxReplayAfterPutFailure(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	fr := &flakyRelay{proxy: httputil.NewSingleHostReverseProxy(target)}
	proxy := httptest.NewServer(fr)
	t.Cleanup(proxy.Close)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), proxy.URL+"/peer")

	fr.refusePuts.Store(true)
	code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--text", "queued", "zt/advisor")
	m := regexp.MustCompile(`peer send: (\S+) is committed but the relay did not take it .*stays in the outbox`).FindStringSubmatch(errb)
	if code != 1 || m == nil {
		t.Fatalf("send with the relay down: exit %d, stderr %q", code, errb)
	}
	id := m[1]
	gp, _ := openParty(p.guestDir)
	es, _ := gp.outbox.Entries()
	if len(es) != 1 || es[0].ID != id || !es[0].Committed {
		t.Fatalf("outbox after the failed put: %+v", es)
	}
	if rows := srv.Envelopes(p.channel, "g2h"); len(rows) != 2 {
		t.Fatalf("the relay took %d envelopes", len(rows))
	}

	fr.refusePuts.Store(false)
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if es, _ := gp.outbox.Entries(); len(es) != 0 {
		t.Fatalf("outbox after serve: %+v", es)
	}
	if rows := srv.Envelopes(p.channel, "g2h"); len(rows) != 3 {
		t.Fatalf("the relay holds %d envelopes after the replay", len(rows))
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "delivered text "+id) {
		t.Fatalf("host serve:\n%s", out)
	}
	// Whatever is sent after the gap arrives too.
	id2, _ := sendOK(t, p.guestDir, "--text", "after the gap", "zt/advisor")
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "delivered text "+id2) {
		t.Fatalf("host serve:\n%s", out)
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Inbox)); n != 2 {
		t.Fatalf("%d records in the host inbox", n)
	}
}

// A host that dies after the commit and before the birth: the next start
// replays the spool and births the record once; a start after that births
// nothing.
func TestServeCrashAfterCommitReplaysOnce(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	id, _ := sendOK(t, p.guestDir, "--text", "survives the crash", "zt/advisor")

	sv, err := openServer(p.hostDir, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	sv.beforeBirth = func(*store.Entry) error { return errors.New("crash before birth") }
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err == nil || !strings.Contains(err.Error(), "crash before birth") {
		t.Fatalf("round: %v", err)
	}
	es, _ := sv.spool.Entries()
	if len(es) != 1 || es[0].ID != id || !es[0].Committed {
		t.Fatalf("spool after the crash: %+v", es)
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Inbox)); n != 0 {
		t.Fatalf("%d records born before the crash", n)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if !hch.Seen(id) || hch.Cursor() != 2 {
		t.Fatalf("the commit did not land: seen %v cursor %d", hch.Seen(id), hch.Cursor())
	}

	var log bytes.Buffer
	for i := 1; i <= 2; i++ {
		sv, err := openServer(p.hostDir, "", &log)
		if err != nil {
			t.Fatal(err)
		}
		if err := sv.start(ctx); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if err := sv.round(ctx); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	if n := strings.Count(log.String(), "delivered text "+id); n != 1 {
		t.Fatalf("replay delivered %d times:\n%s", n, log.String())
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Inbox)); n != 1 {
		t.Fatalf("%d records after the replay", n)
	}
	if es, _ := sv.spool.Entries(); len(es) != 0 {
		t.Fatalf("spool after the replay: %+v", es)
	}
}

// serveChild is the second process: one serve round on PEER_SERVE_DIR that
// stops before its first commit until the parent says go. With
// PEER_SERVE_ROUNDS=n the host stays up for n rounds, printing "up" and
// starting each round on a line from the parent.
func serveChild() int {
	ctx := context.Background()
	in := bufio.NewReader(os.Stdin)
	sv, err := openServer(os.Getenv("PEER_SERVE_DIR"), "", os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	paused := false
	sv.beforeCommit = func(*store.Entry) error {
		if paused {
			return nil
		}
		paused = true
		fmt.Println("ready")
		_, err := in.ReadString('\n')
		return err
	}
	if err := sv.start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	rounds, gated := 1, false
	if n := os.Getenv("PEER_SERVE_ROUNDS"); n != "" {
		if rounds, err = strconv.Atoi(n); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		gated = true
	}
	for i := 0; i < rounds; i++ {
		if gated {
			fmt.Println("up")
			if _, err := in.ReadString('\n'); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		}
		if err := sv.round(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("done")
	}
	return 0
}

type serveProc struct {
	cmd                  *exec.Cmd
	stdin                io.WriteCloser
	out                  *bufio.Reader
	delivered, conflicts int
}

func startServeChild(t *testing.T, dir string, env ...string) *serveProc {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(append(os.Environ(), env...), "PEER_SERVE_CHILD=1", "PEER_SERVE_DIR="+dir)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return &serveProc{cmd: cmd, stdin: stdin, out: bufio.NewReader(stdout)}
}

// readUntil consumes the child's lines, counting births and conflicts, until want.
func (c *serveProc) readUntil(t *testing.T, want string) {
	t.Helper()
	for {
		l, err := c.out.ReadString('\n')
		if err != nil {
			t.Fatalf("child output before %q: %v", want, err)
		}
		l = strings.TrimSpace(l)
		t.Logf("child %s: %s", filepath.Base(filepath.Dir(c.cmd.Env[len(c.cmd.Env)-1])), l)
		switch {
		case l == want:
			return
		case strings.HasPrefix(l, "delivered "):
			c.delivered++
		case strings.Contains(l, "another host advanced the state"):
			c.conflicts++
		}
	}
}

// secondHost is a second host of the party at dir: init's files and the
// config; its own spool, outbox and delivery directory; the state shared.
func secondHost(t *testing.T, dir string) string {
	t.Helper()
	host := filepath.Join(t.TempDir(), "peer")
	if err := os.MkdirAll(host, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{rootFile, identityFile, partyKeysFile, configFile} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(host, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return host
}

// Two OS processes serve the same channel on one shared state — the file
// backend and the pages backend — holding the same version when they
// commit: exactly one inbox birth per message, none lost, every spool
// empty (plan decision 5, the U8 verify: 两台主机共用一份状态时，每条消息恰好落一次，一条不丢).
func TestTwoHostsServeOneState(t *testing.T) {
	for _, kind := range []string{"file", "pages"} {
		t.Run(kind, func(t *testing.T) {
			_, _, base := relaytest.Start(t, login)
			cfg := hostCfg()
			switch kind {
			case "file":
				cfg.State.Dir = filepath.Join(t.TempDir(), "shared-state")
			case "pages":
				ps := pagestest.New("state-0123456789abcdef", "zt:token")
				t.Cleanup(ps.Close)
				cfg.State = stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}
			}
			p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
			var ids []string
			for i := 1; i <= 3; i++ {
				id, _ := sendOK(t, p.guestDir, "--text", fmt.Sprintf("message %d", i), "zt/advisor")
				ids = append(ids, id)
			}
			hostB := secondHost(t, p.hostDir)
			a, b := startServeChild(t, p.hostDir), startServeChild(t, hostB)
			// Both decrypted and spooled the first message from the same version.
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

			born := map[string]int{}
			for _, d := range []string{p.hostDir, hostB} {
				for id := range records(t, deliverDirOf(d), deliver.Inbox) {
					born[id]++
				}
				j, err := store.OpenJournal(filepath.Join(d, spoolDir))
				if err != nil {
					t.Fatal(err)
				}
				if es, _ := j.Entries(); len(es) != 0 {
					t.Errorf("%s: spool holds %+v", d, es)
				}
			}
			for _, id := range ids {
				if born[id] != 1 {
					t.Errorf("%s born %d times, want exactly once", id, born[id])
				}
			}
			if len(born) != 3 || a.delivered+b.delivered != 3 {
				t.Errorf("%d distinct records, children delivered %d+%d, want 3", len(born), a.delivered, b.delivered)
			}
			if a.conflicts+b.conflicts < 1 {
				t.Errorf("no commit conflicted: the hosts did not race")
			}
			_, hch, _ := channelOf(t, p.hostDir, "ancan")
			if hch.Cursor() != 4 {
				t.Errorf("cursor %d, want 4", hch.Cursor())
			}
			for _, id := range ids {
				if !hch.Seen(id) {
					t.Errorf("%s not in the shared seen set", id)
				}
			}
		})
	}
}

// The milestone-1 demo in one test: party A serves on two hosts sharing one
// state, party B on one, and one message goes each way while all three
// serve. Each message is born exactly once on its receiving side — on A once
// across both hosts, whose commits race — and both A hosts stay up through
// the exchange and serve a round after it.
func TestThreeHostsServeBothWays(t *testing.T) {
	for _, kind := range []string{"file", "pages"} {
		t.Run(kind, func(t *testing.T) {
			_, _, base := relaytest.Start(t, login)
			cfg := hostCfg()
			switch kind {
			case "file":
				cfg.State.Dir = filepath.Join(t.TempDir(), "shared-state")
			case "pages":
				ps := pagestest.New("state-0123456789abcdef", "zt:token")
				t.Cleanup(ps.Close)
				cfg.State = stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}
			}
			p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
			a2 := secondHost(t, p.hostDir)
			hosts := []*serveProc{
				startServeChild(t, p.hostDir, "PEER_SERVE_ROUNDS=2"),
				startServeChild(t, a2, "PEER_SERVE_ROUNDS=2"),
			}
			say := func(line string) {
				for _, c := range hosts {
					if _, err := io.WriteString(c.stdin, line+"\n"); err != nil {
						t.Fatal(err)
					}
				}
			}
			until := func(want string) {
				for _, c := range hosts {
					c.readUntil(t, want)
				}
			}
			until("up")

			// One message each way while A's hosts serve: B → A from B's one
			// host, A → B from A's second host.
			toA, _ := sendOK(t, p.guestDir, "--text", "hello from B", "zt/advisor")
			toB, _ := sendOK(t, a2, "--text", "hello from A", "ancan")

			// A's round: both hosts decrypt B's message from the same version
			// and commit together.
			say("round")
			until("ready")
			say("go")
			until("done")

			// B's host takes A's message.
			out := mustOK(t, "serve", "--dir", p.guestDir, "--once")
			if n := strings.Count(out, "delivered text "+toB+" → "); n != 1 {
				t.Errorf("B's serve delivered %s %d times, want once:\n%s", toB, n, out)
			}

			// A's hosts serve on after the exchange: a round each, then a clean exit.
			until("up")
			say("round")
			until("done")
			for _, c := range hosts {
				if err := c.cmd.Wait(); err != nil {
					t.Errorf("an A host went down: %v", err)
				}
			}

			bornA := map[string]int{}
			for _, d := range []string{p.hostDir, a2} {
				for id := range records(t, deliverDirOf(d), deliver.Inbox) {
					bornA[id]++
				}
			}
			if bornA[toA] != 1 || len(bornA) != 1 || hosts[0].delivered+hosts[1].delivered != 1 {
				t.Errorf("on A: %s born %d times across both hosts (%d distinct records, hosts delivered %d+%d), want exactly once",
					toA, bornA[toA], len(bornA), hosts[0].delivered, hosts[1].delivered)
			}
			bornB := records(t, deliverDirOf(p.guestDir), deliver.Inbox)
			if _, ok := bornB[toB]; !ok || len(bornB) != 1 {
				t.Errorf("on B: %s present %v among %d records, want born exactly once", toB, ok, len(bornB))
			}
			if hosts[0].conflicts+hosts[1].conflicts < 1 {
				t.Errorf("no commit conflicted: A's hosts did not race")
			}
		})
	}
}
