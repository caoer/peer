package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/e2e"
	"github.com/caoer/peer/internal/feed"
	"github.com/caoer/peer/internal/feed/feedtest"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/timeline"
)

const (
	feedSecret = "feed-source-secret-0123456789abcdefghijklmn"
	feedToken  = "feed-reader-token-0123456789abcdefghijklmnop"
)

// fedRecord is a frame's record: the timeline data and its truncated mark.
type fedRecord struct {
	timeline.Record
	Truncated bool `json:"truncated"`
}

// fedFrame is one frame as a source sends it or a viewer receives it.
type fedFrame struct {
	Rec        *fedRecord `json:"rec"`
	N          *int64     `json:"n"`
	To         string     `json:"to"`
	ReplayDone string     `json:"replay_done"`
	Readers    []string   `json:"readers"`
}

func parseFeedFrame(t *testing.T, b []byte) fedFrame {
	t.Helper()
	var f fedFrame
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return f
}

// viewerNext is the viewer's next frame, or the test fails after a while.
func viewerNext(t *testing.T, v *feedtest.Viewer) fedFrame {
	t.Helper()
	select {
	case b, ok := <-v.Frames:
		if !ok {
			t.Fatal("the viewer's socket closed")
		}
		return parseFeedFrame(t, b)
	case <-time.After(5 * time.Second):
		t.Fatal("no frame reached the viewer")
	}
	return fedFrame{}
}

// trustFeed points serviceClient at the test's TLS certificate — every
// httptest TLS server serves the same one, so a forward hook is trusted too —
// and bounds a flush, both restored at the end of the test.
func trustFeed(t *testing.T, s *feedtest.Server) {
	t.Helper()
	client, timeout := serviceClient, serviceTimeout
	serviceClient = &http.Client{Transport: s.Client().Transport, CheckRedirect: client.CheckRedirect}
	serviceTimeout = 3 * time.Second
	t.Cleanup(func() { serviceClient, serviceTimeout = client, timeout })
}

// feedPair is a handshake whose guest ("ancan") feeds its messages to a fake
// feed admitting feedSecret and the reader token feedToken — both seeded on
// the fake and in the guest's feed record, as peer feed setup and link leave
// them — its state in a shared directory so a second host can serve it; fwd,
// when set, is its forward too.
func feedPair(t *testing.T, only string, fwd *forwardConfig) (*pair, *feedtest.Server) {
	t.Helper()
	_, _, base := relaytest.Start(t, login)
	cfg := config{State: stateConfig{Dir: filepath.Join(t.TempDir(), "shared-state")}}
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, cfg)
	party := keys.PartyID(rootOf(t, guestDir).Public())
	s := feedtest.Start(t, party, feedSecret, feedToken)
	trustFeed(t, s)
	cfg.Feed = &feedConfig{URL: s.URL, Only: only}
	cfg.Forward = fwd
	if err := os.WriteFile(filepath.Join(guestDir, configFile), mustJSON(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	seedFeed(t, guestDir, feedSecret, feedToken)
	return handshake(t, hostDir, guestDir, base), s
}

// seedFeed writes the feed record under dir as peer feed setup and link
// leave it: the source secret and one reader per token.
func seedFeed(t *testing.T, dir, secret string, tokens ...string) {
	t.Helper()
	p, err := openParty(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := p.store.Feed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.Source = secret
	for i, tok := range tokens {
		f.Readers = append(f.Readers, store.FeedReader{Hash: feedtest.Hash(tok), Label: fmt.Sprintf("reader-%d", i+1), At: feed.At(time.Now())})
	}
	if err := f.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// fleetHost is another machine of the party under dir as a fleet host is:
// identity, party keys and config, no root.json.
func fleetHost(t *testing.T, dir string) string {
	t.Helper()
	host := filepath.Join(t.TempDir(), "peer")
	if err := os.MkdirAll(host, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{identityFile, partyKeysFile, configFile} {
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

// liveServer is a serve of dir with its feed socket open, as a running serve
// holds it; its journal is out.
func liveServer(t *testing.T, dir string, out io.Writer) *server {
	t.Helper()
	sv, err := openServer(dir, "", out)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sv.p.feedStop)
	return sv
}

func waitSources(t *testing.T, s *feedtest.Server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.Sources() != n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Sources() != n {
		t.Fatalf("%d sources, want %d", s.Sources(), n)
	}
}

// The U13 check. A received message is a frame to the viewer and a sent one
// a frame and the local out- record; a viewer with a key connecting to two
// hosts has each replay what it holds, in at order, ending with replay_done
// and the card's readers, and leaves the key in readers-pending once; peer
// e2e publish on the root directory moves it onto the card, where the peer's
// status lists it, and clears the record; peer e2e revoke takes it off.
func TestFeedLiveReplayAndReaderKey(t *testing.T) {
	ctx := context.Background()
	p, s := feedPair(t, "", nil)
	before := len(s.Frames())

	v, _, err := s.Connect(ctx, feedToken, "")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := sendOK(t, p.hostDir, "--text", "hello", "ancan")
	code, _, errb := cmd(t, "serve", "--dir", p.guestDir, "--once")
	if code != 0 || !strings.Contains(errb, "feed: "+s.URL+"\n") {
		t.Fatalf("serve: exit %d, stderr %q", code, errb)
	}
	fr := s.Frames()
	if len(fr) != before+1 {
		t.Fatalf("%d frames after the receive, want one", len(fr)-before)
	}
	if f := parseFeedFrame(t, fr[before].Body); f.Rec == nil || f.Rec.ID != id || f.Rec.Dir != timeline.In || string(f.Rec.Body) != `"hello"` || f.N == nil || f.To != "" {
		t.Fatalf("frame %s", fr[before].Body)
	}
	if f := viewerNext(t, v); f.Rec == nil || f.Rec.ID != id || f.N != nil {
		t.Fatalf("viewer got %+v", f)
	}

	sid, _ := sendOK(t, p.guestDir, "--text", "back", "zt")
	local, err := filepath.Glob(filepath.Join(p.guestDir, feedDir, "zt", "out-*.json"))
	if err != nil || len(local) != 1 {
		t.Fatalf("local records %v %v", local, err)
	}
	var rec timeline.Record
	b, err := os.ReadFile(local[0])
	if err == nil {
		err = json.Unmarshal(b, &rec)
	}
	if err != nil || rec.ID != sid || rec.Dir != timeline.Out || string(rec.Body) != `"back"` || rec.To != p.hostParty {
		t.Fatalf("local record %s: %v", b, err)
	}
	if st, _ := os.Stat(local[0]); st.Mode().Perm() != 0o600 {
		t.Errorf("local record mode %v", st.Mode().Perm())
	}
	if fr := s.Frames(); len(fr) != before+2 || parseFeedFrame(t, fr[before+1].Body).Rec.ID != sid {
		t.Fatalf("frames after the send: %d", len(fr)-before)
	}
	if f := viewerNext(t, v); f.Rec == nil || f.Rec.ID != sid || f.Rec.Dir != timeline.Out {
		t.Fatalf("viewer got %+v", f)
	}
	v.Close()

	var out1, out2 bytes.Buffer
	sv1 := liveServer(t, p.guestDir, &out1)
	sv2 := liveServer(t, secondHost(t, p.guestDir), &out2)
	waitSources(t, s, 2)
	pub, _, err := e2e.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v2, _, err := s.Connect(ctx, feedToken, pub)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	var replayed []string
	for done := 0; done < 2; {
		f := viewerNext(t, v2)
		switch {
		case f.ReplayDone != "":
			done++
			if f.Readers == nil || len(f.Readers) != 0 {
				t.Errorf("replay_done readers %v, want none yet", f.Readers)
			}
		case f.Rec != nil && f.To != "":
			replayed = append(replayed, f.Rec.ID+" "+f.Rec.Dir)
		default:
			t.Fatalf("frame %+v", f)
		}
	}
	// The first host holds the inbox record and the local record; the second
	// host, serving the same state from its own directory, holds neither.
	if want := id + " in " + sid + " out"; strings.Join(replayed, " ") != want {
		t.Fatalf("replayed %v", replayed)
	}
	sv1.p.feedStop()
	sv2.p.feedStop()
	pending, _, err := sv1.p.loadPendingReaders(ctx)
	if err != nil || len(pending.Keys) != 1 || pending.Keys[0].Key != pub || pending.Keys[0].Reader != feedtest.Hash(feedToken) {
		t.Fatalf("readers-pending %+v: %v", pending, err)
	}
	if n := strings.Count(out1.String()+out2.String(), "peer reader key pending for "+p.guestParty+": peer e2e publish where root.json is"); n != 1 {
		t.Fatalf("%d wake lines:\n%s%s", n, out1.String(), out2.String())
	}

	out := procOK(t, "e2e", "publish", "--dir", p.guestDir)
	if !strings.Contains(out, "details.readers takes "+pub) || !strings.Contains(out, "card published to zt") {
		t.Fatalf("publish:\n%s", out)
	}
	procOK(t, "serve", "--dir", p.hostDir, "--once")
	var rows []statusJSON
	if err := json.Unmarshal([]byte(procOK(t, "status", "--dir", p.hostDir, "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].Readers) != 1 || rows[0].Readers[0] != pub {
		t.Fatalf("status: %+v", rows)
	}
	if pending, _, err = sv1.p.loadPendingReaders(ctx); err != nil || len(pending.Keys) != 0 {
		t.Fatalf("readers-pending after the publish %+v: %v", pending, err)
	}
	if out := procOK(t, "e2e", "publish", "--dir", p.guestDir); !strings.Contains(out, "no reader key pending") {
		t.Fatalf("publish with nothing pending:\n%s", out)
	}

	// A live host now answers a replay with the card's readers.
	sv3 := liveServer(t, p.guestDir, io.Discard)
	waitSources(t, s, 1)
	v3, _, err := s.Connect(ctx, feedToken, "")
	if err != nil {
		t.Fatal(err)
	}
	defer v3.Close()
	for {
		if f := viewerNext(t, v3); f.ReplayDone != "" {
			if len(f.Readers) != 1 || f.Readers[0] != pub {
				t.Fatalf("replay_done readers %v", f.Readers)
			}
			break
		}
	}
	sv3.p.feedStop()

	if out := procOK(t, "e2e", "revoke", "--dir", p.guestDir, pub); !strings.Contains(out, "no longer names "+pub) {
		t.Fatalf("revoke:\n%s", out)
	}
	procOK(t, "serve", "--dir", p.hostDir, "--once")
	var after []statusJSON
	if err := json.Unmarshal([]byte(procOK(t, "status", "--dir", p.hostDir, "--json")), &after); err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || len(after[0].Readers) != 0 {
		t.Fatalf("status after the revoke: %+v", after)
	}
	if code, _, errb := peerProc(t, "e2e", "revoke", "--dir", p.guestDir, pub); code != 1 || !strings.Contains(errb, "is not in") {
		t.Fatalf("revoking a key not on the card: exit %d: %s", code, errb)
	}
}

// With feed.only e2e a plain message is forwarded but not fed, in either
// direction, and an encrypted one is fed; the local record is kept either way.
func TestFeedOnlyE2E(t *testing.T) {
	h := newHook(t, func(int, *http.Request) int { return http.StatusOK })
	p, s := feedPair(t, feedOnlyE2E, &forwardConfig{URL: h.URL, Secret: forwardSecret})
	before, posts := len(s.Frames()), h.count()

	sendOK(t, p.hostDir, "--text", "plain", "ancan")
	code, _, errb := cmd(t, "serve", "--dir", p.guestDir, "--once")
	if code != 0 || !strings.Contains(errb, "feed: "+s.URL+" · only e2e\n") {
		t.Fatalf("serve: exit %d, stderr %q", code, errb)
	}
	if h.count() != posts+1 || len(s.Frames()) != before {
		t.Fatalf("%d POSTs and %d frames for a plain message; want one and none", h.count()-posts, len(s.Frames())-before)
	}
	sendOK(t, p.guestDir, "--text", "plain back", "zt")
	if local, _ := filepath.Glob(filepath.Join(p.guestDir, feedDir, "zt", "out-*.json")); len(local) != 1 {
		t.Fatalf("local records %v", local)
	}
	if h.count() != posts+2 || len(s.Frames()) != before {
		t.Fatalf("%d POSTs and %d frames after a plain send; want two and none", h.count()-posts, len(s.Frames())-before)
	}

	pub, _, err := e2e.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := sendOK(t, p.hostDir, "--encrypt", "--to-key", pub, "--text", "sealed", "ancan")
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	fr := s.Frames()
	if len(fr) != before+1 {
		t.Fatalf("%d frames for an encrypted message, want one", len(fr)-before)
	}
	if f := parseFeedFrame(t, fr[before].Body); f.Rec == nil || f.Rec.ID != id || !f.Rec.E2E {
		t.Fatalf("frame %s", fr[before].Body)
	}
}

// A feed whose url is not https or whose only is not e2e refuses to load,
// naming the key.
func TestFeedConfigRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ raw, want string }{
		"http": {`{"url":"http://x"}`, "feed.url"},
		"only": {`{"url":"https://x","only":"plain"}`, "feed.only"},
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
			top["feed"] = json.RawMessage(tc.raw)
			if err := os.WriteFile(path, mustJSON(t, top), 0o600); err != nil {
				t.Fatal(err)
			}
			if code, _, errb := cmd(t, "status", "--dir", dir); code != 1 || !strings.Contains(errb, tc.want) {
				t.Fatalf("exit %d: %s", code, errb)
			}
		})
	}
}

// The U13 check's mint on any machine (decision 33): peer feed setup on one
// fleet host of the party and peer feed link on another, neither holding
// root.json, both taken by the fake under the card; show on the first lists
// the second's link; a serve dials with the record's secret and the link's
// page receives the frames; revoke refuses the page at its next hello; setup
// again refuses, --reset mints a new secret the next serve dials with.
func TestFeedSetupLinkOnAnyMachine(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	cfg := config{State: stateConfig{Dir: filepath.Join(t.TempDir(), "shared-state")}}
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, cfg)
	party := keys.PartyID(rootOf(t, guestDir).Public())
	s := feedtest.Start(t, party, "")
	trustFeed(t, s)
	cfg.Feed = &feedConfig{URL: s.URL}
	if err := os.WriteFile(filepath.Join(guestDir, configFile), mustJSON(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	p := handshake(t, hostDir, guestDir, base)
	h1, h2 := fleetHost(t, guestDir), fleetHost(t, guestDir)
	for _, h := range []string{h1, h2} {
		if _, err := os.Stat(filepath.Join(h, rootFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s holds %s", h, rootFile)
		}
	}

	// Before the setup: a link refuses, show and serve say so, nothing is fed.
	if code, _, errb := cmd(t, "feed", "link", "--dir", h1); code != 1 || !strings.Contains(errb, "not set up — peer feed setup on any machine of this party") {
		t.Fatalf("link before setup: exit %d: %s", code, errb)
	}
	if out := mustOK(t, "feed", "show", "--dir", h1); !strings.Contains(out, feedNotSetUp) {
		t.Fatalf("show before setup:\n%s", out)
	}
	sendOK(t, p.hostDir, "--text", "early", "ancan")
	if code, out, errb := cmd(t, "serve", "--dir", h1, "--once"); code != 0 || !strings.Contains(errb, feedNotSetUp+"\n") || !strings.Contains(out, feedNotSetUp+"\n") {
		t.Fatalf("serve before setup: exit %d\n%s%s", code, out, errb)
	}
	if n := len(s.Frames()); n != 0 {
		t.Fatalf("%d frames before the setup", n)
	}

	out := mustOK(t, "feed", "setup", "--dir", h1)
	if !strings.Contains(out, "feed set up for "+party+" at "+s.URL+"\n") {
		t.Fatalf("setup:\n%s", out)
	}
	held := s.Config()
	if held == nil || held.Party != party || len(held.Readers) != 0 || !strings.HasPrefix(held.Source, "sha256:") {
		t.Fatalf("held %+v", held)
	}
	if code, _, errb := cmd(t, "feed", "setup", "--dir", h2); code != 1 || !strings.Contains(errb, "the feed is set up, 0 reader links") {
		t.Fatalf("setup again: exit %d: %s", code, errb)
	}

	out = mustOK(t, "feed", "link", "--dir", h2, "--label", "phone")
	link, rest, _ := strings.Cut(out, "\n")
	prefix := s.URL + "/#p=" + party + "&t="
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("link %q", link)
	}
	token := strings.TrimPrefix(link, prefix)
	if len(token) != 43 || strings.Contains(rest, token) {
		t.Fatalf("token %q, printed once: %q", token, rest)
	}
	if !strings.Contains(rest, "reader phone · "+feedtest.Hash(token)) {
		t.Fatalf("link's second line %q", rest)
	}
	if held = s.Config(); len(held.Readers) != 1 || held.Readers[0] != feedtest.Hash(token) {
		t.Fatalf("held after the link %+v", held)
	}
	out = mustOK(t, "feed", "show", "--dir", h1, "--remote")
	if !strings.Contains(out, "1 reader links\n  phone · "+feedtest.Hash(token)) || !strings.Contains(out, "worker: at "+held.At+" · source "+held.Source+" · 1 readers") || strings.Contains(out, "not on the worker") {
		t.Fatalf("show --remote:\n%s", out)
	}

	// A serve on the first host dials with the record's secret; the link's
	// page gets the frame.
	v, _, err := s.Connect(ctx, token, "")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := sendOK(t, p.hostDir, "--text", "hello", "ancan")
	if code, _, errb := cmd(t, "serve", "--dir", h1, "--once"); code != 0 || !strings.Contains(errb, "feed: "+s.URL+"\n") {
		t.Fatalf("serve: exit %d, stderr %q", code, errb)
	}
	if f := viewerNext(t, v); f.Rec == nil || f.Rec.ID != id || f.Rec.Dir != timeline.In {
		t.Fatalf("viewer got %+v", f)
	}
	v.Close()

	// Revoke on the first host: the page's next hello is refused.
	if code, _, errb := cmd(t, "feed", "revoke", "--dir", h1, "nobody"); code != 1 || !strings.Contains(errb, `no reader link is "nobody"`) {
		t.Fatalf("revoke nobody: exit %d: %s", code, errb)
	}
	if out := mustOK(t, "feed", "revoke", "--dir", h1, "phone"); !strings.Contains(out, "revoked phone · "+feedtest.Hash(token)) {
		t.Fatalf("revoke:\n%s", out)
	}
	if held = s.Config(); len(held.Readers) != 0 {
		t.Fatalf("held after the revoke %+v", held)
	}
	refused := s.Refused()
	if _, _, err := s.Connect(ctx, token, ""); err == nil || s.Refused() != refused+1 {
		t.Fatalf("a revoked token connected: %v", err)
	}
	if out := mustOK(t, "feed", "link", "--dir", h1, "--label", "laptop"); !strings.Contains(out, "reader laptop · ") {
		t.Fatalf("link by hash prefix setup:\n%s", out)
	}
	hash := s.Config().Readers[0]
	if out := mustOK(t, "feed", "revoke", "--dir", h2, strings.TrimPrefix(hash, "sha256:")[:12]); !strings.Contains(out, "revoked laptop · "+hash) {
		t.Fatalf("revoke by hash prefix:\n%s", out)
	}

	// --reset: a new source secret the next serve dials with; the old one is
	// refused.
	oldSource := s.Config().Source
	out = mustOK(t, "feed", "setup", "--dir", h2, "--reset")
	if !strings.Contains(out, "new source secret") || s.Config().Source == oldSource {
		t.Fatalf("reset:\n%s\nheld %+v", out, s.Config())
	}
	refused, before := s.Refused(), len(s.Frames())
	sendOK(t, p.hostDir, "--text", "after the reset", "ancan")
	mustOK(t, "serve", "--dir", h1, "--once")
	if s.Refused() != refused || len(s.Frames()) != before+1 {
		t.Fatalf("after the reset: %d refused, %d frames", s.Refused()-refused, len(s.Frames())-before)
	}
}

// The fake verifies a config request as the worker does: the card under the
// party id, the body under the card's current identity key. A body signed by
// the root key, by another identity key, or under another party's card is
// refused; an equal at is stale; a GET under the delegation reads the config.
func TestFeedConfigDelegation(t *testing.T) {
	ctx := context.Background()
	a, b := newDir(t, config{}), newDir(t, config{})
	pa, err := openParty(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := openParty(b)
	if err != nil {
		t.Fatal(err)
	}
	s := feedtest.Start(t, pa.partyID(), "")
	client := s.Client()
	cardA, _, _, err := pa.ownCard(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	cardB, _, _, err := pb.ownCard(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := func(at time.Time) *feed.Config {
		return &feed.Config{V: 1, Party: pa.partyID(), At: feed.At(at), Source: feedtest.Hash("s"), Readers: []string{feedtest.Hash("t")}}
	}
	refused := func(err error, status int, code string) {
		t.Helper()
		var r *feed.Refusal
		if !errors.As(err, &r) || r.Status != status || r.Code != code {
			t.Fatalf("want %d %s, got %v", status, code, err)
		}
	}
	now := time.Now()
	dA := feed.NewDelegation(cardA, pa.id)
	if err := feed.PutConfig(ctx, client, s.URL, pa.partyID(), cfg(now), dA); err != nil {
		t.Fatal(err)
	}
	if h := s.Config(); h == nil || h.Source != feedtest.Hash("s") || len(h.Readers) != 1 || h.At != feed.At(now) {
		t.Fatalf("held %+v", h)
	}
	if err := feed.PutConfig(ctx, client, s.URL, pa.partyID(), cfg(now), dA); !errors.Is(err, feed.ErrStale) {
		t.Fatalf("the same at again: %v", err)
	}
	later := now.Add(time.Second)
	refused(feed.PutConfig(ctx, client, s.URL, pa.partyID(), cfg(later), feed.NewDelegation(cardA, pb.id)), 401, "bad_signature")
	refused(feed.PutConfig(ctx, client, s.URL, pa.partyID(), cfg(later), feed.NewDelegation(cardB, pb.id)), 401, "bad_card")
	refused(feed.PutConfig(ctx, client, s.URL, pa.partyID(), cfg(now.Add(10*time.Minute)), dA), 401, "stale")
	body := mustJSON(t, cfg(later))
	req, err := http.NewRequest(http.MethodPut, s.URL+"/feed/"+pa.partyID()+"/config", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(feed.CardHeader, dA.Card())
	req.Header.Set(feed.SignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootOf(t, a).Key, body)))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a root-signed body: %s", resp.Status)
	}
	if s.Puts() != 1 {
		t.Fatalf("%d configs taken, want the first alone", s.Puts())
	}

	c, err := feed.GetConfig(ctx, client, s.URL, pa.partyID(), time.Now(), dA)
	if err != nil || c.Party != pa.partyID() || c.Source != feedtest.Hash("s") || c.At != feed.At(now) {
		t.Fatalf("GET %+v: %v", c, err)
	}
	_, err = feed.GetConfig(ctx, client, s.URL, pa.partyID(), time.Now(), feed.NewDelegation(cardA, pb.id))
	refused(err, 401, "bad_signature")
	s2 := feedtest.Start(t, pb.partyID(), "")
	if _, err := feed.GetConfig(ctx, s2.Client(), s2.URL, pb.partyID(), time.Now(), feed.NewDelegation(cardB, pb.id)); !errors.Is(err, feed.ErrNoConfig) {
		t.Fatalf("GET with no config: %v", err)
	}
}

// updateFixture rewrites the fixture the worker's sign.spec.ts verifies.
var updateFixture = flag.Bool("update", false, "rewrite worker/test/fixtures/config-signed.json from a test party")

// fixturePath is the one fixture both sides verify (plan-delivery § Identifiers,
// Feed config; its shape agreed with U18).
const fixturePath = "../../worker/test/fixtures/config-signed.json"

// configFixture is a PUT body with the identity key's signature over it, the
// X-Peer-Card value, and a GET's X-Peer-At with its signature.
type configFixture struct {
	Party       string `json:"party"`
	Body        string `json:"body"`
	Card        string `json:"card"`
	Signature   string `json:"signature"`
	At          string `json:"at"`
	AtSignature string `json:"atSignature"`
}

// The fixture verifies in Go as it does on the worker: the card under its
// party, the body and the at under the card's identity key; a changed body
// does not. -update writes it from a fresh test party.
func TestFeedConfigFixture(t *testing.T) {
	if *updateFixture {
		dir := newDir(t, config{})
		p, err := openParty(dir)
		if err != nil {
			t.Fatal(err)
		}
		public, _, _, err := p.ownCard(context.Background(), false)
		if err != nil {
			t.Fatal(err)
		}
		d := feed.NewDelegation(public, p.id)
		body := mustJSON(t, feed.Config{V: 1, Party: p.partyID(), At: "2026-11-08T16:00:00.000Z", Source: feedtest.Hash("fixture-source-secret"), Readers: []string{feedtest.Hash("fixture-reader-token-1"), feedtest.Hash("fixture-reader-token-2")}})
		at := "2026-11-08T16:00:30.000Z"
		fx := configFixture{Party: p.partyID(), Body: string(body), Card: d.Card(), Signature: d.Sign(body), At: at, AtSignature: d.Sign([]byte(at))}
		b, err := json.MarshalIndent(fx, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixturePath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fx configFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	if err := feedtest.Verify(fx.Party, fx.Card, fx.Signature, []byte(fx.Body)); err != nil {
		t.Fatalf("the body's signature: %v", err)
	}
	if err := feedtest.Verify(fx.Party, fx.Card, fx.AtSignature, []byte(fx.At)); err != nil {
		t.Fatalf("the at's signature: %v", err)
	}
	var c feed.Config
	if err := json.Unmarshal([]byte(fx.Body), &c); err != nil || c.V != 1 || c.Party != fx.Party || c.Source == "" || len(c.Readers) == 0 {
		t.Fatalf("body %+v: %v", c, err)
	}
	if err := feedtest.Verify(fx.Party, fx.Card, fx.Signature, []byte(fx.Body+" ")); err == nil {
		t.Fatal("a changed body verified")
	}
	if err := feedtest.Verify(fx.Party, fx.Card, fx.AtSignature, []byte(fx.Body)); err == nil {
		t.Fatal("the at's signature verified the body")
	}
}
