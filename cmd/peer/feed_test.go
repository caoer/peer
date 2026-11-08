package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/e2e"
	"github.com/caoer/peer/internal/feed/feedtest"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay/relaytest"
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
// feed admitting feedSecret and the reader token feedToken, its state in a
// shared directory so a second host can serve it; fwd, when set, is its
// forward too.
func feedPair(t *testing.T, only string, fwd *forwardConfig) (*pair, *feedtest.Server) {
	t.Helper()
	_, _, base := relaytest.Start(t, login)
	cfg := config{State: stateConfig{Dir: filepath.Join(t.TempDir(), "shared-state")}}
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, cfg)
	party := keys.PartyID(rootOf(t, guestDir).Public())
	s := feedtest.Start(t, party, feedSecret, feedToken)
	trustFeed(t, s)
	cfg.Feed = &feedConfig{URL: s.URL, Secret: feedSecret, Only: only}
	cfg.Forward = fwd
	if err := os.WriteFile(filepath.Join(guestDir, configFile), mustJSON(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return handshake(t, hostDir, guestDir, base), s
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
	if n := strings.Count(out1.String()+out2.String(), "peer reader key pending for "+p.guestParty+": peer e2e publish on the root machine"); n != 1 {
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

// A feed whose url is not https, whose secret is missing, or whose only is
// not e2e refuses to load, naming the key.
func TestFeedConfigRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ raw, want string }{
		"http":      {`{"url":"http://x","secret":"s"}`, "feed.url"},
		"no secret": {`{"url":"https://x"}`, "secret"},
		"only":      {`{"url":"https://x","secret":"s","only":"plain"}`, "feed.only"},
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
