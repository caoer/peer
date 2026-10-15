package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// syncBuffer is serve's output, read by the test while the loop writes it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// runServe runs serve's loop on dir, as peer serve --every every does, until
// the test ends; reconnects back off in milliseconds.
func runServe(t *testing.T, dir string, every time.Duration) *syncBuffer {
	t.Helper()
	fastBackoff(t)
	return serveLoop(t, dir, every)
}

// fastBackoff makes reconnects back off in milliseconds until the test ends;
// set once before any loop starts, as the loops read it.
func fastBackoff(t *testing.T) {
	oldMin, oldMax := backoffMin, backoffMax
	backoffMin, backoffMax = 10*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { backoffMin, backoffMax = oldMin, oldMax })
}

// serveLoop runs serve's loop on dir until the test ends.
func serveLoop(t *testing.T, dir string, every time.Duration) *syncBuffer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	sv, err := openServer(dir, "", out)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan int)
	go func() { done <- sv.loop(ctx, every, false, out) }()
	t.Cleanup(func() {
		cancel()
		if code := <-done; code != 0 {
			t.Errorf("serve loop exit %d", code)
		}
		t.Logf("serve output:\n%s", out)
	})
	return out
}

// waitFor waits until s appears n times in serve's output.
func waitFor(t *testing.T, out *syncBuffer, s string, n int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for strings.Count(out.String(), s) < n {
		if time.Now().After(deadline) {
			t.Fatalf("serve output holds %q %d times, want %d:\n%s", s, strings.Count(out.String(), s), n, out)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// deliveredOnce checks each id was delivered by exactly one birth and is in
// the host's inbox, which holds those ids alone.
func deliveredOnce(t *testing.T, out *syncBuffer, hostDir string, ids ...string) {
	t.Helper()
	inbox := records(t, deliverDirOf(hostDir), deliver.Inbox)
	for _, id := range ids {
		if n := strings.Count(out.String(), "delivered text "+id+" → "); n != 1 {
			t.Errorf("%s delivered %d times", id, n)
		}
		if _, ok := inbox[id]; !ok {
			t.Errorf("%s not in the inbox", id)
		}
	}
	if len(inbox) != len(ids) {
		t.Errorf("inbox holds %d records, want %d", len(inbox), len(ids))
	}
}

// waitPulls waits until the relay has answered n pulls of the host's rows.
func waitPulls(t *testing.T, srv *relaytest.Server, p *pair, n int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for srv.Pulls(p.channel, "g2h") < n {
		if time.Now().After(deadline) {
			t.Fatalf("the relay answered %d pulls, want %d", srv.Pulls(p.channel, "g2h"), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settle runs serve on the host until its socket is open and the open's pull
// has answered — nothing waits on the relay, so the first round pulls once
// and the open once more — then sends a warm-up, which only its frame can
// deliver, and waits for that. It returns serve's output, the warm-up's id
// and the pulls answered so far. The "delivered" line alone is no sign the
// open's pull is done: a warm-up put before that pull is read by it, and
// the pull's last, empty, GET comes after the line.
func settle(t *testing.T, srv *relaytest.Server, p *pair) (*syncBuffer, string, int) {
	t.Helper()
	pulls := srv.Pulls(p.channel, "g2h") + 2
	out := runServe(t, p.hostDir, time.Hour)
	waitFor(t, out, "ancan: push socket open", 1)
	waitPulls(t, srv, p, pulls)
	id, _ := sendOK(t, p.guestDir, "--text", "warm-up", "zt/advisor")
	waitFor(t, out, "delivered text "+id, 1)
	return out, id, srv.Pulls(p.channel, "g2h")
}

// A pushed frame is delivered once, by the frame: no pull runs for it.
func TestPushDeliversAFrameOnce(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	out, id0, pulls := settle(t, srv, p)

	id1, _ := sendOK(t, p.guestDir, "--text", "pushed one", "zt/advisor")
	waitFor(t, out, "delivered text "+id1, 1)
	id2, _ := sendOK(t, p.guestDir, "--text", "pushed two", "zt/advisor")
	waitFor(t, out, "delivered text "+id2, 1)
	if n := srv.Pulls(p.channel, "g2h"); n != pulls {
		t.Fatalf("%d pulls for two pushed frames, want none", n-pulls)
	}
	deliveredOnce(t, out, p.hostDir, id0, id1, id2)
}

// A socket closed mid-stream — a deploy — is opened again and the pull on
// the reconnect reads what was put while it was down; a frame lost on an
// open socket shows as a gap at the next frame and is pulled. Nothing is
// delivered twice.
func TestPushReconnectPullsTheGap(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	out := runServe(t, p.hostDir, time.Hour)
	waitFor(t, out, "ancan: push socket open", 1)

	id1, _ := sendOK(t, p.guestDir, "--text", "before the deploy", "zt/advisor")
	waitFor(t, out, "delivered text "+id1, 1)

	// The deploy closes every socket and the new Object is not up yet.
	srv.NoPush(true)
	srv.CloseSockets()
	waitFor(t, out, "ancan: push socket closed (", 1)
	waitFor(t, out, "ancan: no push socket (", 1)
	id2, _ := sendOK(t, p.guestDir, "--text", "during the deploy", "zt/advisor")
	id3, _ := sendOK(t, p.guestDir, "--text", "still during it", "zt/advisor")
	srv.NoPush(false)
	waitFor(t, out, "ancan: push socket open", 2)
	waitFor(t, out, "delivered text "+id2, 1)
	waitFor(t, out, "delivered text "+id3, 1)

	// A frame lost on the open socket: the next one is past the cursor's
	// next seq, and the pull reads both.
	srv.DropPushes(1)
	id4, _ := sendOK(t, p.guestDir, "--text", "its frame is lost", "zt/advisor")
	id5, _ := sendOK(t, p.guestDir, "--text", "its frame shows the gap", "zt/advisor")
	waitFor(t, out, "delivered text "+id5, 1)
	waitFor(t, out, "delivered text "+id4, 1)

	deliveredOnce(t, out, p.hostDir, id1, id2, id3, id4, id5)
}

// push.pullEvery frames make one pull, and fewer make none.
func TestPushPullsAfterEveryNFrames(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	cfg := hostCfg()
	cfg.Push.PullEvery = 3
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	// The warm-up is the cycle's first frame.
	out, id0, pulls := settle(t, srv, p)
	ids := []string{id0}

	send := func(text string) {
		id, _ := sendOK(t, p.guestDir, "--text", text, "zt/advisor")
		waitFor(t, out, "delivered text "+id, 1)
		ids = append(ids, id)
	}
	send("the second frame")
	if n := srv.Pulls(p.channel, "g2h") - pulls; n != 0 {
		t.Fatalf("%d pulls after 2 frames with push.pullEvery 3, want 0", n)
	}
	send("the third frame")
	// The third frame's pull runs after its "delivered" line: a fourth put
	// before that pull is read by it, at two GETs, and its frame is then a
	// duplicate. The next cycle's first frame is sent once the pull answered.
	waitPulls(t, srv, p, pulls+1)
	send("the fourth frame")
	if n := srv.Pulls(p.channel, "g2h") - pulls; n != 1 {
		t.Fatalf("%d pulls after 4 frames with push.pullEvery 3, want 1", n)
	}
	deliveredOnce(t, out, p.hostDir, ids...)
}

// A relay that never answers the upgrade leaves serve pulling every round,
// and says so once.
func TestPushAbsentServePulls(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	srv.NoPush(true)
	out := runServe(t, p.hostDir, 100*time.Millisecond)
	waitFor(t, out, "ancan: no push socket (", 1)
	id, _ := sendOK(t, p.guestDir, "--text", "pulled", "zt/advisor")
	waitFor(t, out, "delivered text "+id, 1)
	time.Sleep(300 * time.Millisecond) // more rounds and failed upgrades
	if s := out.String(); strings.Contains(s, "push socket open") || strings.Count(s, "no push socket") != 1 {
		t.Fatalf("serve output without push:\n%s", s)
	}
	deliveredOnce(t, out, p.hostDir, id)
}
