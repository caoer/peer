package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay"
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
	servingMu.Lock()
	servingBackends[dir] = sv.p.backend
	servingMu.Unlock()
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

// settle runs serve on the host until its socket is open and caught up —
// the first round pulls once; the socket opens at the cursor that pull left
// and the relay resumes it there, so the open pulls nothing — then sends a
// warm-up, which only its frame can deliver, and waits for that. It returns
// serve's output, the warm-up's id and the pulls answered so far.
func settle(t *testing.T, srv *relaytest.Server, p *pair) (*syncBuffer, string, int) {
	t.Helper()
	return settleEvery(t, srv, p, time.Hour)
}

// settleEvery is settle with rounds every every.
func settleEvery(t *testing.T, srv *relaytest.Server, p *pair, every time.Duration) (*syncBuffer, string, int) {
	t.Helper()
	pulls := srv.Pulls(p.channel, "g2h") + 1
	out := runServe(t, p.hostDir, every)
	waitFor(t, out, "ancan: push socket caught up", 1)
	if n := srv.Pulls(p.channel, "g2h"); n != pulls {
		t.Fatalf("the relay answered %d pulls by the socket's catch-up, want %d (the first round's)", n, pulls)
	}
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

// A socket closed mid-stream — a deploy — is opened again at the cursor and
// its catch-up carries what was put while it was down, with no pull; a frame
// lost on an open socket shows as a gap at the next frame and is pulled.
// Nothing is delivered twice.
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
	pulls := srv.Pulls(p.channel, "g2h")
	srv.NoPush(false)
	waitFor(t, out, "ancan: push socket caught up", 2)
	waitFor(t, out, "delivered text "+id2, 1)
	waitFor(t, out, "delivered text "+id3, 1)
	if n := srv.Pulls(p.channel, "g2h") - pulls; n != 0 {
		t.Fatalf("%d pulls on the resumed reconnect, want 0", n)
	}

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

// A round leaves a channel its open socket keeps current unpulled: rounds
// every few milliseconds cost the relay no pull, and a message still arrives
// by its frame.
func TestPushRoundRestsAnOpenSocket(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	out, id0, pulls := settleEvery(t, srv, p, 20*time.Millisecond)

	time.Sleep(300 * time.Millisecond) // about fifteen rounds
	if n := srv.Pulls(p.channel, "g2h") - pulls; n != 0 {
		t.Fatalf("%d pulls in rounds beside an open socket, want 0", n)
	}
	id1, _ := sendOK(t, p.guestDir, "--text", "pushed between rounds", "zt/advisor")
	waitFor(t, out, "delivered text "+id1, 1)
	time.Sleep(100 * time.Millisecond)
	if n := srv.Pulls(p.channel, "g2h") - pulls; n != 0 {
		t.Fatalf("%d pulls for a pushed frame between rounds, want 0", n)
	}
	deliveredOnce(t, out, p.hostDir, id0, id1)
}

// Once the socket closes and cannot open again, the next round pulls the
// channel, and what was put after the close is delivered once.
func TestPushRoundPullsAfterTheSocketCloses(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	out, id0, _ := settleEvery(t, srv, p, 50*time.Millisecond)

	srv.NoPush(true)
	srv.CloseSockets()
	waitFor(t, out, "ancan: no push socket (", 1)
	pulls := srv.Pulls(p.channel, "g2h")
	id1, _ := sendOK(t, p.guestDir, "--text", "after the close", "zt/advisor")
	waitFor(t, out, "delivered text "+id1, 1)
	if srv.Pulls(p.channel, "g2h") == pulls {
		t.Fatal("delivered without a pull, with no socket open")
	}
	deliveredOnce(t, out, p.hostDir, id0, id1)
}

// The rule a round rests by: an open socket, a last pull that read to the
// relay's end, and a cursor at or past every frame the socket carried.
func TestPushRests(t *testing.T) {
	k := pushKey{id: "c"}
	frame := func(seq int64) pushEvent { return pushEvent{kind: pushFrame, key: k, rec: relay.Record{Seq: seq}} }
	for _, tc := range []struct {
		name   string
		events []pushEvent
		atHead bool
		cursor int64
		want   bool
	}{
		{"open, pulled to the end", []pushEvent{{kind: pushOpen}}, true, -1, true},
		{"not open yet", nil, true, -1, false},
		{"open, last pull short of the end", []pushEvent{{kind: pushOpen}}, false, -1, false},
		{"frame taken", []pushEvent{{kind: pushOpen}, frame(4)}, true, 4, true},
		{"frame left untaken", []pushEvent{{kind: pushOpen}, frame(4)}, true, 3, false},
		{"closed", []pushEvent{{kind: pushOpen}, {kind: pushClosed}}, true, -1, false},
		{"down", []pushEvent{{kind: pushOpen}, {kind: pushDown}}, true, -1, false},
		{"refused for good", []pushEvent{{kind: pushOpen}, {kind: pushGone}}, true, -1, false},
		{"open again", []pushEvent{{kind: pushOpen}, {kind: pushClosed}, {kind: pushOpen}}, true, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := &pusher{socks: map[pushKey]*pushSocket{k: {seen: -1}}}
			for _, ev := range tc.events {
				ps.socks[k].note(ev)
			}
			ps.pulled(k, tc.atHead)
			if got := ps.rests(k, tc.cursor); got != tc.want {
				t.Fatalf("rests = %v, want %v", got, tc.want)
			}
		})
	}
	var none *pusher
	if none.rests(k, 0) {
		t.Fatal("rests without a pusher (--once)")
	}
	none.pulled(k, true)
}
