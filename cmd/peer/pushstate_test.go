package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// pageHost is a host whose state is a fake ccc-pages page, as the fleet's is.
func pageHost(t *testing.T) (*pagestest.Server, config) {
	t.Helper()
	ps := pagestest.New("peer-state-0123456789abcdef", "zt:owner-secret")
	t.Cleanup(ps.Close)
	cfg := hostCfg()
	cfg.State = stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}
	return ps, cfg
}

// waitTrue polls cond for up to 15 s.
func waitTrue(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// stateLive waits until serve's state backend answers from its live socket.
func stateLive(t *testing.T, ps *pagestest.Server) {
	t.Helper()
	waitTrue(t, "the state page's live socket", func() bool { return ps.LiveSockets() == 1 })
	// The hello is the socket's first frame; one round of reads after it
	// shows nothing is read any more.
	before := ps.Gets("")
	waitTrue(t, "reads to stop", func() bool {
		time.Sleep(60 * time.Millisecond)
		n := ps.Gets("")
		defer func() { before = n }()
		return n == before
	})
}

// Push: rounds every 20 ms, a channel envelope and another host's roster
// change all reach a serving host with no read of the state page and no
// pull of the relay: the envelope as a relay frame, the roster change as a
// live frame.
func TestPushStateAndEnvelopeReadNothing(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	ps, cfg := pageHost(t)
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	out, id0, pulls := settleEvery(t, srv, p, 20*time.Millisecond)
	stateLive(t, ps)
	gets := ps.Gets("")

	time.Sleep(300 * time.Millisecond) // about fifteen rounds
	id1, _ := sendOK(t, p.guestDir, "--text", "pushed", "zt/advisor")
	waitFor(t, out, "delivered text "+id1, 1)
	if n := ps.Gets("") - gets; n != 0 {
		t.Errorf("%d state page reads by rounds and a pushed envelope, want 0", n)
	}

	// Another host of the party writes the roster; serve's state sees it.
	other, err := openParty(p.hostDir)
	if err != nil {
		t.Fatal(err)
	}
	mark := roster.Peer{Name: "other-host", Channel: "ab" + p.channel[2:], Relay: base, Side: roster.Host, Token: "t", State: roster.Invited}
	if err := roster.Update(context.Background(), other.backend, func(r *roster.Roster) error { r.Set(mark); return nil }); err != nil {
		t.Fatal(err)
	}
	afterWrite := ps.Gets("")
	sv := serving(t, p.hostDir)
	waitTrue(t, "the roster change on serve's state", func() bool {
		r, err := roster.Load(context.Background(), sv)
		return err == nil && r.ByName("other-host") != nil
	})
	time.Sleep(100 * time.Millisecond)

	if n := srv.Pulls(p.channel, "g2h") - pulls; n != 0 {
		t.Errorf("%d relay pulls, want 0", n)
	}
	if n := ps.Gets("") - afterWrite; n != 0 {
		t.Errorf("%d state page reads after the other host's write, want 0", n)
	}
	deliveredOnce(t, out, p.hostDir, id0, id1)
}

// servingBackends is each serve loop's state backend by its directory,
// recorded by serveLoop.
var (
	servingMu       sync.Mutex
	servingBackends = map[string]store.Backend{}
)

// serving is the state backend a serve loop on dir holds: the most recent
// one serveLoop opened.
func serving(t *testing.T, dir string) store.Backend {
	t.Helper()
	servingMu.Lock()
	defer servingMu.Unlock()
	b := servingBackends[dir]
	if b == nil {
		t.Fatalf("no serve loop on %s", dir)
	}
	return b
}

// Resume: a deploy drops the relay socket and the state page's socket;
// what was put while they were down arrives on the reconnect as the relay
// socket's catch-up, and the state comes back as the page's delta — no
// pull, no roster read, no channel record read.
func TestPushResumeReadsOnlyWhatIsMissing(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	ps, cfg := pageHost(t)
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	out, id0, pulls := settle(t, srv, p)
	stateLive(t, ps)

	srv.NoPush(true)
	srv.CloseSockets()
	ps.CloseLive()
	waitFor(t, out, "ancan: no push socket (", 1)
	id1, _ := sendOK(t, p.guestDir, "--text", "during the deploy", "zt/advisor")
	id2, _ := sendOK(t, p.guestDir, "--text", "still during it", "zt/advisor")
	waitTrue(t, "the state socket to resume", func() bool {
		_, resumed := ps.Upgrades()
		return resumed == 1 && ps.LiveSockets() == 1
	})
	gets := ps.Gets("")
	srv.NoPush(false)
	waitFor(t, out, "ancan: push socket open, resuming", 2)
	waitFor(t, out, "delivered text "+id1, 1)
	waitFor(t, out, "delivered text "+id2, 1)
	waitFor(t, out, "ancan: push socket caught up", 2)

	if n := srv.Pulls(p.channel, "g2h") - pulls; n != 0 {
		t.Errorf("%d relay pulls on the reconnect, want 0", n)
	}
	if n := ps.Gets("") - gets; n != 0 {
		t.Errorf("%d state page reads on the reconnect (peers %d, channel %d), want 0", n, ps.Gets(roster.Key), ps.Gets(store.ChannelKey(p.channel)))
	}
	deliveredOnce(t, out, p.hostDir, id0, id1, id2)
}

// Compat, new client against an old relay: a socket the relay does not
// resume is pulled on its open, as before, and nothing is lost or doubled.
func TestPushOldRelayPullsOnOpen(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	srv.NoResume(true)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	pulls := srv.Pulls(p.channel, "g2h")
	out := runServe(t, p.hostDir, time.Hour)
	waitFor(t, out, "ancan: push socket open\n", 1)
	waitPulls(t, srv, p, pulls+2) // the first round's and the open's
	if s := out.String(); strings.Contains(s, "resuming") || strings.Contains(s, "caught up") {
		t.Fatalf("an old relay's socket taken as resumed:\n%s", s)
	}

	srv.NoPush(true)
	srv.CloseSockets()
	waitFor(t, out, "ancan: no push socket (", 1)
	id1, _ := sendOK(t, p.guestDir, "--text", "during the deploy", "zt/advisor")
	srv.NoPush(false)
	waitFor(t, out, "ancan: push socket open\n", 2)
	waitFor(t, out, "delivered text "+id1, 1)
	deliveredOnce(t, out, p.hostDir, id1)
}

// Compat, new client against a page service without live sockets: every
// read goes to the page, as before, and messages arrive.
func TestPushStateWithoutLiveReadsThePage(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	ps, cfg := pageHost(t)
	ps.NoLive(true)
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	out, id0, _ := settle(t, srv, p)
	gets := ps.Gets("")
	id1, _ := sendOK(t, p.guestDir, "--text", "pushed", "zt/advisor")
	waitFor(t, out, "delivered text "+id1, 1)
	if ps.Gets("") == gets {
		t.Fatal("a frame taken with no state read and no live socket")
	}
	waitFor(t, out, "state page: live socket down (", 1)
	deliveredOnce(t, out, p.hostDir, id0, id1)
}
