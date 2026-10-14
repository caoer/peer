package main

import (
	"context"
	"io"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/store"
)

// A running serve — the deployment shape, serve --every — replays the outbox
// every round, not only at its start: a message whose put failed after its
// commit goes out without a new command, as peer send promises.
func TestRunningServeReplaysTheOutbox(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	fr := &flakyRelay{proxy: httputil.NewSingleHostReverseProxy(target)}
	proxy := httptest.NewServer(fr)
	t.Cleanup(proxy.Close)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), proxy.URL+"/peer")

	sv, err := openServer(p.guestDir, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	before := len(srv.Envelopes(p.channel, "g2h"))

	fr.refusePuts.Store(true)
	code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--text", "queued while the relay was down", "zt/advisor")
	m := regexp.MustCompile(`peer send: (\S+) is committed but the relay did not take it`).FindStringSubmatch(errb)
	if code != 1 || m == nil {
		t.Fatalf("send with the relay refusing puts: exit %d, stderr %q", code, errb)
	}
	id := m[1]
	fr.refusePuts.Store(false)

	// The loop runs on, with no new command: one round is enough.
	if err := sv.round(ctx); err != nil {
		t.Fatal(err)
	}
	if es, _ := sv.p.outbox.Entries(); len(es) != 0 {
		t.Fatalf("outbox after a round of the running serve: %+v", es)
	}
	if n := len(srv.Envelopes(p.channel, "g2h")); n != before+1 {
		t.Fatalf("the relay holds %d g2h rows, want %d", n, before+1)
	}
	if log := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(log, "delivered text "+id) {
		t.Fatalf("host serve:\n%s", log)
	}
}

// An entry the relay can never take is dropped at the next replay, and the
// message behind it reaches the peer. Before the fix the replay returned on
// that entry, so it held up every channel's outbox at every send and start.
func TestOutboxDropsAnEntryTheRelayCanNeverTake(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	fr := &flakyRelay{proxy: httputil.NewSingleHostReverseProxy(target)}
	proxy := httptest.NewServer(fr)
	t.Cleanup(proxy.Close)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), proxy.URL+"/peer")
	gp, err := openParty(p.guestDir)
	if err != nil {
		t.Fatal(err)
	}
	before := len(srv.Envelopes(p.channel, "g2h"))

	// An entry whose envelope type no longer parses: committed, and no retry
	// can ever put it.
	stuck := &store.Entry{ID: "stuck-entry-0000000000", Channel: p.channel, Type: "bogus", Body: []byte("x")}
	if err := gp.outbox.Add(stuck); err != nil {
		t.Fatal(err)
	}
	if err := gp.outbox.MarkCommitted(stuck); err != nil {
		t.Fatal(err)
	}
	// And behind it, a real message whose put failed after its commit.
	fr.refusePuts.Store(true)
	code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--text", "behind the stuck entry", "zt/advisor")
	m := regexp.MustCompile(`peer send: (\S+) is committed but the relay did not take it`).FindStringSubmatch(errb)
	if code != 1 || m == nil {
		t.Fatalf("send with the relay refusing puts: exit %d, stderr %q", code, errb)
	}
	id := m[1]
	// The send's own replay reached the stuck entry first and dropped it.
	if !strings.Contains(errb, "stuck-entry-0000000000 dropped") {
		t.Errorf("the replay did not report the drop:\n%s", errb)
	}
	fr.refusePuts.Store(false)

	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if es, _ := gp.outbox.Entries(); len(es) != 0 {
		t.Fatalf("outbox after the replay: %+v", es)
	}
	if n := len(srv.Envelopes(p.channel, "g2h")); n != before+1 {
		t.Fatalf("the relay holds %d g2h rows, want %d", n, before+1)
	}
	if log := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(log, "delivered text "+id) {
		t.Fatalf("host serve:\n%s", log)
	}
	if _, ok := records(t, deliverDirOf(p.hostDir), deliver.Inbox)[id]; !ok {
		t.Fatalf("%s is not in the host inbox", id)
	}
}
