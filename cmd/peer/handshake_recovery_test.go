package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/store"
)

// obstruct makes a record's temp path a directory, so that record's next
// write fails where a full disk or a refused page would.
func obstruct(t *testing.T, dir, key string) string {
	t.Helper()
	p := filepath.Join(dir, stateDir, key+".json.tmp")
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// bumpRelay fronts the fake relay and, once armed, runs bump on the next
// envelope pull — a stand-in for another host of the party committing the
// keys record while a command holds its snapshot.
type bumpRelay struct {
	proxy  http.Handler
	armed  atomic.Bool
	bumped atomic.Bool
	bump   func()
}

func (b *bumpRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.armed.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/envelopes") && !b.bumped.Swap(true) {
		b.bump()
	}
	b.proxy.ServeHTTP(w, r)
}

func frontRelay(t *testing.T, base string, bump func()) (*bumpRelay, string) {
	t.Helper()
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	br := &bumpRelay{proxy: httputil.NewSingleHostReverseProxy(target), bump: bump}
	ts := httptest.NewServer(br)
	t.Cleanup(ts.Close)
	return br, ts.URL + "/peer"
}

// confirm's roster write is its last step. When it fails after the channel
// commit and the card put, re-running confirm finishes the handshake instead
// of refusing: the channel already holds the pinned card and the session, and
// the guest's spent token cannot be retried. A wrong code still refuses.
func TestConfirmFinishesAfterItsRosterWriteFailed(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, config{})
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	out = mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	code := codeRE.FindStringSubmatch(out)[1]

	block := obstruct(t, hostDir, roster.Key)
	if c, _, _ := cmd(t, "confirm", "--dir", hostDir, "--code", code, "ancan"); c == 0 {
		t.Fatal("confirm with the roster write failing: exit 0")
	}
	if err := os.RemoveAll(block); err != nil {
		t.Fatal(err)
	}
	_, _, hpe := channelOf(t, hostDir, "ancan")
	if hpe.State != roster.Invited {
		t.Fatalf("host state %s after the failed roster write", hpe.State)
	}

	mustRefuse(t, "code does not match", "confirm", "--dir", hostDir, "--code", "00000000", "ancan")
	if _, _, pe := channelOf(t, hostDir, "ancan"); pe.State != roster.Invited {
		t.Fatalf("a wrong code finished the confirm: state %s", pe.State)
	}
	if out := mustOK(t, "confirm", "--dir", hostDir, "--code", code, "ancan"); !strings.Contains(out, "confirmed ancan") {
		t.Fatalf("confirm re-run:\n%s", out)
	}
	if _, _, pe := channelOf(t, hostDir, "ancan"); pe.State != roster.Confirmed {
		t.Fatalf("host state %s after the re-run", pe.State)
	}

	// The channel serves both ways from here: the guest takes the host's
	// details card and answers, and the host delivers the guest's message.
	mustOK(t, "serve", "--dir", guestDir, "--once")
	mustOK(t, "serve", "--dir", hostDir, "--once")
	id, _ := sendOK(t, guestDir, "--text", "the channel works", "zt/advisor")
	if log := mustOK(t, "serve", "--dir", hostDir, "--once"); !strings.Contains(log, "delivered text "+id) {
		t.Fatalf("host serve:\n%s", log)
	}
}

// Another host's serve commits the party keys on every PreKey record, so a
// confirm's keys commit meets a conflict on a live party. That conflict costs
// a spare one-time prekey, not the handshake: confirm reports it and writes
// the roster.
func TestConfirmAbsorbsAKeysConflict(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, config{})
	var bumpErr error
	br, front := frontRelay(t, base, func() {
		p, err := openParty(hostDir)
		if err != nil {
			bumpErr = err
			return
		}
		k, err := p.keys(context.Background())
		if err != nil {
			bumpErr = err
			return
		}
		bumpErr = k.Commit(context.Background())
	})

	out := mustOK(t, "invite", "--dir", hostDir, "--relay", front, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	out = mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	code := codeRE.FindStringSubmatch(out)[1]

	br.armed.Store(true)
	out = mustOK(t, "confirm", "--dir", hostDir, "--code", code, "ancan")
	if bumpErr != nil {
		t.Fatalf("the keys bump did not land: %v", bumpErr)
	}
	if !br.bumped.Load() {
		t.Fatal("the keys record was never bumped under the confirm")
	}
	if !strings.Contains(out, "stays a spare") {
		t.Fatalf("confirm did not report the keys conflict:\n%s", out)
	}
	if _, _, pe := channelOf(t, hostDir, "ancan"); pe.State != roster.Confirmed {
		t.Fatalf("host state %s after a keys conflict", pe.State)
	}
	id, _ := sendOK(t, guestDir, "--text", "after the keys conflict", "zt/advisor")
	mustOK(t, "serve", "--dir", guestDir, "--once")
	if log := mustOK(t, "serve", "--dir", hostDir, "--once"); !strings.Contains(log, "delivered text "+id) {
		t.Fatalf("host serve:\n%s", log)
	}
}

// accept spends the invite token at the join, so a failure after it must be
// resumable: the row carries the token, and another accept with the same link
// finishes the handshake. A second run once the session is built prints the
// code again and changes nothing.
func TestAcceptResumesAfterAFailurePastTheToken(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, config{})
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	l, err := invite.Parse(link, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	block := obstruct(t, guestDir, store.ChannelKey(l.Channel))
	if c, _, _ := cmd(t, "accept", "--dir", guestDir, "--name", "zt", link); c == 0 {
		t.Fatal("accept with the channel write failing: exit 0")
	}
	if err := os.RemoveAll(block); err != nil {
		t.Fatal(err)
	}
	if n := len(srv.Envelopes(l.Channel, "g2h")); n != 0 {
		t.Fatalf("the failed accept put %d envelopes", n)
	}

	out = mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	m := codeRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the resumed accept printed no code:\n%s", out)
	}
	if rows := srv.Envelopes(l.Channel, "g2h"); len(rows) != 1 || rows[0].Type != "prekey" {
		t.Fatalf("relay g2h after the resume: %+v", rows)
	}
	// Running it once more is a no-op that prints the same code.
	again := mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	if c := codeRE.FindStringSubmatch(again); c == nil || c[1] != m[1] {
		t.Fatalf("a third accept printed %q, want the code %s", again, m[1])
	}
	if rows := srv.Envelopes(l.Channel, "g2h"); len(rows) != 1 {
		t.Fatalf("the no-op accept put %d envelopes", len(rows)-1)
	}

	mustOK(t, "confirm", "--dir", hostDir, "--code", m[1], "ancan")
	mustOK(t, "serve", "--dir", guestDir, "--once")
	mustOK(t, "serve", "--dir", hostDir, "--once")
	id, _ := sendOK(t, guestDir, "--text", "the resumed channel works", "zt/advisor")
	if log := mustOK(t, "serve", "--dir", hostDir, "--once"); !strings.Contains(log, "delivered text "+id) {
		t.Fatalf("host serve:\n%s", log)
	}
	if _, ok := records(t, deliverDirOf(hostDir), deliver.Inbox)[id]; !ok {
		t.Fatalf("%s is not in the host inbox", id)
	}
}

// The guest's answer to the host's details card commits the channel, the
// cursor past that card, before the roster says confirmed. When that commit
// lands and its answer is lost, the answer never reaches the relay and the
// roster stays accepted; the next round finishes both: the guest's details
// card goes out and the guest is confirmed.
func TestServeGuestConfirmsAfterItsAnswerWasCutShort(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, config{})
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	out = mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	mustOK(t, "confirm", "--dir", hostDir, "--code", codeRE.FindStringSubmatch(out)[1], "ancan")

	var log bytes.Buffer
	sv, err := openServer(guestDir, "", &log)
	if err != nil {
		t.Fatal(err)
	}
	sv.p.store = store.New(landThenFail{sv.p.backend}, sv.p.id)
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err == nil {
		t.Fatalf("guest round: no error, want the lost answer\n%s", log.String())
	}
	if _, gch, gpe := channelOf(t, guestDir, "zt"); gpe.State != roster.Accepted || gch.Cursor() < 1 {
		t.Fatalf("after the lost answer: state %s, cursor %d", gpe.State, gch.Cursor())
	}

	mustOK(t, "serve", "--dir", guestDir, "--once")
	if _, _, gpe := channelOf(t, guestDir, "zt"); gpe.State != roster.Confirmed {
		t.Fatalf("guest state %s after the next round", gpe.State)
	}
	if out := mustOK(t, "serve", "--dir", hostDir, "--once"); !strings.Contains(out, "card from ancan pinned") {
		t.Fatalf("the guest's details card did not reach the host:\n%s", out)
	}
}
