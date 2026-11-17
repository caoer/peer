package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/relay/relaytest"
)

// statusByRecord is peer status's text read record by record from the
// state, as status read it before it held the state at once.
func statusByRecord(t *testing.T, dir string) string {
	t.Helper()
	ctx := context.Background()
	p, err := openParty(dir)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := runStatus(ctx, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	printStatus(&b, rows, time.Now())
	lines, err := runRoomStatus(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// peer status on a page state: with no serve, one values list of the page
// and no record read; with serve running, serve's copy and no request at
// all. Either way it prints what reading record by record prints.
func TestStatusReadsTheStateAtOnce(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	ps, cfg := pageHost(t)
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)

	want := statusByRecord(t, p.hostDir)
	if !strings.Contains(want, "ancan") {
		t.Fatalf("status by record names no peer:\n%s", want)
	}
	gets, lists := ps.Gets(""), ps.Lists()
	if got := mustOK(t, "status", "--dir", p.hostDir); got != want {
		t.Fatalf("status with no serve:\n%s\nwant\n%s", got, want)
	}
	if g, l := ps.Gets("")-gets, ps.Lists()-lists; g != 0 || l != 1 {
		t.Fatalf("status with no serve: %d record reads and %d lists, want 0 and 1", g, l)
	}

	runServe(t, p.hostDir, time.Hour)
	stateLive(t, ps)
	waitTrue(t, "serve's state socket", func() bool {
		_, err := os.Stat(filepath.Join(p.hostDir, stateSock))
		return err == nil
	})
	want = statusByRecord(t, p.hostDir)
	gets, lists = ps.Gets(""), ps.Lists()
	for range 3 {
		if got := mustOK(t, "status", "--dir", p.hostDir); got != want {
			t.Fatalf("status with serve:\n%s\nwant\n%s", got, want)
		}
	}
	if g, l := ps.Gets("")-gets, ps.Lists()-lists; g != 0 || l != 0 {
		t.Fatalf("3 status calls with serve: %d record reads and %d lists, want 0", g, l)
	}
}

// peer wait with no serve on the directory fails at once, naming it.
func TestWaitWithoutServeFails(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	_, cfg := pageHost(t)
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	mustRefuse(t, "no serve answers", "wait", "--dir", p.hostDir, "ancan")
}

// peer wait holds on serve's push: a message from the peer wakes it within
// a moment, it prints the peer's new row, and neither it nor serve reads
// the state page meanwhile.
func TestWaitReturnsOnAMessage(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	ps, cfg := pageHost(t)
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	out, _, _ := settleEvery(t, srv, p, time.Hour)
	stateLive(t, ps)
	unread := statusRows(t, p.hostDir)["ancan"].Unread

	type result struct {
		code      int
		out, errb string
		at        time.Time
	}
	done := make(chan result, 1)
	go func() {
		var o, e strings.Builder
		code := run([]string{"wait", "--dir", p.hostDir, "--json", "ancan"}, &o, &e)
		done <- result{code, o.String(), e.String(), time.Now()}
	}()
	time.Sleep(500 * time.Millisecond) // the wait takes its first copy
	select {
	case r := <-done:
		t.Fatalf("wait returned before any change: %d %s%s", r.code, r.out, r.errb)
	default:
	}
	gets, lists := ps.Gets(""), ps.Lists()
	id, _ := sendOK(t, p.guestDir, "--text", "wake", "zt/advisor")
	sent := time.Now()
	waitFor(t, out, "delivered text "+id, 1)
	var r result
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("wait did not return on a delivered message")
	}
	if r.code != 0 {
		t.Fatalf("wait: exit %d: %s", r.code, r.errb)
	}
	var rows []statusJSON
	if err := json.Unmarshal([]byte(r.out), &rows); err != nil || len(rows) != 1 || rows[0].Name != "ancan" || rows[0].Unread != unread+1 {
		t.Fatalf("wait printed %s (%v), want ancan with unread %d", r.out, err, unread+1)
	}
	t.Logf("sent %s, wait returned %s: %v", sent.UTC().Format(time.RFC3339Nano), r.at.UTC().Format(time.RFC3339Nano), r.at.Sub(sent))
	if d := r.at.Sub(sent); d > 2*time.Second {
		t.Fatalf("wait returned %v after the send, want under 2 s", d)
	}
	if g, l := ps.Gets("")-gets, ps.Lists()-lists; g != 0 || l != 0 {
		t.Fatalf("%d state page reads and %d lists while waiting, want 0", g, l)
	}
}
