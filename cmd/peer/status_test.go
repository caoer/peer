package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/status"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// statusRows runs peer status --json.
func statusRows(t *testing.T, dir string) map[string]statusJSON {
	t.Helper()
	var rows []statusJSON
	if err := json.Unmarshal([]byte(mustOK(t, "status", "--dir", dir, "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]statusJSON{}
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

// guestOfTwo is a guest party (named "ancan" by the hosts) confirmed with
// the first host, "zt", and accepted on the second host's link, "h2", which
// that host has not confirmed. It returns the pair and the second host's
// party id.
func guestOfTwo(t *testing.T, guestCfg config) (*pair, string) {
	t.Helper()
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, guestCfg), base)
	h2 := newDir(t, hostCfg())
	out := mustOK(t, "invite", "--dir", h2, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	if _, err := invite.Parse(link, time.Now()); err != nil {
		t.Fatal(err)
	}
	mustOK(t, "accept", "--dir", p.guestDir, "--name", "h2", link)
	return p, keys.PartyID(rootOf(t, h2).Public())
}

// peer status on a party with a confirmed and an accepted peer: the store's
// view of each, the last message and unread from the activity record, and a
// send clearing unread.
func TestStatusConfirmedAndAccepted(t *testing.T) {
	p, h2Party := guestOfTwo(t, config{})
	start := time.Now().Add(-time.Second)
	sendOK(t, p.hostDir, "--kind", "task", "--text", "please review", "ancan")
	mustOK(t, "serve", "--dir", p.guestDir, "--once")

	rows := statusRows(t, p.guestDir)
	zt, h2 := rows["zt"], rows["h2"]
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if zt.Party != p.hostParty || zt.Channel != p.channel || zt.Side != "guest" || zt.State != "confirmed" || zt.Cursor < 1 {
		t.Fatalf("zt %+v", zt)
	}
	if zt.LastAt == nil || zt.LastAt.Before(start) || zt.LastKind != "task" || zt.Unread != 1 || !zt.Active || zt.SentAt != nil || zt.Page != nil {
		t.Fatalf("zt activity %+v", zt)
	}
	if h2.Party != h2Party || h2.State != "accepted" || h2.LastAt != nil || h2.LastKind != "" || h2.Unread != 0 || h2.Active {
		t.Fatalf("h2 %+v", h2)
	}

	out := mustOK(t, "status", "--dir", p.guestDir)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "NAME") {
		t.Fatalf("status:\n%s", out)
	}
	for _, want := range [][]string{
		{"zt", tail(p.hostParty), "guest", "confirmed", "task " + zt.LastAt.Format(time.RFC3339), " 1 ", "yes"},
		{"h2", tail(h2Party), "guest", "accepted", " - ", " 0 ", "no"},
	} {
		found := false
		for _, l := range lines[1:] {
			if strings.HasPrefix(l, want[0]+" ") {
				found = true
				for _, w := range want[1:] {
					if !strings.Contains(l, w) {
						t.Errorf("line %q lacks %q", l, w)
					}
				}
			}
		}
		if !found {
			t.Errorf("no line for %s:\n%s", want[0], out)
		}
	}

	sendOK(t, p.guestDir, "--kind", "answer", "--text", "done", "zt")
	if zt := statusRows(t, p.guestDir)["zt"]; zt.Unread != 0 || zt.SentAt == nil || !zt.SentAt.After(*zt.LastAt) || zt.LastKind != "task" {
		t.Fatalf("after the answer: %+v", zt)
	}
	// The host's own view: the answer is its unread, its task the guest's.
	if an := statusRows(t, p.hostDir)["ancan"]; an.Unread != 0 || an.SentAt == nil {
		t.Fatalf("host before its serve: %+v", an)
	}
	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if an := statusRows(t, p.hostDir)["ancan"]; an.Unread != 1 || an.LastKind != "answer" {
		t.Fatalf("host after its serve: %+v", an)
	}
}

// serve writes one roster row per peer per round on the private page, with
// the fields of peer-roster@1, nothing about the host or the login; status
// reads it back as fresh.
func TestServeWritesRosterPage(t *testing.T) {
	ps := pagestest.New("roster-0123456789abcdef", "zt:roster-secret")
	t.Cleanup(ps.Close)
	p, h2Party := guestOfTwo(t, config{Roster: rosterConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}})
	hostRoot, _ := keys.ParsePartyID(p.hostParty)
	h2Root, _ := keys.ParsePartyID(h2Party)
	ztKey, h2Key := status.RowKey(hostRoot), status.RowKey(h2Root)

	id, _ := sendOK(t, p.hostDir, "--text", "hello", "ancan")
	before := ps.Puts()
	start := time.Now().Add(-time.Second)
	out := mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.Contains(out, "delivered text "+id) || strings.Contains(out, "roster page") {
		t.Fatalf("guest serve:\n%s", out)
	}
	if n := ps.Puts() - before; n != 2 {
		t.Fatalf("%d PUTs in one round for two peers", n)
	}

	row := func(key string) (*status.Row, []byte) {
		t.Helper()
		rec, ok := ps.Record(key)
		if !ok || rec.Schema != status.RowSchema {
			t.Fatalf("%s: %+v %v", key, rec, ok)
		}
		var r status.Row
		if err := json.Unmarshal(rec.Data, &r); err != nil {
			t.Fatal(err)
		}
		return &r, rec.Data
	}
	zt, ztBytes := row(ztKey)
	if zt.Name != "zt" || zt.Party != p.hostParty || zt.Channel != p.channel || zt.Side != "guest" || zt.State != "confirmed" {
		t.Fatalf("zt row %s", ztBytes)
	}
	if zt.LastAt == nil || zt.LastAt.Before(start) || zt.LastKind != "text" || zt.Unread != 1 || !zt.Active || zt.Beat != 30 {
		t.Fatalf("zt row %s", ztBytes)
	}
	if zt.At.Before(start) || zt.Stale(time.Now()) || !zt.Stale(zt.At.Add(91*time.Second)) {
		t.Fatalf("zt row freshness %s", ztBytes)
	}
	h2, h2Bytes := row(h2Key)
	if h2.Name != "h2" || h2.Party != h2Party || h2.State != "accepted" || h2.LastAt != nil || h2.Active {
		t.Fatalf("h2 row %s", h2Bytes)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(ztBytes, &fields)
	if len(fields) != 11 {
		t.Fatalf("row fields %s", ztBytes)
	}
	host, _ := os.Hostname()
	_, _, gpe := channelOf(t, p.guestDir, "zt")
	for _, b := range [][]byte{ztBytes, h2Bytes} {
		for _, secret := range []string{host, login, ps.Bearer, "roster-secret", gpe.Token, p.guestDir} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("row carries %q: %s", secret, b)
			}
		}
	}

	out = mustOK(t, "status", "--dir", p.guestDir)
	if strings.Count(out, " fresh ") != 2 {
		t.Fatalf("status:\n%s", out)
	}
	if rows := statusRows(t, p.guestDir); rows["zt"].Page == nil || rows["zt"].Page.Stale || rows["zt"].Page.At == nil {
		t.Fatalf("status page view %+v", rows["zt"].Page)
	}
}

// A roster page that refuses — the login, or a conflict on every write —
// is logged and leaves the round alone: the message is born, the cursor
// moves, serve exits 0, and status shows the refusal.
func TestRosterPageRefusalLeavesDeliveries(t *testing.T) {
	conflict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"no such object","code":"no_such_object"}`))
			return
		}
		w.WriteHeader(409)
		w.Write([]byte(`{"error":"expected version 0, found 9","code":"version_conflict","version":9}`))
	}))
	t.Cleanup(conflict.Close)
	ps := pagestest.New("roster-0123456789abcdef", "zt:roster-secret")
	t.Cleanup(ps.Close)
	for name, rc := range map[string]rosterConfig{
		"401":      {Page: ps.URL, Slug: ps.Slug, Login: "zt:wrong"},
		"conflict": {Page: conflict.URL, Slug: "roster-x", Login: "zt:any"},
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := guestOfTwo(t, config{Roster: rc})
			_, ch, _ := channelOf(t, p.guestDir, "zt")
			cursor := ch.Cursor()
			id, _ := sendOK(t, p.hostDir, "--text", "through anyway", "ancan")
			out := mustOK(t, "serve", "--dir", p.guestDir, "--once")
			if !strings.Contains(out, "delivered text "+id) || !strings.Contains(out, "roster page: ") {
				t.Fatalf("guest serve:\n%s", out)
			}
			if strings.Count(out, "roster page: ") != 1 {
				t.Errorf("one refusal per round, not per row:\n%s", out)
			}
			if _, ok := records(t, deliverDirOf(p.guestDir), deliver.Inbox)[id]; !ok {
				t.Fatalf("%s not born", id)
			}
			if _, ch, _ := channelOf(t, p.guestDir, "zt"); ch.Cursor() != cursor+1 {
				t.Fatalf("cursor %d, want %d", ch.Cursor(), cursor+1)
			}
			if zt := statusRows(t, p.guestDir)["zt"]; zt.Page == nil || (name == "401" && zt.Page.Error == "") || zt.Unread != 1 {
				t.Fatalf("status %+v %+v", zt, zt.Page)
			}
		})
	}
}
