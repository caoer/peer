package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// uccSession is the fixture map's session. Its roster records are seats no
// agent holds — vacant — and the record lands all the same: nothing in peer
// reads liveness (UCC design v2 § 5, the record is the delivery).
const uccSession = "projects/demo"

// uccRoot is a sessions root for a test: the fixture map — the first real
// map, internal/seats/testdata/seats.md — at peers/seats.md, and the session
// it names with INTENT.md and its two roster records.
func uccRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sessions")
	writeSeats(t, root)
	sd := filepath.Join(root, filepath.FromSlash(uccSession))
	if err := os.MkdirAll(filepath.Join(sd, "rosters"), 0o755); err != nil {
		t.Fatal(err)
	}
	for n, body := range map[string]string{
		"INTENT.md":                 "---\ntype: intent\nsession: demo\n---\n# Intent\n",
		"rosters/leader-peer-v1.md": "---\ntype: roster\nrole: leader\n---\n# leader-peer-v1\n",
		"rosters/worker-cli.md":     "---\ntype: roster\nrole: worker\n---\n# worker-cli\n",
		"rosters/advisor-demo.md":   "---\ntype: roster\nrole: advisor\n---\n# advisor-demo\n",
	} {
		if err := os.WriteFile(filepath.Join(sd, filepath.FromSlash(n)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeSeats(t *testing.T, root string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "seats", "testdata", "seats.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "peers"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "peers", "seats.md"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// uccCfg is a host party on the fleet: no agents of its own — the map's rows
// are its agents.
func uccCfg(root string) config { return config{UCC: &uccConfig{Root: root}} }

// sessionRecords lists <root>/<session>/<place>/*.md by id.
func sessionRecords(t *testing.T, root string, place deliver.Place) map[string][]byte {
	t.Helper()
	return records(t, filepath.Join(root, filepath.FromSlash(uccSession)), place)
}

// bornAnywhere reports whether <id>.md is under root at all.
func bornAnywhere(t *testing.T, root, id string) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == id+".md" {
			found = true
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// A fleet host serves by the map: the card's agents are its rows; text and
// task to a seat birth the inbox record under the seat's session with
// exactly the five keys and the protocol addresses; a question to the human
// (zt) is a record in the inbox of the position his row names, to: still
// <party>/zt (the plan's U16 verify, up to the advisor's inbox); doc, file
// and a kind outside the row's accepts go to the quarantine beside it; an
// unmapped label and a bare party address are refused at the border with
// their reason, consumed, and born nowhere — not under the root, not in the
// local delivery directory.
func TestServeUCCDelivery(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	root := uccRoot(t)
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)

	hp, err := openParty(p.hostDir)
	if err != nil {
		t.Fatal(err)
	}
	seat := []string{"text", "task", "question", "answer", "ack"}
	agents := []card.Agent{
		{ID: "leader", Accepts: seat}, {ID: "cli", Accepts: seat},
		{ID: "zt", Accepts: []string{"text", "question", "answer"}}, {ID: "hook", Accepts: []string{"text"}},
	}
	if !reflect.DeepEqual(hp.cfg.Agents, agents) {
		t.Fatalf("the card's agents are not the map's rows:\n%+v", hp.cfg.Agents)
	}

	vendor := "vnd." + p.guestParty + ".ping"
	ids := map[string]string{}
	for _, c := range []struct{ name, kind, to string }{
		{"text", "text", "zt/leader"}, {"task", "task", "zt/leader"},
		{"doc", "doc", "zt/leader"}, {"file", "file", "zt/leader"}, {"vendor", vendor, "zt/leader"},
		{"nobody", "text", "zt/nobody"}, {"human", "question", "zt/zt"}, {"bare", "text", "zt"},
	} {
		if isAttachment(c.kind) {
			f := filepath.Join(t.TempDir(), c.name+".md")
			if err := os.WriteFile(f, []byte("body of "+c.name), 0o600); err != nil {
				t.Fatal(err)
			}
			ids[c.name], _ = sendOK(t, p.guestDir, "--kind", c.kind, "--file", f, c.to)
			continue
		}
		ids[c.name], _ = sendOK(t, p.guestDir, "--kind", c.kind, "--text", "body of "+c.name, c.to)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")

	in := sessionRecords(t, root, deliver.Inbox)
	q := sessionRecords(t, root, deliver.Quarantine)
	for _, n := range []string{"text", "task"} {
		if _, ok := in[ids[n]]; !ok {
			t.Errorf("%s is not in the seat's inbox; serve said:\n%s", n, out)
		}
		if !strings.Contains(out, "delivered "+n+" "+ids[n]+" → "+filepath.Join(root, filepath.FromSlash(uccSession), "inbox", ids[n]+".md")) {
			t.Errorf("serve did not report %s delivered under the session:\n%s", n, out)
		}
	}
	for n, kind := range map[string]string{"doc": "doc", "file": "file", "vendor": vendor} {
		if _, ok := q[ids[n]]; !ok {
			t.Errorf("%s is not in the seat's quarantine; serve said:\n%s", n, out)
		}
		if !strings.Contains(out, "quarantined "+kind+" "+ids[n]) {
			t.Errorf("serve did not report %s quarantined:\n%s", n, out)
		}
	}
	if len(in) != 3 || len(q) != 3 {
		t.Fatalf("%d in the inbox, %d quarantined", len(in), len(q))
	}
	hm, horder, hbody := parseRecord(t, in[ids["human"]])
	if !reflect.DeepEqual(horder, []string{"from", "to", "kind", "verified", "at"}) || hm["to"] != p.hostParty+"/zt" || hm["kind"] != "question" || hbody != "body of human" {
		t.Errorf("the question to zt in the advisor's session inbox: %v %v %q", horder, hm, hbody)
	}
	fm, order, body := parseRecord(t, in[ids["text"]])
	if want := []string{"from", "to", "kind", "verified", "at"}; !reflect.DeepEqual(order, want) {
		t.Errorf("frontmatter keys %v, want exactly %v", order, want)
	}
	if fm["from"] != p.guestParty || fm["to"] != p.hostParty+"/leader" || fm["kind"] != "text" || fm["verified"] != "true" || body != "body of text" {
		t.Errorf("inbox record %v %q", fm, body)
	}

	for n, reason := range map[string]string{
		"nobody": `unmapped label "nobody": refused`,
		"bare":   `unmapped label "": refused`,
	} {
		if !strings.Contains(out, "skip ancan #") || !strings.Contains(out, reason) {
			t.Errorf("serve did not refuse %s with %q:\n%s", n, reason, out)
		}
		if bornAnywhere(t, root, ids[n]) {
			t.Errorf("%s was born under the root", n)
		}
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Inbox)) + len(records(t, deliverDirOf(p.hostDir), deliver.Quarantine)); n != 0 {
		t.Errorf("%d records in the local delivery directory, want none under ucc", n)
	}
	// Every record consumed — the guest's card at #1 and the eight messages.
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if hch.Cursor() != 9 {
		t.Errorf("cursor %d, want 9", hch.Cursor())
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); strings.Contains(out, "delivered") || strings.Contains(out, "skip") {
		t.Errorf("a second serve did something:\n%s", out)
	}
}

// Nothing is consumed for want of UCC's side: without the map serve does not
// open; a seat whose session is not on this root is waited for, the cursor
// staying before the message, and it is delivered once the session is there.
func TestServeUCCWaits(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	root := uccRoot(t)
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)
	id, _ := sendOK(t, p.guestDir, "--text", "hello", "zt/leader")

	mapPath := filepath.Join(root, "peers", "seats.md")
	if err := os.Rename(mapPath, mapPath+".away"); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "seat map "+mapPath, "serve", "--dir", p.hostDir, "--once")
	if err := os.Rename(mapPath+".away", mapPath); err != nil {
		t.Fatal(err)
	}
	if bornAnywhere(t, root, id) {
		t.Fatal("born without the map")
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if hch.Cursor() != 1 {
		t.Fatalf("cursor %d after the refused serve, want 1", hch.Cursor())
	}

	sd := filepath.Join(root, filepath.FromSlash(uccSession))
	if err := os.Rename(sd, sd+".away"); err != nil {
		t.Fatal(err)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "ancan: waiting at #2: leader's session "+uccSession+" is not on this root") {
		t.Fatalf("serve did not wait:\n%s", out)
	}
	if err := os.Rename(sd+".away", sd); err != nil {
		t.Fatal(err)
	}
	if bornAnywhere(t, root, id) {
		t.Fatal("born while the session was away")
	}
	if _, hch, _ = channelOf(t, p.hostDir, "ancan"); hch.Cursor() != 1 {
		t.Fatalf("cursor %d after the wait, want 1", hch.Cursor())
	}

	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if _, ok := sessionRecords(t, root, deliver.Inbox)[id]; !ok || !strings.Contains(out, "delivered text "+id) {
		t.Fatalf("not delivered once the session was back:\n%s", out)
	}
	if _, hch, _ = channelOf(t, p.hostDir, "ancan"); hch.Cursor() != 2 {
		t.Fatalf("cursor %d after the delivery, want 2", hch.Cursor())
	}
}

// Two OS processes serve one shared state and one sessions root — the file
// backend and the pages backend — holding the same version when they commit:
// exactly one inbox record per message under the seat's session, none lost,
// both spools empty (plan decision 5; the U11 verify: 一条消息只落一条记录，
// 两台机器同时收也只一条；岗位空着记录等着).
func TestTwoHostsServeUCC(t *testing.T) {
	for _, kind := range []string{"file", "pages"} {
		t.Run(kind, func(t *testing.T) {
			_, _, base := relaytest.Start(t, login)
			root := uccRoot(t)
			cfg := uccCfg(root)
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
				id, _ := sendOK(t, p.guestDir, "--text", fmt.Sprintf("message %d", i), "zt/leader")
				ids = append(ids, id)
			}
			hostB := filepath.Join(t.TempDir(), "peer")
			if err := os.MkdirAll(hostB, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, n := range []string{rootFile, identityFile, partyKeysFile, configFile} {
				b, err := os.ReadFile(filepath.Join(p.hostDir, n))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(hostB, n), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a, b := startServeChild(t, p.hostDir), startServeChild(t, hostB)
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

			in := sessionRecords(t, root, deliver.Inbox)
			for _, id := range ids {
				if _, ok := in[id]; !ok {
					t.Errorf("%s is not in the seat's inbox", id)
				}
			}
			if len(in) != 3 || a.delivered+b.delivered != 3 {
				t.Errorf("%d records, children delivered %d+%d, want 3 and 3", len(in), a.delivered, b.delivered)
			}
			for _, d := range []string{p.hostDir, hostB} {
				j, err := store.OpenJournal(filepath.Join(d, spoolDir))
				if err != nil {
					t.Fatal(err)
				}
				if es, _ := j.Entries(); len(es) != 0 {
					t.Errorf("%s: spool holds %+v", d, es)
				}
				if n := len(records(t, deliverDirOf(d), deliver.Inbox)); n != 0 {
					t.Errorf("%s: %d records in the local delivery directory", d, n)
				}
			}
			if a.conflicts+b.conflicts < 1 {
				t.Errorf("no commit conflicted: the hosts did not race")
			}
			_, hch, _ := channelOf(t, p.hostDir, "ancan")
			if hch.Cursor() != 4 {
				t.Errorf("cursor %d, want 4", hch.Cursor())
			}
		})
	}
}
