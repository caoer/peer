package main

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/sealed"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

var roomSentRE = regexp.MustCompile(`(?m)^sent (\S+) to room .*\(\S+, #(\d+)\)$`)

// roomSendOK runs peer send into a room and returns the message id and seq.
func roomSendOK(t *testing.T, dir string, args ...string) (string, int64) {
	t.Helper()
	out := mustOK(t, append([]string{"send", "--dir", dir}, args...)...)
	m := roomSentRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("room send printed no receipt:\n%s", out)
	}
	seq, _ := strconv.ParseInt(m[2], 10, 64)
	return m[1], seq
}

// trio is three parties in one room: A created it (room name r1) and added
// B (bob) and C (carol) over its channels; every serve has run to quiet.
type trio struct {
	a, b, c       string
	ab, ac        *pair
	id            string
	srv           *relaytest.Server
	aRoom, bcRoom string // A's name for the room, and B's and C's
}

func newTrio(t *testing.T, base string, srv *relaytest.Server, cfgA config) *trio {
	t.Helper()
	tr := &trio{a: newDir(t, cfgA), b: newDir(t, config{}), c: newDir(t, config{}), srv: srv, aRoom: "r1"}
	tr.ab = handshakeNamed(t, tr.a, tr.b, base, "bob", "alice")
	tr.ac = handshakeNamed(t, tr.a, tr.c, base, "carol", "alice")
	tr.id = createRoom(t, tr.a, base, "r1")
	tr.bcRoom = tr.id[:8]
	addToRoom(t, tr.a, tr.b, "r1", "bob")
	addToRoom(t, tr.a, tr.c, "r1", "carol")
	for _, d := range []string{tr.b, tr.c, tr.a} {
		mustOK(t, "serve", "--dir", d, "--once")
	}
	return tr
}

// frontMatter is a record's frontmatter keys in order and their values.
func frontMatter(t *testing.T, rec []byte) ([]string, map[string]string, string) {
	t.Helper()
	s := string(rec)
	if !strings.HasPrefix(s, "---\n") {
		t.Fatalf("record without frontmatter:\n%s", s)
	}
	head, body, ok := strings.Cut(s[4:], "\n---\n")
	if !ok {
		t.Fatalf("record frontmatter not closed:\n%s", s)
	}
	var keys []string
	vals := map[string]string{}
	for _, l := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(l, ": ")
		keys = append(keys, k)
		vals[k] = v
	}
	return keys, vals, body
}

// roomRecord checks a born room record: the six keys in order, from, to,
// group and the body.
func roomRecord(t *testing.T, rec []byte, from, to, group, body string) {
	t.Helper()
	keys, v, b := frontMatter(t, rec)
	if strings.Join(keys, " ") != "from to kind verified at group" {
		t.Fatalf("record keys %v, want from to kind verified at group:\n%s", keys, rec)
	}
	if v["from"] != from || v["to"] != to || v["group"] != group || v["verified"] != "true" || b != body {
		t.Fatalf("record:\n%s\nwant from %s to %s group %s body %q", rec, from, to, group, body)
	}
}

// Three parties send into the room and each reads the other two: one
// record per message at each receiver, group the room id, to the receiver,
// none of its own; a second serve births nothing; status prints the room.
func TestRoomSendServeBothWays(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	parties := map[string]string{tr.a: tr.ab.hostParty, tr.b: tr.ab.guestParty, tr.c: tr.ac.guestParty}
	names := map[string]string{tr.a: tr.aRoom, tr.b: tr.bcRoom, tr.c: tr.bcRoom}
	sent := map[string]string{} // id → sender dir
	for _, d := range []string{tr.a, tr.b, tr.c} {
		id, _ := roomSendOK(t, d, "--text", "hello from "+parties[d], names[d])
		sent[id] = d
	}
	for _, d := range []string{tr.a, tr.b, tr.c} {
		mustOK(t, "serve", "--dir", d, "--once")
	}
	for _, d := range []string{tr.a, tr.b, tr.c} {
		in := withoutRoster(t, records(t, deliverDirOf(d), deliver.Inbox))
		if len(in) != 2 {
			t.Fatalf("%s holds %d records, want the other two's", parties[d], len(in))
		}
		for id, from := range sent {
			rec, ok := in[id]
			if from == d {
				if ok {
					t.Fatalf("%s got its own record back", parties[d])
				}
				continue
			}
			if !ok {
				t.Fatalf("%s did not get %s's record", parties[d], parties[from])
			}
			roomRecord(t, rec, parties[from], parties[d], tr.id, "hello from "+parties[from])
		}
		if out := mustOK(t, "serve", "--dir", d, "--once"); strings.Contains(out, "delivered") {
			t.Fatalf("a second serve delivered again:\n%s", out)
		}
	}
	out := mustOK(t, "status", "--dir", tr.b)
	if !regexp.MustCompile(`room ` + tr.bcRoom + ` \(` + tr.id + `\)  idx 1  3 members  cursor #\d+  dropped 0  reported 0\n`).MatchString(out) {
		t.Fatalf("B's status has no room line:\n%s", out)
	}
}

// A --to subset is sealed to the named members alone: the third member's
// pull passes it with no stanza, and its counter check, run on the verified
// record, reports no gap when the writer's next record comes.
func TestRoomSendSubset(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	all1, _ := roomSendOK(t, tr.a, "--text", "to all", "r1")
	bob, _ := roomSendOK(t, tr.a, "--to", "bob", "--text", "to bob alone", "r1")
	all2, _ := roomSendOK(t, tr.a, "--text", "to all again", "r1")

	outC := mustOK(t, "serve", "--dir", tr.c, "--once")
	if strings.Contains(outC, "gap") || strings.Contains(outC, "step back") {
		t.Fatalf("C reported the subset record:\n%s", outC)
	}
	in := withoutRoster(t, records(t, deliverDirOf(tr.c), deliver.Inbox))
	if _, ok := in[bob]; ok || len(in) != 2 || in[all1] == nil || in[all2] == nil {
		t.Fatalf("C holds %d records (bob's %v)", len(in), in[bob] != nil)
	}
	_, _, cst := roomOf(t, tr.c, tr.bcRoom)
	if cst.Reported() != 0 {
		t.Fatalf("C's reported count %d", cst.Reported())
	}

	mustOK(t, "serve", "--dir", tr.b, "--once")
	in = withoutRoster(t, records(t, deliverDirOf(tr.b), deliver.Inbox))
	if len(in) != 3 {
		t.Fatalf("B holds %d records, want 3", len(in))
	}
	roomRecord(t, in[bob], tr.ab.hostParty, tr.ab.guestParty, tr.id, "to bob alone")
	if rows := srv.RoomRecords(tr.id); len(rows) == 0 {
		t.Fatal("no rows")
	} else if r, err := sealed.Parse(mustB64(t, rows[len(rows)-2].Body)); err != nil || len(r.Recipients()) != 1 || r.Recipients()[0] != 1 {
		t.Fatalf("the subset record's stanzas: %v (%v)", r.Recipients(), err)
	}

	mustRefuse(t, "no peer named dave", "send", "--dir", tr.a, "--to", "dave", "--text", "x", "r1")
	mustRefuse(t, "names you", "send", "--dir", tr.b, "--to", tr.ab.guestParty, "--text", "x", tr.bcRoom)
	mustRefuse(t, "no room named bob", "send", "--dir", tr.a, "--to", "carol", "--text", "x", "bob")
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A record the relay holds twice — the same bytes, the same idx and ctr —
// is read once: the receiver reports the step back and births nothing new.
func TestRoomReplayRejected(t *testing.T) {
	ctx := context.Background()
	srv, rc, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	id, seq := roomSendOK(t, tr.a, "--text", "once", "r1")
	mustOK(t, "serve", "--dir", tr.b, "--once")

	var body []byte
	for _, r := range srv.RoomRecords(tr.id) {
		if r.Seq == seq {
			body = mustB64(t, r.Body)
		}
	}
	_, aref, _ := roomOf(t, tr.a, "r1")
	if _, err := rc.PutRecord(ctx, tr.id, aref.Token, body, srv.RoomMembership(tr.id), false); err != nil {
		t.Fatal(err)
	}
	out := mustOK(t, "serve", "--dir", tr.b, "--once")
	if !strings.Contains(out, "step back") || strings.Contains(out, "delivered") {
		t.Fatalf("B's serve of the replay:\n%s", out)
	}
	if in := withoutRoster(t, records(t, deliverDirOf(tr.b), deliver.Inbox)); len(in) != 1 || in[id] == nil {
		t.Fatalf("B holds %d records", len(in))
	}
	if _, _, bst := roomOf(t, tr.b, tr.bcRoom); bst.Reported() != 1 {
		t.Fatalf("B's reported count %d, want 1", bst.Reported())
	}
}

// roomFront fronts the fake relay; an armed hook runs once on the next room
// record put, and answers it itself when it returns true.
type roomFront struct {
	proxy http.Handler
	onPut atomic.Pointer[func(http.ResponseWriter, *http.Request) bool]
}

func (f *roomFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/peer/r/") && strings.HasSuffix(r.URL.Path, "/records") {
		if h := f.onPut.Swap(nil); h != nil && (*h)(w, r) {
			return
		}
	}
	f.proxy.ServeHTTP(w, r)
}

func (f *roomFront) arm(h func(http.ResponseWriter, *http.Request) bool) { f.onPut.Store(&h) }

func startFront(t *testing.T) (*relaytest.Server, string, *roomFront) {
	t.Helper()
	srv, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	f := &roomFront{proxy: httputil.NewSingleHostReverseProxy(target)}
	front := httptest.NewServer(f)
	t.Cleanup(front.Close)
	return srv, front.URL + "/peer", f
}

// lastCtr is the ctr of idx's last record on the relay.
func lastCtr(t *testing.T, srv *relaytest.Server, id string, idx int) (uint64, int) {
	t.Helper()
	var ctr uint64
	n := 0
	for _, r := range srv.RoomRecords(id) {
		if r.Idx != idx {
			continue
		}
		rec, err := sealed.Parse(mustB64(t, r.Body))
		if err != nil {
			t.Fatal(err)
		}
		ctr, n = rec.Header.Ctr, n+1
	}
	return ctr, n
}

// The membership moves between A's pull and its put: the relay answers 409,
// A folds to head and seals the same plaintext at the same ctr to the
// roster as it stands, and puts once more — one record at the receivers,
// its ctr the next one, no report.
func TestRoomPut409ResealsSameCtr(t *testing.T) {
	ctx := context.Background()
	srv, base, front := startFront(t)
	tr := newTrio(t, base, srv, config{})
	before, n := lastCtr(t, srv, tr.id, 0)
	_, aref, _ := roomOf(t, tr.a, "r1")
	m0 := srv.RoomMembership(tr.id)
	front.arm(func(http.ResponseWriter, *http.Request) bool {
		// Another admin host mints between A's pull and its put.
		if _, err := relay.New(base, nil).AddMember(ctx, tr.id, aref.Token, relay.RoleWrite); err != nil {
			t.Error(err)
		}
		return false
	})
	id, _ := roomSendOK(t, tr.a, "--text", "after the bump", "r1")
	if srv.RoomMembership(tr.id) != m0+1 {
		t.Fatalf("membership %d, want %d: the bump did not run", srv.RoomMembership(tr.id), m0+1)
	}
	after, n2 := lastCtr(t, srv, tr.id, 0)
	if n2 != n+1 || after != before+1 {
		t.Fatalf("A's records %d → %d, ctr %d → %d: want one more record at the next ctr", n, n2, before, after)
	}
	out := mustOK(t, "serve", "--dir", tr.b, "--once")
	if strings.Contains(out, "gap") || strings.Contains(out, "step back") || strings.Count(out, "delivered text "+id) != 1 {
		t.Fatalf("B's serve:\n%s", out)
	}
	if _, _, bst := roomOf(t, tr.b, tr.bcRoom); bst.Reported() != 0 {
		t.Fatalf("B reported %d", bst.Reported())
	}
}

// A put that fails on the transport leaves the record in this host's room
// outbox, its ctr spent: status names it, the next serve puts it, a later
// send puts what waits first — receivers read every record once, in ctr
// order, with no report.
func TestRoomOutboxReplay(t *testing.T) {
	srv, base, front := startFront(t)
	tr := newTrio(t, base, srv, config{})
	fail := func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"error":"down for a moment","code":"internal_error"}`)
		return true
	}

	front.arm(fail)
	code, _, errb := cmd(t, "send", "--dir", tr.a, "--text", "first", "r1")
	if code != 1 || !strings.Contains(errb, "is committed but the relay did not take it") || !strings.Contains(errb, "room outbox") {
		t.Fatalf("send through a failing relay: %d\n%s", code, errb)
	}
	first := regexp.MustCompile(`peer send: (\S+) is committed`).FindStringSubmatch(errb)[1]
	if out := mustOK(t, "status", "--dir", tr.a); !strings.Contains(out, "1 waiting in the room outbox") {
		t.Fatalf("status does not name the waiting record:\n%s", out)
	}
	mustOK(t, "serve", "--dir", tr.a, "--once")
	if out := mustOK(t, "status", "--dir", tr.a); strings.Contains(out, "waiting in the room outbox") {
		t.Fatalf("the serve did not put the waiting record:\n%s", out)
	}

	front.arm(fail)
	code, _, errb = cmd(t, "send", "--dir", tr.a, "--text", "second", "r1")
	if code != 1 {
		t.Fatalf("second send through a failing relay: %d\n%s", code, errb)
	}
	second := regexp.MustCompile(`peer send: (\S+) is committed`).FindStringSubmatch(errb)[1]
	third, _ := roomSendOK(t, tr.a, "--text", "third", "r1")

	out := mustOK(t, "serve", "--dir", tr.b, "--once")
	if strings.Contains(out, "gap") || strings.Contains(out, "step back") {
		t.Fatalf("B reported a counter break:\n%s", out)
	}
	in := withoutRoster(t, records(t, deliverDirOf(tr.b), deliver.Inbox))
	for _, id := range []string{first, second, third} {
		if in[id] == nil {
			t.Fatalf("B lacks %s; holds %d", id, len(in))
		}
	}
	if len(in) != 3 {
		t.Fatalf("B holds %d records, want 3", len(in))
	}
	ia, ib := strings.Index(out, second), strings.Index(out, third)
	if ia < 0 || ib < 0 || ia > ib {
		t.Fatalf("B did not read the waiting record before the later one:\n%s", out)
	}
}

// Two OS processes serve one room on one shared state — file and pages —
// both paused before their first room commit at the same version: each
// record is born exactly once across the two hosts, both room spools end
// empty, and at least one commit conflicted.
func TestTwoHostsServeOneRoom(t *testing.T) {
	for _, kind := range []string{"file", "pages"} {
		t.Run(kind, func(t *testing.T) {
			_, _, base := relaytest.Start(t, login)
			cfg := config{}
			switch kind {
			case "file":
				cfg.State.Dir = filepath.Join(t.TempDir(), "shared-state")
			case "pages":
				ps := pagestest.New("state-0123456789abcdef", "zt:token")
				t.Cleanup(ps.Close)
				cfg.State = stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}
			}
			a, b := newDir(t, cfg), newDir(t, config{})
			handshakeNamed(t, a, b, base, "bob", "alice")
			id := createRoom(t, a, base, "r1")
			addToRoom(t, a, b, "r1", "bob")
			mustOK(t, "serve", "--dir", a, "--once")
			var ids []string
			for i := 1; i <= 3; i++ {
				mid, _ := roomSendOK(t, b, "--text", "room message "+strconv.Itoa(i), id[:8])
				ids = append(ids, mid)
			}
			hostB := secondHost(t, a)
			x, y := startServeChild(t, a), startServeChild(t, hostB)
			x.readUntil(t, "ready")
			y.readUntil(t, "ready")
			for _, c := range []*serveProc{x, y} {
				if _, err := io.WriteString(c.stdin, "go\n"); err != nil {
					t.Fatal(err)
				}
			}
			x.readUntil(t, "done")
			y.readUntil(t, "done")
			for _, c := range []*serveProc{x, y} {
				if err := c.cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			}
			born := map[string]int{}
			for _, d := range []string{a, hostB} {
				for mid, rec := range records(t, deliverDirOf(d), deliver.Inbox) {
					born[mid]++
					if _, v, _ := frontMatter(t, rec); v["group"] != id {
						t.Errorf("%s: group %q", mid, v["group"])
					}
				}
				j, err := store.OpenJournal(filepath.Join(d, roomSpoolDir))
				if err != nil {
					t.Fatal(err)
				}
				if es, _ := j.Entries(); len(es) != 0 {
					t.Errorf("%s: room spool holds %+v", d, es)
				}
			}
			for _, mid := range ids {
				if born[mid] != 1 {
					t.Errorf("%s born %d times, want exactly once", mid, born[mid])
				}
			}
			if len(born) != 3 || x.delivered+y.delivered != 3 {
				t.Errorf("%d distinct records, children delivered %d+%d, want 3", len(born), x.delivered, y.delivered)
			}
			if x.conflicts+y.conflicts < 1 {
				t.Errorf("no commit conflicted: the hosts did not race")
			}
			_, _, st := roomOf(t, a, "r1")
			for _, mid := range ids {
				if !st.Seen(mid) {
					t.Errorf("%s not in the shared seen set", mid)
				}
			}
		})
	}
}

// writeRoomSeats writes a seat map with a rooms column and the sessions it
// names: leader in projects/demo takes room ops by name, cli in projects/ops
// takes every room when cliRooms is *, zt is the human, relayed by
// projects/demo's advisor.
func writeRoomSeats(t *testing.T, root, cliRooms string) {
	t.Helper()
	m := "---\ntype: seats\n---\n# Seats\n\n| label | to | accepts | rooms |\n|---|---|---|---|\n" +
		"| leader | [[projects/demo/rosters/leader-peer-v1]] | text task question answer ack | ops |\n" +
		"| cli | [[projects/ops/rosters/worker-cli]] | text task | " + cliRooms + " |\n" +
		"| zt | human [[projects/demo/rosters/advisor-demo]] | text question answer | |\n"
	for _, d := range []string{"peers", "projects/demo/rosters", "projects/ops/rosters"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "peers", "seats.md"), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
}

// On a fleet host the seat map's rooms column routes a room record that
// names no agent: one record in the session of each row naming the room —
// by name, or by * — and none matching, the local quarantine; a record
// whose to names an agent reaches that label's row as a channel message
// does, an unmapped label refused. Each record is born with group, the room
// id, as its sixth key.
func TestRoomSeatMapRouting(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	root := filepath.Join(t.TempDir(), "sessions")
	writeRoomSeats(t, root, "*")
	a, b := newDir(t, uccCfg(root)), newDir(t, config{})
	ab := handshakeNamed(t, a, b, base, "bob", "alice")
	ops := createRoom(t, a, base, "ops")
	chat := createRoom(t, a, base, "chat")
	addToRoom(t, a, b, "ops", "bob")
	addToRoom(t, a, b, "chat", "bob")
	mustOK(t, "serve", "--dir", a, "--once")
	demo, opsDir := filepath.Join(root, "projects", "demo"), filepath.Join(root, "projects", "ops")
	A, B := ab.hostParty, ab.guestParty

	toOps, _ := roomSendOK(t, b, "--text", "to ops", ops[:8])
	toChat, _ := roomSendOK(t, b, "--text", "to chat", chat[:8])
	toZT, _ := roomSendOK(t, b, "--kind", "question", "--to", "alice/zt", "--text", "a question", chat[:8])
	toNobody, _ := roomSendOK(t, b, "--to", "alice/nobody", "--text", "lost", chat[:8])
	out := mustOK(t, "serve", "--dir", a, "--once")

	demoIn, opsIn := records(t, demo, deliver.Inbox), records(t, opsDir, deliver.Inbox)
	roomRecord(t, demoIn[toOps], B, A+"/leader", ops, "to ops")
	roomRecord(t, opsIn[toOps], B, A+"/cli", ops, "to ops")
	roomRecord(t, opsIn[toChat], B, A+"/cli", chat, "to chat")
	if demoIn[toChat] != nil {
		t.Fatal("the leader's row names ops alone and got the chat record")
	}
	roomRecord(t, demoIn[toZT], B, A+"/zt", chat, "a question")
	if opsIn[toZT] != nil {
		t.Fatal("a record to an agent reached the rooms rows too")
	}
	if _, err := os.Stat(deliverDirOf(a)); err == nil && bornAnywhere(t, deliverDirOf(a), toNobody) {
		t.Fatal("the unmapped label's record was born in the local delivery directory")
	}
	if !strings.Contains(out, `unmapped label "nobody": refused`) || bornAnywhere(t, root, toNobody) {
		t.Fatalf("the unmapped label was not refused, or was born:\n%s", out)
	}
	if len(demoIn) != 2 || len(opsIn) != 2 {
		t.Fatalf("demo holds %d records, ops %d; want 2 and 2", len(demoIn), len(opsIn))
	}

	// The map changes under serve: no row takes chat now.
	writeRoomSeats(t, root, "ops")
	none, _ := roomSendOK(t, b, "--text", "nobody takes it", chat[:8])
	mustOK(t, "serve", "--dir", a, "--once")
	if bornAnywhere(t, root, none) {
		t.Fatal("a record no row takes was born under the root")
	}
	q := records(t, deliverDirOf(a), deliver.Quarantine)
	roomRecord(t, q[none], B, A, chat, "nobody takes it")
}

// The roster moves between A's pull and its put: bob, an admin since the
// handover, removes carol. The relay answers A's put 409; A folds the
// removal and seals the same plaintext again to the roster as it now stands
// — a stanza for bob, none for carol, who left.
func TestRoomPut409ResealsToCurrentRoster(t *testing.T) {
	srv, base, front := startFront(t)
	tr := newTrio(t, base, srv, config{})
	mustOK(t, "room", "handover", "--dir", tr.a, "r1", "bob")
	mustOK(t, "serve", "--dir", tr.b, "--once")
	mustOK(t, "serve", "--dir", tr.c, "--once")
	m0 := srv.RoomMembership(tr.id)
	front.arm(func(http.ResponseWriter, *http.Request) bool {
		// A's own records never come back on its pull: the removal is bob's.
		if code, _, errb := cmd(t, "room", "remove", "--dir", tr.b, tr.bcRoom, "2"); code != 0 {
			t.Errorf("bob's remove of carol: exit %d: %s", code, errb)
		}
		return false
	})
	code, out, errb := cmd(t, "send", "--dir", tr.a, "--text", "after the removal", "r1")
	if code != 0 || roomSentRE.FindStringSubmatch(out) == nil {
		t.Fatalf("A's send: exit %d\n%s%s", code, out, errb)
	}
	if !strings.Contains(errb, "idx 2 left") {
		t.Fatalf("A's send did not fold the removal after the 409:\n%s", errb)
	}
	if srv.RoomMembership(tr.id) != m0+2 {
		t.Fatalf("membership %d, want %d: the removal record's bump and the revoke", srv.RoomMembership(tr.id), m0+2)
	}
	rows := srv.RoomRecords(tr.id)
	var last []byte
	for _, r := range rows {
		if r.Idx == 0 {
			last = mustB64(t, r.Body)
		}
	}
	rec, err := sealed.Parse(last)
	if err != nil {
		t.Fatal(err)
	}
	if to := rec.Recipients(); !slices.Contains(to, 1) || slices.Contains(to, 2) {
		t.Fatalf("A's record is sealed to %v: want bob (1), not carol (2)", to)
	}
}

// peer send into a room refuses a doc and a file — a room carries no blob —
// and a name both a peer and a room carry: the room is named by its id then.
func TestRoomSendRefusesBlobsAndAmbiguousName(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	a, b := newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	createRoom(t, a, base, "r1")
	f := filepath.Join(t.TempDir(), "attachment.txt")
	if err := os.WriteFile(f, []byte("a blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"doc", "file"} {
		code, _, errb := cmd(t, "send", "--dir", a, "--kind", kind, "--file", f, "r1")
		if code == 0 || !strings.Contains(errb, "a "+kind+" goes to a peer: a room carries no blob") {
			t.Fatalf("a %s into a room: exit %d, %s", kind, code, errb)
		}
	}
	id := createRoom(t, a, base, "bob")
	mustRefuse(t, "both a peer and a room are named bob: name the room by its id, "+id, "send", "--dir", a, "--text", "x", "bob")
}

// A room pull a command runs commits the records it passes and leaves their
// birth to serve: a record peer send's pull passes is born in the delivery
// directory serve runs with, never in the default one.
func TestRoomCommandPullBirthsInServeDeliver(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	custom := filepath.Join(t.TempDir(), "agent-inbox")
	mustOK(t, "serve", "--dir", tr.b, "--deliver", custom, "--once")
	id, _ := roomSendOK(t, tr.a, "--text", "for bob's agent", "r1")
	roomSendOK(t, tr.b, "--text", "reply", tr.bcRoom) // its pull passes A's record
	mustOK(t, "serve", "--dir", tr.b, "--deliver", custom, "--once")
	inCustom, inDefault := records(t, custom, deliver.Inbox)[id] != nil, records(t, deliverDirOf(tr.b), deliver.Inbox)[id] != nil
	if !inCustom || inDefault {
		t.Fatalf("record %s: in serve's --deliver directory %v, in the default one %v", id, inCustom, inDefault)
	}
}

// A delivery that waits on a seat's session keeps its record in the room
// spool while the cursor and the fold go on: the relay's membership version
// is adopted at head, a send lands at once, and the waiting record is born
// once the session is on this root.
func TestRoomWaitDoesNotBlockPuts(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	root := filepath.Join(t.TempDir(), "sessions")
	writeRoomSeats(t, root, "*")
	a, b := newDir(t, uccCfg(root)), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	mustOK(t, "serve", "--dir", a, "--once")
	mustOK(t, "serve", "--dir", b, "--once")
	ops := filepath.Join(root, "projects", "ops")
	if err := os.RemoveAll(ops); err != nil {
		t.Fatal(err)
	}
	waiting, _ := roomSendOK(t, b, "--text", "waits at A", id[:8])
	_, aref, _ := roomOf(t, a, "r1")
	// The membership moves with no record: another mint.
	if _, err := relay.New(base, nil).AddMember(ctx, id, aref.Token, relay.RoleWrite); err != nil {
		t.Fatal(err)
	}
	roomSendOK(t, a, "--text", "from A", "r1")
	mustOK(t, "serve", "--dir", a, "--once")
	if st := mustOK(t, "status", "--dir", a); strings.Contains(st, "waiting in the room outbox") {
		t.Fatalf("A's record waits behind the delivery:\n%s", st)
	}
	if _, _, ast := roomOf(t, a, "r1"); ast.Membership() != srv.RoomMembership(id) {
		t.Fatalf("A holds membership %d, the relay %d", ast.Membership(), srv.RoomMembership(id))
	}
	if bornAnywhere(t, root, waiting) {
		t.Fatalf("%s is born while its session is absent", waiting)
	}
	if err := os.MkdirAll(ops, 0o755); err != nil {
		t.Fatal(err)
	}
	mustOK(t, "serve", "--dir", a, "--once")
	if records(t, ops, deliver.Inbox)[waiting] == nil {
		t.Fatalf("%s is not born in %s once the session is back", waiting, ops)
	}
}

// A removal record behind a waiting delivery is folded before anything is
// sealed at the version its bump set: a send past the wait is sealed
// without the removed member, which reads nothing of it; once the revoke
// lands, the next send takes the 409, pulls to head and lands.
func TestRoomWaitBeforeRemovalSealsWithoutRemoved(t *testing.T) {
	srv, base, front := startPathFront(t, http.MethodDelete, "/members/2")
	root := filepath.Join(t.TempDir(), "sessions")
	writeRoomSeats(t, root, "*")
	a, b, c := newDir(t, config{}), newDir(t, config{}), newDir(t, config{})
	x := newDir(t, uccCfg(root))
	handshakeNamed(t, a, b, base, "bob", "alice")
	handshakeNamed(t, a, c, base, "carol", "alice")
	ax := handshakeNamed(t, a, x, base, "xavier", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")   // idx 1
	addToRoom(t, a, c, "r1", "carol") // idx 2
	addToRoom(t, a, x, "r1", "xavier")
	for _, d := range []string{a, b, c, x} {
		mustOK(t, "serve", "--dir", d, "--once")
	}
	if err := os.RemoveAll(filepath.Join(root, "projects", "ops")); err != nil {
		t.Fatal(err)
	}
	roomSendOK(t, b, "--to", ax.guestParty+"/zt", "--text", "deliverable", id[:8]) // born at X
	roomSendOK(t, b, "--text", "waits at X", id[:8])                               // X's * row waits
	front.arm(fail503)                                                             // the removal's revoke
	mustOK(t, "room", "remove", "--dir", a, "r1", "carol")

	hello, _ := roomSendOK(t, x, "--text", "hello", id[:8])
	rows := srv.RoomRecords(id)
	last := rows[len(rows)-1]
	rec, err := sealed.Parse(mustB64(t, last.Body))
	if err != nil {
		t.Fatal(err)
	}
	if last.Idx != 3 || slices.Contains(rec.Recipients(), 2) {
		t.Fatalf("X's record #%d (writer idx %d) is sealed to %v, the removed idx 2 among them", last.Seq, last.Idx, rec.Recipients())
	}
	mustOK(t, "serve", "--dir", c, "--once")
	if records(t, deliverDirOf(c), deliver.Inbox)[hello] != nil {
		t.Fatal("C, removed, read X's record put after its removal")
	}
	mustOK(t, "serve", "--dir", a, "--once") // the revoke lands
	roomSendOK(t, x, "--text", "hello again", id[:8])
}
