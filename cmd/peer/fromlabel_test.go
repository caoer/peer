package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/relay/relaytest"
)

// The real case, huaibin #15: ZT's seat map before the 7aac59f8 row. The SA
// Feishu DM seat 7aac59f8 sent --from 7aac59f8; huaibin's answer to
// <party>/7aac59f8 was refused at workstation-nyc-2's border as an unmapped
// label and lost. The row added afterwards is row7aac59f8.
const (
	seats15     = "zt-before-7aac59f8.md"
	row7aac59f8 = "| 7aac59f8 | [[year=2026/month=09/29-12-super-advisor/rosters/worker-sa-feishu-dm]] | text task question answer doc file ack |\n"
	feishuSeat  = "year=2026/month=09/29-12-super-advisor/rosters/worker-sa-feishu-dm"
	superSeat   = "year=2026/month=09/29-12-super-advisor/rosters/advisor-super"
)

// root15 is a sessions root holding the pre-row map.
func root15(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(filepath.Join(root, "peers"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeMap15(t, root, "")
	return root
}

// writeMap15 writes the pre-row map with extra rows after its last.
func writeMap15(t *testing.T, root, extra string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "seats", "testdata", seats15))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "peers", "seats.md"), append(b, extra...), 0o644); err != nil {
		t.Fatal(err)
	}
}

// asSeat makes the test's process an agent whose card holds the seat.
func asSeat(t *testing.T, root, short, seat string) {
	t.Helper()
	dir := filepath.Join(root, "agents", short)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	card := "---\ntype: agent\nseat: \"[[" + seat + "]]\"\n---\n# " + short + "\n"
	if err := os.WriteFile(filepath.Join(dir, short+".md"), []byte(card), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CODE_SESSION_ID", short+"-0000-4000-8000-000000000000")
}

// #15 against the pre-row map: --from 7aac59f8 is refused on a channel send
// and on a file send, before anything reaches the relay, and the error names
// the map and this seat's labels (none); a mapped label and no --from pass.
// With the row added — the map as it is now — --from 7aac59f8 passes.
func TestSendFromUnmappedLabel(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	root := root15(t)
	asSeat(t, root, "7aac59f8", feishuSeat)
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)
	h2g := len(srv.Envelopes(p.channel, "h2g"))

	want := `--from "7aac59f8": the seat map ` + filepath.Join(root, "peers", "seats.md") + ` has no row for it`
	mustRefuse(t, want, "send", "--dir", p.hostDir, "--from", "7aac59f8", "--text", "calib?", "ancan")
	mustRefuse(t, "this seat ("+feishuSeat+") may send from: none", "send", "--dir", p.hostDir, "--from", "7aac59f8", "--text", "calib?", "ancan")
	f := filepath.Join(t.TempDir(), "peer-ask-hb-calib.txt")
	if err := os.WriteFile(f, []byte("calib?"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, want, "send", "--dir", p.hostDir, "--from", "7aac59f8", "--kind", "file", "--file", f, "ancan")
	if n := len(srv.Envelopes(p.channel, "h2g")); n != h2g {
		t.Fatalf("a refused send put %d envelopes on the channel", n-h2g)
	}

	sendOK(t, p.hostDir, "--from", "sa", "--text", "from sa", "ancan")
	sendOK(t, p.hostDir, "--text", "from the party", "ancan")

	writeMap15(t, root, row7aac59f8)
	sendOK(t, p.hostDir, "--from", "7aac59f8", "--text", "calib?", "ancan")
	sendOK(t, p.hostDir, "--from", "sa", "--text", "from sa", "ancan")
}

// The labels in the error are the calling seat's rows, a human row it relays
// for included; a seat that cannot be resolved gets every label and is told
// so.
func TestSendFromLabelsOfTheSeat(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	root := root15(t)
	asSeat(t, root, "ff29b7c4", superSeat)
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)

	mustRefuse(t, "this seat ("+superSeat+") may send from: zt, sa;", "send", "--dir", p.hostDir, "--from", "ff29b7c4", "--text", "x", "ancan")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	mustRefuse(t, "this seat was not resolved (CLAUDE_CODE_SESSION_ID is not set) — the map's labels: zt, sa, liaison, cli, assistant, install, cto, chan-rachel, ml-engineer;",
		"send", "--dir", p.hostDir, "--from", "ff29b7c4", "--text", "x", "ancan")
}

// A host with no seat map configured sends from any label, as before.
func TestSendFromWithoutSeatMap(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	sendOK(t, p.hostDir, "--from", "7aac59f8", "--text", "no map here", "ancan")
	sendOK(t, p.guestDir, "--from", "7aac59f8", "--text", "no map here", "zt/advisor")
}

// A room send takes the same check: --from 7aac59f8 refused against the
// pre-row map, --from sa and no --from sent.
func TestRoomSendFromUnmappedLabel(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	root := root15(t)
	asSeat(t, root, "7aac59f8", feishuSeat)
	a, b := newDir(t, uccCfg(root)), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	createRoom(t, a, base, "ops")
	addToRoom(t, a, b, "ops", "bob")

	mustRefuse(t, "this seat ("+feishuSeat+") may send from: none", "send", "--dir", a, "--from", "7aac59f8", "--text", "calib?", "ops")
	if out := mustOK(t, "send", "--dir", a, "--from", "sa", "--text", "from sa", "ops"); !strings.Contains(out, "sent ") {
		t.Fatalf("room send from sa printed no receipt:\n%s", out)
	}
	roomSendOK(t, a, "--text", "from the party", "ops")
}
