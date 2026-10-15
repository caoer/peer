package main

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/room"
)

var createdRE = regexp.MustCompile(`(?m)^created room (\S+) \(([0-9a-f]{32})\)`)

// createRoom runs peer room create on dir and returns the room id.
func createRoom(t *testing.T, dir, base, name string, flags ...string) string {
	t.Helper()
	args := append([]string{"room", "create", "--dir", dir, "--relay", base, "--login", login}, flags...)
	out := mustOK(t, append(args, name)...)
	m := createdRE.FindStringSubmatch(out)
	if m == nil || m[1] != name {
		t.Fatalf("create printed no room line:\n%s", out)
	}
	return m[2]
}

// addToRoom runs one add to its end: the adder's peer room add, then the
// serves that carry invite → accept → (mint) seat → join → (roster) token,
// and the newcomer's serve that takes the token and pulls the room. It
// returns each serve's output in order.
func addToRoom(t *testing.T, adderDir, newDir, roomName, peerName string) []string {
	t.Helper()
	mustOK(t, "room", "add", "--dir", adderDir, roomName, peerName)
	var outs []string
	for i, dir := range []string{newDir, adderDir, newDir, adderDir, newDir} {
		out := mustOK(t, "serve", "--dir", dir, "--once")
		outs = append(outs, out)
		if want := []string{"invites you", "minted idx", "seated at idx", "its token goes out", "joined room"}[i]; !strings.Contains(out, want) {
			t.Fatalf("serve %d of the add: no %q in\n%s", i+1, want, out)
		}
	}
	return outs
}

// roomOf is the room's rooms-record entry and state as a fresh process loads them.
func roomOf(t *testing.T, dir, name string) (*party, roomRef, *room.State) {
	t.Helper()
	ctx := context.Background()
	p, err := openParty(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		t.Fatal(err)
	}
	ref := l.byName(name)
	if ref == nil {
		t.Fatalf("%s: no room %s", dir, name)
	}
	st, err := room.Load(ctx, p.backend, ref.ID)
	if err != nil {
		t.Fatal(err)
	}
	return p, *ref, st
}

// putRoomText puts a text record in the room as dir's party, the way a room
// send seals one (to head, counter committed, sealed to the roster, put).
func putRoomText(t *testing.T, dir, name, text string) (string, int64) {
	t.Helper()
	ctx := context.Background()
	p, ref, _ := roomOf(t, dir, name)
	c, err := p.openRoom(ctx, ref, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.pull(ctx); err != nil {
		t.Fatal(err)
	}
	m, err := newRoomMessage(p.partyID(), ref.ID, "text", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	ctr := c.st.NextCounter()
	if err := c.st.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seq, err := c.send(ctx, m, ctr)
	if err != nil {
		t.Fatal(err)
	}
	return m.ID, seq
}

// membersLine is the line of peer room members for idx.
func membersLine(t *testing.T, out string, idx string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "  "+idx+"  ") {
			return l
		}
	}
	t.Fatalf("no member at idx %s in\n%s", idx, out)
	return ""
}

// Three parties on the fake relay: A creates, adds B, then C. Each step of
// the join runs in the adder's order (invite, accept, mint, seat, join,
// roster, token); the newcomer reads nothing below its from; every member
// folds the same roster; members marks each entry.
func TestRoomThreePartiesCreateAddAdd(t *testing.T) {
	ctx := context.Background()
	srv, rc, base := relaytest.Start(t, login)
	a, b, c := newDir(t, config{}), newDir(t, config{}), newDir(t, config{})
	ab := handshakeNamed(t, a, b, base, "bob", "alice")
	ac := handshakeNamed(t, a, c, base, "carol", "alice")

	id := createRoom(t, a, base, "r1")
	if rows := srv.RoomRecords(id); len(rows) != 1 || rows[0].Idx != 0 {
		t.Fatalf("after create the relay holds %+v, want record #0 from idx 0", rows)
	}
	_, aref, ast := roomOf(t, a, "r1")
	if aref.Stage != stageJoined || ast.Idx() != 0 || !ast.IsAdmin(0) || ast.Add() != room.AddAdmins || len(ast.Members()) != 1 {
		t.Fatalf("creator: ref %+v idx %d admin %v add %s members %d", aref, ast.Idx(), ast.IsAdmin(0), ast.Add(), len(ast.Members()))
	}

	addToRoom(t, a, b, "r1", "bob")
	_, bref, bst := roomOf(t, b, id[:8])
	if bref.Stage != stageJoined || bref.Idx != 1 || bst.Idx() != 1 || bref.From != 1 {
		t.Fatalf("B after the add: ref %+v state idx %d", bref, bst.Idx())
	}
	if m := bst.Member(1); m == nil || m.Party != ab.guestParty || bst.Member(0) == nil || bst.Member(0).Party != ab.hostParty {
		t.Fatalf("B's roster: %+v", bst.Members())
	}
	if rows := srv.RoomRecords(id); len(rows) != 2 || rows[1].Idx != 0 {
		t.Fatalf("after B's add the relay holds %d records, want #0 and A's roster #1", len(rows))
	}

	// Records before C's mint: C's from is past them, and C never reads them.
	textID, textSeq := putRoomText(t, a, "r1", "before carol")
	addToRoom(t, a, c, "r1", "carol")
	_, cref, cst := roomOf(t, c, id[:8])
	if cref.Idx != 2 || cref.From <= textSeq {
		t.Fatalf("C: idx %d from %d; the text before the add is #%d", cref.Idx, cref.From, textSeq)
	}
	page, err := rc.PullRoom(ctx, id, cref.Token, -1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range page.Records {
		if r.Seq < cref.From {
			t.Fatalf("C pulled #%d below its from #%d", r.Seq, cref.From)
		}
	}
	if cst.Seen(textID) {
		t.Fatal("C saw the text put before its mint")
	}
	if len(cst.Members()) != 3 {
		t.Fatalf("C's roster has %d members, want 3", len(cst.Members()))
	}

	// B reads A's roster record adding C and folds it.
	mustOK(t, "serve", "--dir", b, "--once")
	_, _, bst = roomOf(t, b, id[:8])
	if m := bst.Member(2); m == nil || m.Party != ac.guestParty {
		t.Fatalf("B's roster after C's add: %+v", bst.Members())
	}
	_, _, ast = roomOf(t, a, "r1")
	if len(ast.Members()) != 3 || ast.Membership() != srv.RoomMembership(id) {
		t.Fatalf("A: %d members, membership %d, relay %d", len(ast.Members()), ast.Membership(), srv.RoomMembership(id))
	}

	// members: you, matches your channel <name>, vouched by the admin.
	out := mustOK(t, "room", "members", "--dir", b, id[:8])
	if l := membersLine(t, out, "0"); !strings.Contains(l, ab.hostParty) || !strings.Contains(l, "matches your channel alice") || !strings.Contains(l, "admin") {
		t.Fatalf("B's members, idx 0: %q", l)
	}
	if l := membersLine(t, out, "1"); !strings.Contains(l, "you") {
		t.Fatalf("B's members, idx 1: %q", l)
	}
	if l := membersLine(t, out, "2"); !strings.Contains(l, ac.guestParty) || !strings.Contains(l, "vouched by the admin") {
		t.Fatalf("B's members, idx 2: %q", l)
	}
	out = mustOK(t, "room", "members", "--dir", a, "r1")
	if l := membersLine(t, out, "1"); !strings.Contains(l, "matches your channel bob") {
		t.Fatalf("A's members, idx 1: %q", l)
	}
	if l := membersLine(t, out, "2"); !strings.Contains(l, "matches your channel carol") {
		t.Fatalf("A's members, idx 2: %q", l)
	}
	if strings.Contains(out, "adding") {
		t.Fatalf("A still lists an add in flight:\n%s", out)
	}

	// A double add is refused.
	mustRefuse(t, "is in it already, at idx 1", "room", "add", "--dir", a, "r1", "bob")
}

// A record put between the mint and the roster record is sealed to the old
// set: the newcomer reads past it (no stanza), the members before it open it.
func TestRoomRecordInMintRosterWindow(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	a, b, c := newDir(t, config{}), newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	handshakeNamed(t, a, c, base, "carol", "alice")
	id := createRoom(t, a, base, "w")
	addToRoom(t, a, b, "w", "bob")

	mustOK(t, "room", "add", "--dir", a, "w", "carol")
	mustOK(t, "serve", "--dir", c, "--once") // invite → accept
	mustOK(t, "serve", "--dir", a, "--once") // accept → mint, seat
	// The window: C's idx is minted, the roster record not yet put.
	textID, textSeq := putRoomText(t, b, id[:8], "in the window")
	mustOK(t, "serve", "--dir", c, "--once") // seat → join
	out := mustOK(t, "serve", "--dir", a, "--once")
	if !strings.Contains(out, "delivered text "+textID) {
		t.Fatalf("A did not open B's text in the window:\n%s", out)
	}
	out = mustOK(t, "serve", "--dir", c, "--once") // token → joined, pull
	if !strings.Contains(out, "joined room") || strings.Contains(out, "delivered text") {
		t.Fatalf("C's serve:\n%s", out)
	}
	_, cref, cst := roomOf(t, c, id[:8])
	if textSeq < cref.From {
		t.Fatalf("the window text #%d is below C's from #%d: not in the window", textSeq, cref.From)
	}
	if cst.Cursor() < textSeq || cst.Seen(textID) {
		t.Fatalf("C: cursor %d past the window text #%d, saw it %v", cst.Cursor(), textSeq, cst.Seen(textID))
	}
	if n := len(srv.RoomRecords(id)); int64(n) <= textSeq {
		t.Fatalf("relay holds %d records", n)
	}
}

// A transient relay error while the adder handles room-join leaves the join
// in the spool: a later round posts its roster record and the token goes
// out. A re-add while the add is seated sends the seat again and keeps the
// minted idx; nothing is minted twice.
func TestRoomJoinTransientErrorReplays(t *testing.T) {
	ctx := context.Background()
	_, base, front := startPathFront(t, http.MethodGet, "/records")
	a, b := newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	mustOK(t, "room", "add", "--dir", a, "r1", "bob")
	mustOK(t, "serve", "--dir", b, "--once") // invite → accept
	mustOK(t, "serve", "--dir", a, "--once") // accept → mint, seat
	mustOK(t, "serve", "--dir", b, "--once") // seat → join
	front.arm(fail503)                       // the adder's pull before the roster record
	cmd(t, "serve", "--dir", a, "--once")
	if ref := refOf(t, a, "r1"); len(ref.Adds) != 1 || ref.Adds[0].Stage != addSeated || ref.Adds[0].Idx != 1 {
		t.Fatalf("after the 503 the add is %+v, want seated at idx 1", ref.Adds)
	}
	if out := mustOK(t, "room", "add", "--dir", a, "r1", "bob"); !strings.Contains(out, "seat again") {
		t.Errorf("a re-add while seated:\n%s", out)
	}
	for _, dir := range []string{b, a, b, a, b} {
		mustOK(t, "serve", "--dir", dir, "--once")
	}
	if bref := refOf(t, b, id[:8]); bref.Stage != stageJoined || bref.Idx != 1 {
		t.Fatalf("the newcomer is %s at idx %d, want joined at idx 1", bref.Stage, bref.Idx)
	}
	ms, err := relay.New(base, nil).ListMembers(ctx, id, refOf(t, a, "r1").Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms.Members) != 2 {
		t.Fatalf("the relay holds %d seats, want 2 — one mint for bob: %+v", len(ms.Members), ms.Members)
	}
}

// A change folded between the invite and the mint — a handover here — is
// below the newcomer's from and in no invite: after the mint the adder
// brings its fold to from, and a room that changed gets a fresh invite
// before the seat. The newcomer's admin set is everyone else's, and a
// removal by the new admin folds there too.
func TestRoomInviteRefreshedAfterMint(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	a, b, c := newDir(t, config{}), newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	handshakeNamed(t, a, c, base, "carol", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	mustOK(t, "room", "add", "--dir", a, "r1", "carol") // the invite: admins [0]
	mustOK(t, "room", "handover", "--dir", a, "r1", "bob")
	mustOK(t, "serve", "--dir", b, "--once")
	for _, dir := range []string{c, a, c, a, c, a, c} {
		mustOK(t, "serve", "--dir", dir, "--once")
	}
	_, _, ast := roomOf(t, a, "r1")
	_, cref, cst := roomOf(t, c, id[:8])
	if cref.Stage != stageJoined || !slices.Equal(cst.Admins(), ast.Admins()) {
		t.Fatalf("C is %s with admins %v; A holds %v", cref.Stage, cst.Admins(), ast.Admins())
	}
	mustOK(t, "room", "remove", "--dir", b, id[:8], "0")
	mustOK(t, "serve", "--dir", c, "--once")
	if _, _, cst := roomOf(t, c, id[:8]); cst.Member(0) != nil {
		t.Fatalf("C still holds idx 0 after bob, an admin, removed it")
	}
}

// Under --add members a member adds a party it holds a confirmed channel
// with, and every member folds that roster; under admins the member's add
// is refused before anything is sent.
func TestRoomMemberAdd(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	a, b, c := newDir(t, config{}), newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	bc := handshakeNamed(t, b, c, base, "carol", "bob")

	id := createRoom(t, a, base, "m", "--add", "members")
	addToRoom(t, a, b, "m", "bob")
	addToRoom(t, b, c, id[:8], "carol")
	_, _, cst := roomOf(t, c, id[:8])
	if cst.Idx() != 2 || len(cst.Members()) != 3 || cst.Add() != room.AddMembers {
		t.Fatalf("C: idx %d, %d members, add %s", cst.Idx(), len(cst.Members()), cst.Add())
	}
	out := mustOK(t, "serve", "--dir", a, "--once")
	if !strings.Contains(out, "idx 2 joined: "+bc.guestParty) {
		t.Fatalf("A did not fold B's roster record:\n%s", out)
	}
	_, _, ast := roomOf(t, a, "m")
	if m := ast.Member(2); m == nil || m.Party != bc.guestParty {
		t.Fatalf("A's roster: %+v", ast.Members())
	}
	out = mustOK(t, "room", "members", "--dir", a, "m")
	if l := membersLine(t, out, "2"); !strings.Contains(l, "vouched by the admin") {
		t.Fatalf("A's members, idx 2: %q", l)
	}

	// Under admins: B is no admin, so its add refuses and no invite leaves.
	id2 := createRoom(t, a, base, "adm")
	addToRoom(t, a, b, "adm", "bob")
	before := len(srv.Envelopes(bc.channel, "h2g"))
	mustRefuse(t, "its add setting is admins and you are not in its admin set", "room", "add", "--dir", b, id2[:8], "carol")
	if after := len(srv.Envelopes(bc.channel, "h2g")); after != before {
		t.Fatalf("the refused add put %d envelopes on the channel", after-before)
	}
}

// A room-invite goes only over a confirmed channel: an invited peer that has
// not accepted, and a name with no channel, are refused before anything is sent.
func TestRoomAddRefusesWithoutConfirmedChannel(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	a := newDir(t, config{})
	createRoom(t, a, base, "r")
	out := mustOK(t, "invite", "--dir", a, "--relay", base, "--login", login, "dave")
	link, _, _ := strings.Cut(out, "\n")
	l, err := invite.Parse(link, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "dave is not a confirmed channel", "room", "add", "--dir", a, "r", "dave")
	if rows := srv.Envelopes(l.Channel, "h2g"); len(rows) != 1 {
		t.Fatalf("the refused add put %d envelopes on dave's channel", len(rows)-1)
	}
	mustRefuse(t, "no peer named erin", "room", "add", "--dir", a, "r", "erin")
	mustRefuse(t, "no room named nope", "room", "add", "--dir", a, "nope", "dave")
	_, ref, _ := roomOf(t, a, "r")
	if len(ref.Adds) != 0 {
		t.Fatalf("refused adds left %+v", ref.Adds)
	}
}

// The roster record adding carol fails its put and waits in the room outbox;
// a later send puts it, so the add is rostered and its token has not gone
// out. A re-run of peer room add sends the stored token again — no second
// mint, the relay's members as they were — and carol joins with it.
func TestRoomAddRerunResendsToken(t *testing.T) {
	ctx := context.Background()
	srv, base, front := startFront(t)
	a, c := newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, c, base, "carol", "alice")
	id := createRoom(t, a, base, "r1")
	mustOK(t, "room", "add", "--dir", a, "r1", "carol")
	for i, dir := range []string{c, a, c} {
		if out, want := mustOK(t, "serve", "--dir", dir, "--once"), []string{"invites you", "minted idx", "seated at idx"}[i]; !strings.Contains(out, want) {
			t.Fatalf("serve %d of the add: no %q in\n%s", i+1, want, out)
		}
	}
	// Every room put fails for the length of A's serve: the step's put and
	// the round's outbox flush, which would land the record and send the
	// token in the same round.
	var down func(http.ResponseWriter, *http.Request) bool
	down = func(w http.ResponseWriter, r *http.Request) bool {
		front.arm(down)
		return fail503(w, r)
	}
	front.arm(down)
	out := mustOK(t, "serve", "--dir", a, "--once")
	front.onPut.Store(nil)
	if !strings.Contains(out, "is committed and did not land") || strings.Contains(out, "its token went out") {
		t.Fatalf("A's serve on carol's join, the roster put failing:\n%s", out)
	}
	roomSendOK(t, a, "--text", "the roster record goes first", "r1")
	if out := mustOK(t, "room", "members", "--dir", a, "r1"); !strings.Contains(out, "adding carol: idx 1 in the roster, token not sent") {
		t.Fatalf("A's members after the roster record landed:\n%s", out)
	}
	m1 := srv.RoomMembership(id)
	_, aref, _ := roomOf(t, a, "r1")
	ms1, err := relay.New(base, nil).ListMembers(ctx, id, aref.Token)
	if err != nil {
		t.Fatal(err)
	}

	out = mustOK(t, "room", "add", "--dir", a, "r1", "carol")
	if !strings.Contains(out, "room r1: sent carol the token for idx 1 again") {
		t.Fatalf("the add re-run:\n%s", out)
	}
	ms2, err := relay.New(base, nil).ListMembers(ctx, id, aref.Token)
	if err != nil || len(ms2.Members) != len(ms1.Members) || srv.RoomMembership(id) != m1 {
		t.Fatalf("the re-run minted: members %d → %d, membership %d → %d (%v)", len(ms1.Members), len(ms2.Members), m1, srv.RoomMembership(id), err)
	}
	if out := mustOK(t, "serve", "--dir", c, "--once"); !strings.Contains(out, "joined room") {
		t.Fatalf("carol's serve on the resent token:\n%s", out)
	}
	if _, _, cst := roomOf(t, c, id[:8]); cst.Idx() != 1 || len(cst.Members()) != 2 {
		t.Fatalf("carol's state: idx %d, %d members", cst.Idx(), len(cst.Members()))
	}
}
