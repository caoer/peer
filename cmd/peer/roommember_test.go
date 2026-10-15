package main

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/sealed"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// withoutRoster is the inbox less the roster notices: the records a test
// counts by what was sent.
func withoutRoster(t *testing.T, in map[string][]byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for id, rec := range in {
		if _, v, _ := frontMatter(t, rec); v["kind"] != deliver.KindRoster {
			out[id] = rec
		}
	}
	return out
}

// rosterNotices is the inbox's roster notices by message id: each body.
func rosterNotices(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for id, rec := range records(t, dir, deliver.Inbox) {
		_, v, body := frontMatter(t, rec)
		if v["kind"] != deliver.KindRoster {
			continue
		}
		if v["verified"] != "true" || v["group"] == "" || !strings.Contains(body, "members of room "+v["group"]+" now: ") {
			t.Fatalf("roster notice %s: %s", id, rec)
		}
		out[id] = body
	}
	return out
}

// pathFront fronts the fake relay; an armed hook runs once on the next
// request of method whose path ends in suffix, and answers it itself when it
// returns true.
type pathFront struct {
	proxy  http.Handler
	method string
	suffix string
	hook   atomic.Pointer[func(http.ResponseWriter, *http.Request) bool]
}

func (f *pathFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == f.method && strings.HasSuffix(r.URL.Path, f.suffix) {
		if h := f.hook.Swap(nil); h != nil && (*h)(w, r) {
			return
		}
	}
	f.proxy.ServeHTTP(w, r)
}

func (f *pathFront) arm(h func(http.ResponseWriter, *http.Request) bool) { f.hook.Store(&h) }

func startPathFront(t *testing.T, method, suffix string) (*relaytest.Server, string, *pathFront) {
	t.Helper()
	srv, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	f := &pathFront{proxy: httputil.NewSingleHostReverseProxy(target), method: method, suffix: suffix}
	front := httptest.NewServer(f)
	t.Cleanup(front.Close)
	return srv, front.URL + "/peer", f
}

func fail503(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	io.WriteString(w, `{"error":"down for a moment","code":"internal_error"}`)
	return true
}

// The removal record travels with bump: between it and the revoke a put at
// the old membership is 409, so no stale put lands sealed to the leaver. The
// removed member's next pull says so and its state is dropped; the rest fold
// idx 1 out and get a roster notice. A revoke that fails after the record is
// retried by serve.
func TestRoomRemoveBumpsBeforeRevoke(t *testing.T) {
	ctx := context.Background()
	srv, base, front := startPathFront(t, http.MethodDelete, "/members/1")
	tr := newTrio(t, base, srv, config{})
	_, cref, cst := roomOf(t, tr.c, tr.bcRoom)
	m0 := srv.RoomMembership(tr.id)
	var stale, current error
	front.arm(func(http.ResponseWriter, *http.Request) bool {
		// The record is on the relay, the revoke not yet: C puts at the
		// membership it holds, then at the relay's.
		rc := relay.New(base, nil)
		_, stale = rc.PutRecord(ctx, tr.id, cref.Token, []byte("x"), cst.Membership(), false)
		_, current = rc.PutRecord(ctx, tr.id, cref.Token, []byte("x"), srv.RoomMembership(tr.id), false)
		return false
	})
	out := mustOK(t, "room", "remove", "--dir", tr.a, "r1", "bob")
	if !strings.Contains(out, "idx 1 ("+tr.ab.guestParty+") removed") || !strings.Contains(out, "idx 1 revoked") {
		t.Fatalf("remove:\n%s", out)
	}
	if !errors.Is(stale, relay.ErrStaleMembership) || current != nil {
		t.Fatalf("a put at the old membership after the removal record: %v; at the bumped one: %v", stale, current)
	}
	if srv.RoomMembership(tr.id) != m0+2 {
		t.Fatalf("membership %d, want %d: one bump for the record, one for the revoke", srv.RoomMembership(tr.id), m0+2)
	}
	_, aref, ast := roomOf(t, tr.a, "r1")
	if ast.Member(1) != nil || len(ast.Members()) != 2 || len(aref.Removals) != 0 {
		t.Fatalf("A after the remove: %d members, removals %v", len(ast.Members()), aref.Removals)
	}
	out = mustOK(t, "serve", "--dir", tr.b, "--once")
	if !strings.Contains(out, "you are out of the room: removed") {
		t.Fatalf("B's serve after its removal:\n%s", out)
	}
	if out := mustOK(t, "status", "--dir", tr.b); !strings.Contains(out, "room "+tr.bcRoom+" ("+tr.id+"): removed") {
		t.Fatalf("B's status:\n%s", out)
	}
	if _, err := room.Load(ctx, mustParty(t, tr.b).backend, tr.id); !errors.Is(err, room.ErrNoRoom) {
		t.Fatalf("B's state after the removal: %v, want dropped", err)
	}
	mustRefuse(t, "you were removed from it already", "room", "leave", "--dir", tr.b, tr.bcRoom)
	out = mustOK(t, "serve", "--dir", tr.c, "--once")
	if !strings.Contains(out, "idx 1 left") || !strings.Contains(out, "delivered roster") {
		t.Fatalf("C's serve on the removal:\n%s", out)
	}
	_, _, cst = roomOf(t, tr.c, tr.bcRoom)
	if cst.Member(1) != nil || len(cst.Members()) != 2 {
		t.Fatalf("C's roster after the removal: %+v", cst.Members())
	}
	found := false
	for _, body := range rosterNotices(t, deliverDirOf(tr.c)) {
		if strings.Contains(body, "idx 1 left\n") && strings.Contains(body, "idx 2 "+tr.ac.guestParty+" (you)") && !strings.Contains(body, "idx 1 "+tr.ab.guestParty) {
			found = true
		}
	}
	if !found {
		t.Fatalf("C has no roster notice for idx 1 leaving: %+v", rosterNotices(t, deliverDirOf(tr.c)))
	}
	if bref := refOf(t, tr.b, tr.bcRoom); bref.Token != "" || bref.Stage != stageRemoved {
		t.Fatalf("B's rooms record after the removal: %+v", bref)
	}

	// The revoke of C fails after the record: serve retries it.
	front2 := &pathFront{proxy: front.proxy, method: http.MethodDelete, suffix: "/members/2"}
	srv2 := httptest.NewServer(front2)
	t.Cleanup(srv2.Close)
	front2.arm(fail503)
	_, aref, _ = roomOf(t, tr.a, "r1")
	setRelay(t, tr.a, aref.ID, srv2.URL+"/peer")
	out = mustOK(t, "room", "remove", "--dir", tr.a, "r1", "2")
	if !strings.Contains(out, "idx 2 ("+tr.ac.guestParty+") removed") || !strings.Contains(out, "the revoke of idx 2 did not land") {
		t.Fatalf("remove with a failing revoke:\n%s", out)
	}
	if _, aref, _ = roomOf(t, tr.a, "r1"); len(aref.Removals) != 1 || aref.Removals[0] != 2 {
		t.Fatalf("the failed revoke is not recorded: %v", aref.Removals)
	}
	if ms, err := relay.New(base, nil).ListMembers(ctx, tr.id, aref.Token); err != nil || ms.Members[2].Revoked {
		t.Fatalf("idx 2 revoked before the retry: %v (%v)", ms.Members, err)
	}
	out = mustOK(t, "serve", "--dir", tr.a, "--once")
	if !strings.Contains(out, "idx 2 revoked") {
		t.Fatalf("A's serve did not retry the revoke:\n%s", out)
	}
	if _, aref, _ = roomOf(t, tr.a, "r1"); len(aref.Removals) != 0 {
		t.Fatalf("removals after the retry: %v", aref.Removals)
	}
	if ms, err := relay.New(base, nil).ListMembers(ctx, tr.id, aref.Token); err != nil || !ms.Members[2].Revoked {
		t.Fatalf("idx 2 not revoked after the retry: %v (%v)", ms.Members, err)
	}
}

// refOf is the room's rooms-record entry as a fresh process loads it.
func refOf(t *testing.T, dir, name string) roomRef {
	t.Helper()
	l, err := loadRooms(context.Background(), mustParty(t, dir).backend)
	if err != nil {
		t.Fatal(err)
	}
	ref := l.byName(name)
	if ref == nil {
		t.Fatalf("%s: no room %s", dir, name)
	}
	return *ref
}

// putSealedTo puts a text record in the room as dir's party sealed to one
// recipient under a key of the caller's choosing — a sender a rotation
// behind, which a send (to head first) never is.
func putSealedTo(t *testing.T, dir, name, text string, idx uint16, key *ecdh.PublicKey) string {
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
	plain, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	ctr := c.st.NextCounter()
	if err := c.st.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	h := sealed.Header{Room: ref.ID, Idx: c.st.Idx(), Ctr: ctr, At: m.At}
	b, err := sealed.Seal(h, plain, []sealed.Recipient{{Idx: idx, Key: key}}, c.st.SignKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.rc.PutRecord(ctx, ref.ID, ref.Token, b, c.st.Membership(), false); err != nil {
		t.Fatal(err)
	}
	return m.ID
}

func mustParty(t *testing.T, dir string) *party {
	t.Helper()
	p, err := openParty(dir)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// setRelay points a room's rooms-record entry at another relay base.
func setRelay(t *testing.T, dir, roomID, base string) {
	t.Helper()
	p := mustParty(t, dir)
	err := updateRooms(context.Background(), p.backend, func(l *roomList) error {
		l.byID(roomID).Relay = base
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The last admin cannot leave a room others are in; the creator hands over
// to bob (the handover record, the admin token over the channel), then
// leaves (the leave record, DELETE self), and bob still mints and revokes
// while the left creator's token is refused. A re-run of the handover sends
// the stored token again, no second grant.
func TestRoomHandoverThenLeave(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	d := newDir(t, config{})
	bd := handshakeNamed(t, tr.b, d, base, "dave", "bob")

	mustRefuse(t, "you are its last admin and 2 other members stay", "room", "leave", "--dir", tr.a, "r1")
	out := mustOK(t, "room", "handover", "--dir", tr.a, "r1", "bob")
	if !strings.Contains(out, "handover record #") || !strings.Contains(out, "bob (idx 1) is an admin; its token went out") {
		t.Fatalf("handover:\n%s", out)
	}
	m1 := srv.RoomMembership(tr.id)
	_, aref, ast := roomOf(t, tr.a, "r1")
	if !ast.IsAdmin(1) || len(aref.Handovers) != 1 || !aref.Handovers[0].Sent || aref.Handovers[0].Token == "" {
		t.Fatalf("A after the handover: admins %v, handovers %+v", ast.Admins(), aref.Handovers)
	}
	// B takes the token; C folds the handover.
	out = mustOK(t, "serve", "--dir", tr.b, "--once")
	if !strings.Contains(out, "alice handed you the admin token") || !strings.Contains(out, "idx 1 is an admin") {
		t.Fatalf("B's serve on the handover:\n%s", out)
	}
	if out := mustOK(t, "serve", "--dir", tr.c, "--once"); !strings.Contains(out, "idx 1 is an admin") {
		t.Fatalf("C's serve on the handover:\n%s", out)
	}
	// A re-run sends the token again without a second grant: the membership
	// stays, bob's token still works.
	out = mustOK(t, "room", "handover", "--dir", tr.a, "r1", "bob")
	if strings.Contains(out, "handover record #") || !strings.Contains(out, "its token went out") || srv.RoomMembership(tr.id) != m1 {
		t.Fatalf("handover re-run:\n%s (membership %d, want %d)", out, srv.RoomMembership(tr.id), m1)
	}
	mustOK(t, "serve", "--dir", tr.b, "--once")

	oldToken := aref.Token
	out = mustOK(t, "room", "leave", "--dir", tr.a, "r1")
	if !strings.Contains(out, "leave record #") || !strings.Contains(out, "left room r1") {
		t.Fatalf("leave:\n%s", out)
	}
	if out := mustOK(t, "status", "--dir", tr.a); !strings.Contains(out, "room r1 ("+tr.id+"): left") {
		t.Fatalf("A's status:\n%s", out)
	}
	if out := mustOK(t, "room", "members", "--dir", tr.a, "r1"); !strings.Contains(out, "room r1 ("+tr.id+"): left") {
		t.Fatalf("A's members after leaving:\n%s", out)
	}
	mustRefuse(t, "you left it already", "room", "remove", "--dir", tr.a, "r1", "bob")
	if _, err := relay.New(base, nil).AddMember(ctx, tr.id, oldToken, relay.RoleWrite); !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("the left creator's token: %v, want revoked", err)
	}
	// B and C fold the leave; the notice names idx 0.
	for _, dir := range []string{tr.b, tr.c} {
		out := mustOK(t, "serve", "--dir", dir, "--once")
		if !strings.Contains(out, "idx 0 left") || !strings.Contains(out, "delivered roster") {
			t.Fatalf("serve on the leave:\n%s", out)
		}
		_, _, st := roomOf(t, dir, tr.bcRoom)
		if st.Member(0) != nil || st.IsAdmin(0) || !st.IsAdmin(1) {
			t.Fatalf("after the leave: members %+v admins %v", st.Members(), st.Admins())
		}
	}
	// bob mints: dave joins through bob, and bob revokes carol.
	addToRoom(t, tr.b, d, tr.bcRoom, "dave")
	_, _, dst := roomOf(t, d, tr.bcRoom)
	if dst.Idx() != 3 || len(dst.Members()) != 3 || dst.Member(0) != nil || !dst.IsAdmin(1) || dst.IsAdmin(0) {
		t.Fatalf("D's state: idx %d members %+v admins %v", dst.Idx(), dst.Members(), dst.Admins())
	}
	out = mustOK(t, "room", "remove", "--dir", tr.b, tr.bcRoom, "2") // bob holds no channel with carol: by idx
	if !strings.Contains(out, "idx 2 ("+tr.ac.guestParty+") removed") || !strings.Contains(out, "idx 2 revoked") {
		t.Fatalf("bob's remove:\n%s", out)
	}
	if out := mustOK(t, "serve", "--dir", tr.c, "--once"); !strings.Contains(out, "out of the room: removed") {
		t.Fatalf("carol's serve:\n%s", out)
	}
	_ = bd
}

// Two hosts of one party rotate together: both load the state at one
// version and both find the rotation due; the first Commit wins and posts
// one roomcard, the second host reads the winner's key. The member folds the
// new seal key and a record each way opens.
func TestRoomRotateTwoHostsOneKey(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	cfg := config{}
	cfg.State.Dir = filepath.Join(t.TempDir(), "shared-state")
	a, b := newDir(t, cfg), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	mustOK(t, "serve", "--dir", a, "--once")
	hostB := secondHost(t, a)
	rows := len(srv.RoomRecords(id))

	now := time.Now().Add(room.RotateEvery + time.Minute)
	pA, pB := mustParty(t, a), mustParty(t, hostB)
	_, ref, before := roomOf(t, a, "r1")
	cA, err := pA.openRoom(ctx, ref, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cB, err := pB.openRoom(ctx, ref, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !cA.st.RotationDue(now) || !cB.st.RotationDue(now) {
		t.Fatal("the rotation is not due on both hosts")
	}
	var outB strings.Builder
	cB.out = &outB
	if err := cA.rotate(ctx, now, false); err != nil {
		t.Fatal(err)
	}
	if err := cB.rotate(ctx, now, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outB.String(), "another host rotated the seal key") {
		t.Fatalf("the second host:\n%s", outB.String())
	}
	_, _, after := roomOf(t, a, "r1")
	if after.SealKey().Equal(before.SealKey()) || !cB.st.SealKey().Equal(after.SealKey()) || !cA.st.SealKey().Equal(after.SealKey()) {
		t.Fatal("the hosts do not end with one new key")
	}
	if len(after.RetiredSealKeys()) != 1 || after.RotationPending() || !after.CardCurrent() {
		t.Fatalf("after the rotation: %d retired, pending %v, current %v", len(after.RetiredSealKeys()), after.RotationPending(), after.CardCurrent())
	}
	if n := len(srv.RoomRecords(id)); n != rows+1 {
		t.Fatalf("the relay holds %d records, want one roomcard more than %d", n, rows)
	}
	// Not due again, on either host, until a day passes.
	cB2, _ := pB.openRoom(ctx, ref, io.Discard)
	if cB2.st.RotationDue(now.Add(time.Hour)) || !cB2.st.RotationDue(now.Add(room.RotateEvery)) {
		t.Fatal("due is not counted from the rotation")
	}
	// B folds the roomcard and seals to the new key; A's old key opens nothing new.
	mustOK(t, "serve", "--dir", b, "--once")
	_, _, bst := roomOf(t, b, id[:8])
	if !bst.Member(0).Seal().Equal(after.SealKey().PublicKey()) {
		t.Fatal("B did not fold A's new seal key")
	}
	mid, _ := roomSendOK(t, b, "--text", "to the new key", id[:8])
	if out := mustOK(t, "serve", "--dir", a, "--once"); !strings.Contains(out, "delivered text "+mid) {
		t.Fatalf("A's serve:\n%s", out)
	}
	mid, _ = roomSendOK(t, a, "--text", "from the new key", "r1")
	if out := mustOK(t, "serve", "--dir", b, "--once"); !strings.Contains(out, "delivered text "+mid) {
		t.Fatalf("B's serve:\n%s", out)
	}
}

// Serve rotates when the folded own card is a day old; the retired key
// opens a record a slow sender sealed to it within two days, and after two
// days the key is gone and such a record is reported, not opened.
func TestRetiredKeyOpensWithinTwoDays(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	a, b := newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	mustOK(t, "serve", "--dir", a, "--once")
	t.Cleanup(func() { roomClock = time.Now })
	_, _, bst := roomOf(t, b, id[:8])
	firstKey := bst.SealKey().PublicKey()

	// B's serve a day later rotates; a sender a rotation behind still seals to B's first key.
	day := time.Now().Add(room.RotateEvery + time.Minute)
	roomClock = func() time.Time { return day }
	out := mustOK(t, "serve", "--dir", b, "--once")
	if !strings.Contains(out, "seal key rotated; roomcard #") {
		t.Fatalf("B's serve a day later:\n%s", out)
	}
	roomClock = time.Now
	_, _, bst = roomOf(t, b, id[:8])
	if len(bst.RetiredSealKeys()) != 1 || bst.RotationPending() || bst.SealKey().PublicKey().Equal(firstKey) {
		t.Fatalf("B after the rotation: %d retired, pending %v", len(bst.RetiredSealKeys()), bst.RotationPending())
	}
	old := putSealedTo(t, a, "r1", "sealed to the old key", 1, firstKey)
	out = mustOK(t, "serve", "--dir", b, "--once")
	if !strings.Contains(out, "delivered text "+old) {
		t.Fatalf("B did not open a record sealed to its retired key:\n%s", out)
	}
	_, _, bst = roomOf(t, b, id[:8])
	if bst.Reported() != 0 || len(bst.RetiredSealKeys()) != 1 {
		t.Fatalf("B after the old-key record: reported %d, retired %d", bst.Reported(), len(bst.RetiredSealKeys()))
	}

	// Two days on: the retired key is dropped (and the day's rotation runs).
	roomClock = func() time.Time { return day.Add(room.Retention + time.Minute) }
	out = mustOK(t, "serve", "--dir", b, "--once")
	if !strings.Contains(out, "1 retired seal key(s) dropped") || !strings.Contains(out, "seal key rotated") {
		t.Fatalf("B's serve two days on:\n%s", out)
	}
	roomClock = time.Now
	_, _, bst = roomOf(t, b, id[:8])
	if len(bst.RetiredSealKeys()) != 1 {
		t.Fatalf("B holds %d retired keys, want the day's one alone", len(bst.RetiredSealKeys()))
	}
	gone := putSealedTo(t, a, "r1", "still sealed to the first key", 1, firstKey)
	out = mustOK(t, "serve", "--dir", b, "--once")
	if strings.Contains(out, "delivered text "+gone) {
		t.Fatalf("B opened a record sealed to a key two days retired:\n%s", out)
	}
	if _, _, bst = roomOf(t, b, id[:8]); bst.Reported() != 1 {
		t.Fatalf("B's reported count %d, want 1", bst.Reported())
	}
	// A send folds B's roomcards first and seals to the current key.
	fresh, _ := roomSendOK(t, a, "--text", "to the current key", "r1")
	if out := mustOK(t, "serve", "--dir", b, "--once"); !strings.Contains(out, "delivered text "+fresh) {
		t.Fatalf("B's serve on the current key:\n%s", out)
	}
}

// close removes everyone: one removal record with bump, every revoke, the
// admin's own leave and revoke; the relay answers revoked to every former
// token, the members' next pull says so, and a non-admin's close is refused.
func TestRoomCloseRevokesEveryone(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	mustRefuse(t, "close is an admin's act", "room", "close", "--dir", tr.b, tr.bcRoom)
	var tokens []string
	for _, dir := range []string{tr.a, tr.b, tr.c} {
		_, ref, _ := roomOf(t, dir, map[bool]string{true: "r1", false: tr.bcRoom}[dir == tr.a])
		tokens = append(tokens, ref.Token)
	}
	rows := len(srv.RoomRecords(tr.id))
	out := mustOK(t, "room", "close", "--dir", tr.a, "r1")
	for _, want := range []string{"2 members removed (record #", "idx 1 revoked", "idx 2 revoked", "leave record #", "closed room r1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("close did not say %q:\n%s", want, out)
		}
	}
	if n := len(srv.RoomRecords(tr.id)); n != rows+2 {
		t.Fatalf("the relay holds %d records, want the removal and the leave on top of %d", n, rows)
	}
	rc := relay.New(base, nil)
	for i, tok := range tokens {
		if _, err := rc.PullRoom(ctx, tr.id, tok, -1); !errors.Is(err, relay.ErrRevoked) {
			t.Fatalf("former token %d: %v, want revoked", i, err)
		}
	}
	if out := mustOK(t, "status", "--dir", tr.a); !strings.Contains(out, "room r1 ("+tr.id+"): closed") {
		t.Fatalf("A's status:\n%s", out)
	}
	if _, err := room.Load(ctx, mustParty(t, tr.a).backend, tr.id); !errors.Is(err, room.ErrNoRoom) {
		t.Fatalf("A's state after the close: %v, want dropped", err)
	}
	for _, dir := range []string{tr.b, tr.c} {
		if out := mustOK(t, "serve", "--dir", dir, "--once"); !strings.Contains(out, "out of the room: removed") {
			t.Fatalf("a member's serve after the close:\n%s", out)
		}
	}
	mustRefuse(t, "you closed it already", "send", "--dir", tr.a, "--text", "x", "r1")
}

// A read member learns its role from the token, rotates through its channel
// (the admin's roster entry announces the card, and the member records where
// it landed), and leaves by DELETE self; the admin's host sees the idx
// revoked and posts the removal.
func TestReadMemberRotatesAndLeavesViaChannel(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	a, b := newDir(t, config{}), newDir(t, config{})
	ab := handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	mustOK(t, "room", "add", "--dir", a, "--read", "r1", "bob")
	for i, dir := range []string{b, a, b, a, b} {
		out := mustOK(t, "serve", "--dir", dir, "--once")
		if i == 4 && !strings.Contains(out, "joined room "+id[:8]+" as idx 1, read") {
			t.Fatalf("the read member's join:\n%s", out)
		}
	}
	mustOK(t, "serve", "--dir", a, "--once")
	_, bref, bst := roomOf(t, b, id[:8])
	if !bref.Read {
		t.Fatal("B does not know it is a read member")
	}
	if out := mustOK(t, "status", "--dir", b); !regexp.MustCompile(`room ` + id[:8] + ` \(` + id + `\)  idx 1 \(read\)`).MatchString(out) {
		t.Fatalf("B's status has no read mark:\n%s", out)
	}
	first := bst.SealKey()

	out := mustOK(t, "room", "rotate", "--dir", b, id[:8])
	if !strings.Contains(out, "your room card went to alice over the channel") {
		t.Fatalf("the read member's rotate:\n%s", out)
	}
	_, _, bst = roomOf(t, b, id[:8])
	if bst.SealKey().Equal(first) || !bst.RotationPending() || bst.CardCurrent() {
		t.Fatal("the rotation did not commit a new key waiting for its card")
	}
	out = mustOK(t, "serve", "--dir", a, "--once")
	if !strings.Contains(out, "bob's new room card is announced (roster #") {
		t.Fatalf("A's serve on the card:\n%s", out)
	}
	_, _, ast := roomOf(t, a, "r1")
	if !ast.Member(1).Seal().Equal(bst.SealKey().PublicKey()) {
		t.Fatal("A did not fold B's new seal key")
	}
	out = mustOK(t, "serve", "--dir", b, "--once")
	_, _, bst = roomOf(t, b, id[:8])
	if bst.RotationPending() || !bst.CardCurrent() {
		t.Fatalf("B after folding the admin's entry: pending %v current %v\n%s", bst.RotationPending(), bst.CardCurrent(), out)
	}
	mid, _ := roomSendOK(t, a, "--text", "to the reader's new key", "r1")
	if out := mustOK(t, "serve", "--dir", b, "--once"); !strings.Contains(out, "delivered text "+mid) {
		t.Fatalf("B's serve:\n%s", out)
	}
	out = mustOK(t, "room", "leave", "--dir", b, id[:8])
	if strings.Contains(out, "leave record") || !strings.Contains(out, "left room "+id[:8]) {
		t.Fatalf("the read member's leave:\n%s", out)
	}
	out = mustOK(t, "serve", "--dir", a, "--once")
	if !strings.Contains(out, "idx [1] left (token revoked); roster record #") {
		t.Fatalf("A's serve after the reader left:\n%s", out)
	}
	_, _, ast = roomOf(t, a, "r1")
	if ast.Member(1) != nil || len(ast.Members()) != 1 {
		t.Fatalf("A's roster after the reader left: %+v", ast.Members())
	}
	if out := mustOK(t, "serve", "--dir", a, "--once"); strings.Contains(out, "roster record #") {
		t.Fatalf("A posted the removal again:\n%s", out)
	}
	_ = ab
}

// A member's identity key changes: the new card reaches the admin as v1
// publishes it and the human accepts it; the member's serve sends a room
// card re-signed by the new key over the channel, the admin posts the roster
// entry with the new party card at the same idx, and records flow both ways.
// The member's state is a sealed page, so the rotation re-seals the rooms.
func TestIdentityChangeRecardsTheRoom(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	ps := pagestest.New("state-0123456789abcdef", "zt:state-secret")
	t.Cleanup(ps.Close)
	cfg := config{State: stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}}
	a, b := newDir(t, config{}), newDir(t, cfg)
	ab := handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	mustOK(t, "serve", "--dir", a, "--once")
	_, _, bst := roomOf(t, b, id[:8])
	oldIdentity := identityOf(t, bst.Member(1).Card.Body)

	out := mustOK(t, "identity", "rotate", "--dir", b, "--yes")
	if !strings.Contains(out, "card published to alice") || !strings.Contains(out, "state re-sealed under the new identity key") {
		t.Fatalf("bob's identity rotate:\n%s", out)
	}
	_, bref, bst := roomOf(t, b, id[:8])
	if bref.Stage != stageJoined || bst.Idx() != 1 {
		t.Fatalf("B's room after the re-seal: %+v idx %d", bref, bst.Idx())
	}
	out = mustOK(t, "serve", "--dir", a, "--once")
	if !strings.Contains(out, "peer keys accept bob") {
		t.Fatalf("A's serve on the new card:\n%s", out)
	}
	mustOK(t, "keys", "accept", "--dir", a, "bob")
	mustOK(t, "serve", "--dir", a, "--once")
	out = mustOK(t, "serve", "--dir", b, "--once")
	if !strings.Contains(out, "your room card went to alice over the channel") {
		t.Fatalf("B's serve after the rotation:\n%s", out)
	}
	out = mustOK(t, "serve", "--dir", a, "--once")
	if !strings.Contains(out, "bob's new room card is announced (roster #") {
		t.Fatalf("A's serve on the re-signed card:\n%s", out)
	}
	_, _, ast := roomOf(t, a, "r1")
	newIdentity := identityOf(t, ast.Member(1).Card.Body)
	if newIdentity == oldIdentity || newIdentity != keys.CurveText(mustParty(t, b).id.PublicKey()) {
		t.Fatalf("A's folded party card for bob: %s (old %s)", newIdentity, oldIdentity)
	}
	out = mustOK(t, "serve", "--dir", b, "--once")
	if strings.Contains(out, "your room card went to") {
		t.Fatalf("B sent its card again after the entry folded:\n%s", out)
	}
	if _, _, bst = roomOf(t, b, id[:8]); identityOf(t, bst.Member(1).Card.Body) != newIdentity {
		t.Fatal("B did not fold its own new party card")
	}
	mid, _ := roomSendOK(t, b, "--text", "under the new identity", id[:8])
	if out := mustOK(t, "serve", "--dir", a, "--once"); !strings.Contains(out, "delivered text "+mid) {
		t.Fatalf("A's serve:\n%s", out)
	}
	mid, _ = roomSendOK(t, a, "--text", "to the re-carded member", "r1")
	if out := mustOK(t, "serve", "--dir", b, "--once"); !strings.Contains(out, "delivered text "+mid) {
		t.Fatalf("B's serve:\n%s", out)
	}
	_ = ab
}

// identityOf is the current identity key a party card names.
func identityOf(t *testing.T, body []byte) string {
	t.Helper()
	var pc struct {
		Keys []struct {
			Identity string  `json:"identity"`
			Until    *string `json:"until"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &pc); err != nil {
		t.Fatal(err)
	}
	for _, k := range pc.Keys {
		if k.Until == nil {
			return k.Identity
		}
	}
	t.Fatal("the party card names no current key")
	return ""
}

// close's removal record travels with bump: between it and the first revoke
// the membership is one past the members', so a member's put at the
// membership it holds is 409 — no stale record lands sealed to the closed
// room's leavers.
func TestRoomCloseBumpsBeforeRevoke(t *testing.T) {
	ctx := context.Background()
	srv, base, front := startPathFront(t, http.MethodDelete, "/members/1")
	tr := newTrio(t, base, srv, config{})
	_, cref, cst := roomOf(t, tr.c, tr.bcRoom)
	m0 := srv.RoomMembership(tr.id)
	var stale error
	var atRevoke int64
	front.arm(func(http.ResponseWriter, *http.Request) bool {
		// The removal record is on the relay, no revoke yet.
		atRevoke = srv.RoomMembership(tr.id)
		_, stale = relay.New(base, nil).PutRecord(ctx, tr.id, cref.Token, []byte("x"), cst.Membership(), false)
		return false
	})
	out := mustOK(t, "room", "close", "--dir", tr.a, "r1")
	if !strings.Contains(out, "2 members removed (record #") || !strings.Contains(out, "closed room r1") {
		t.Fatalf("close:\n%s", out)
	}
	if !errors.Is(stale, relay.ErrStaleMembership) || atRevoke != m0+1 {
		t.Fatalf("before the first revoke: membership %d, want %d; a put at the old one: %v, want 409", atRevoke, m0+1, stale)
	}
}

// The admin's sweep finds a seat revoked that the roster still holds — a
// leave by DELETE self alone, as a read member leaves — and posts its
// removal with bump: a writer that folded the revoke and not the removal
// puts at a stale membership and is refused, never sealing to the leaver.
func TestRoomRevokedSweepBumps(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	_, cref, _ := roomOf(t, tr.c, tr.bcRoom)
	rc := relay.New(base, nil)
	if _, err := rc.LeaveRoom(ctx, tr.id, cref.Token); err != nil {
		t.Fatal(err)
	}
	m := srv.RoomMembership(tr.id)
	out := mustOK(t, "serve", "--dir", tr.a, "--once")
	if !strings.Contains(out, "idx [2] left (token revoked); roster record #") {
		t.Fatalf("A's serve after carol's seat was revoked:\n%s", out)
	}
	if srv.RoomMembership(tr.id) != m+1 {
		t.Fatalf("membership %d, want %d: the removal record's bump", srv.RoomMembership(tr.id), m+1)
	}
	_, bref, _ := roomOf(t, tr.b, tr.bcRoom)
	if _, err := rc.PutRecord(ctx, tr.id, bref.Token, []byte("x"), m, false); !errors.Is(err, relay.ErrStaleMembership) {
		t.Fatalf("a put at the membership after the revoke and before the removal: %v, want 409", err)
	}
}
