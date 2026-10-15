package main

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/sealed"
)

var (
	feedLinkRE = regexp.MustCompile(`(?m)^(https?://\S+/f/[0-9a-f]{32}#v1\.\S+)$`)
	madeRE     = regexp.MustCompile(`(?m)^party (ed25519:[A-Za-z0-9_-]{43}) in `)
	followedRE = regexp.MustCompile(`(?m)^following feed \S+ \([0-9a-f]{32}\): (\d+) records delivered`)
)

// linkOf runs peer room link (with flags) on the owner's dir and returns the
// feed link it prints.
func linkOf(t *testing.T, dir, name string, flags ...string) string {
	t.Helper()
	out := mustOK(t, append(append([]string{"room", "link", "--dir", dir}, flags...), name)...)
	m := feedLinkRE.FindAllString(out, -1)
	if len(m) == 0 {
		t.Fatalf("room link printed no feed link:\n%s", out)
	}
	return m[len(m)-1]
}

// follow runs peer room follow on dir and returns how many records it
// delivered and its output.
func follow(t *testing.T, dir, link string) (string, string) {
	t.Helper()
	out := mustOK(t, "room", "follow", "--dir", dir, link)
	m := followedRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("follow printed no receipt:\n%s", out)
	}
	return m[1], out
}

// addReader adds peer to the owner's room as a read member, serves run to
// the reader's join.
func addReader(t *testing.T, ownerDir, readerDir, roomName, peerName string) {
	t.Helper()
	mustOK(t, "room", "add", "--dir", ownerDir, "--read", roomName, peerName)
	for i, dir := range []string{readerDir, ownerDir, readerDir, ownerDir, readerDir} {
		out := mustOK(t, "serve", "--dir", dir, "--once")
		if i == 4 && !strings.Contains(out, ", read") {
			t.Fatalf("the read member's join:\n%s", out)
		}
	}
	mustOK(t, "serve", "--dir", ownerDir, "--once")
}

// stanzas is each relay record's stanza idxs, by seq.
func stanzas(t *testing.T, srv *relaytest.Server, id string) map[int64][]uint16 {
	t.Helper()
	out := map[int64][]uint16{}
	for _, r := range srv.RoomRecords(id) {
		rec, err := sealed.Parse(mustB64(t, r.Body))
		if err != nil {
			t.Fatal(err)
		}
		out[r.Seq] = rec.Recipients()
	}
	return out
}

// A feed's owner posts; a fresh CLI on an empty peer directory follows the
// link alone and reads every post, each verified under the owner's room
// signing key the link names; a link with a wrong link key or a wrong owner
// key opens nothing; the read member's records still open; serve delivers
// the next post to the link holder; the link stanza rides the posts and no
// membership record.
func TestRoomFeedFollowFromLinkAlone(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	a, b := newDir(t, config{}), newDir(t, config{})
	ab := handshakeNamed(t, a, b, base, "bob", "alice")
	mustRefuse(t, "--feed takes --add admins", "room", "create", "--dir", a, "--relay", base, "--login", login, "--feed", "--add", "members", "f0")
	id := createRoom(t, a, base, "f1", "--feed")
	mustRefuse(t, "is a feed", "room", "add", "--dir", a, "f1", "bob")
	addReader(t, a, b, "f1", "bob")

	p1, s1 := roomSendOK(t, a, "--text", "post one", "f1")
	p2, s2 := roomSendOK(t, a, "--text", "post two", "f1")
	link := linkOf(t, a, "f1")
	f, err := invite.ParseFeed(link)
	if err != nil {
		t.Fatal(err)
	}
	_, _, ast := roomOf(t, a, "f1")
	if f.Room != id || !f.Owner.Equal(ast.SignKey().Public()) {
		t.Fatal("the link does not name the room and the owner's room signing key")
	}

	fresh := filepath.Join(t.TempDir(), "peer")
	n, out := follow(t, fresh, link)
	made := madeRE.FindStringSubmatch(out)
	if made == nil {
		t.Fatalf("follow on an empty directory made no party:\n%s", out)
	}
	if n != "2" {
		t.Fatalf("follow delivered %s records, want 2:\n%s", n, out)
	}
	in := records(t, deliverDirOf(fresh), deliver.Inbox)
	for mid, text := range map[string]string{p1: "post one", p2: "post two"} {
		rec, ok := in[mid]
		if !ok {
			t.Fatalf("the link holder did not get %q", text)
		}
		roomRecord(t, rec, ab.hostParty, made[1], id, text)
	}
	if len(in) != 2 {
		t.Fatalf("the link holder holds %d records, want the two posts", len(in))
	}

	// A wrong link key opens no stanza; a wrong owner key verifies nothing.
	for name, bad := range map[string]invite.Feed{
		"key":   {Relay: f.Relay, Room: f.Room, Token: f.Token, Key: make([]byte, invite.LinkKeySize), Owner: f.Owner},
		"owner": {Relay: f.Relay, Room: f.Room, Token: f.Token, Key: f.Key, Owner: ab.hostRoot.Public()},
	} {
		dir := filepath.Join(t.TempDir(), "peer")
		n, out := follow(t, dir, bad.String())
		want := map[string]string{"key": "stanza", "owner": "not signed by the feed's owner"}[name]
		if n != "0" || !strings.Contains(out, want) || len(records(t, deliverDirOf(dir), deliver.Inbox)) != 0 {
			t.Fatalf("a link with a wrong %s delivered %s records:\n%s", name, n, out)
		}
	}

	// The read member reads the posts as a member.
	mustOK(t, "serve", "--dir", b, "--once")
	bin := withoutRoster(t, records(t, deliverDirOf(b), deliver.Inbox))
	if len(bin) != 2 || bin[p1] == nil || bin[p2] == nil {
		t.Fatalf("the read member holds %d posts", len(bin))
	}
	roomRecord(t, bin[p1], ab.hostParty, ab.guestParty, id, "post one")

	// serve reads on for the link holder, and says where it stands.
	p3, s3 := roomSendOK(t, a, "--text", "post three", "f1")
	if out := mustOK(t, "serve", "--dir", fresh, "--once"); !strings.Contains(out, p3) {
		t.Fatalf("serve did not deliver the next post to the link holder:\n%s", out)
	}
	roomRecord(t, records(t, deliverDirOf(fresh), deliver.Inbox)[p3], ab.hostParty, made[1], id, "post three")
	if out := mustOK(t, "status", "--dir", fresh); !strings.Contains(out, "("+id+"): following its feed by a link  cursor #") {
		t.Fatalf("the link holder's status:\n%s", out)
	}
	mustRefuse(t, "its owner alone writes", "send", "--dir", fresh, "--text", "hi", id[:8])

	// The link stanza is on every post and on no membership record.
	all := stanzas(t, srv, id)
	if len(all) < 5 {
		t.Fatalf("the relay holds %d records, want the roster records and three posts", len(all))
	}
	for seq, idxs := range all {
		if post := seq == s1 || seq == s2 || seq == s3; slices.Contains(idxs, relay.FeedIdx) != post {
			t.Fatalf("record #%d (a post: %v) has stanzas %v", seq, post, idxs)
		}
	}
}

// A room created without --feed seals no link stanza and has no link.
func TestRoomWithoutFeedHasNoLink(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	a := newDir(t, config{})
	id := createRoom(t, a, base, "r1")
	roomSendOK(t, a, "--text", "alone", "r1")
	for seq, idxs := range stanzas(t, srv, id) {
		if slices.Contains(idxs, relay.FeedIdx) {
			t.Fatalf("record #%d of a room that is no feed carries a link stanza", seq)
		}
	}
	mustRefuse(t, "is not a feed", "room", "link", "--dir", a, "r1")
}

// A new link cuts every old holder off: the old read token answers revoked,
// the old holder's serve says it is cut and gets no new post, a fresh
// follow of the old link is refused; the holder follows the new link and
// reads on from its cursor.
func TestRoomFeedLinkRotation(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	a := newDir(t, config{})
	id := createRoom(t, a, base, "f1", "--feed")
	roomSendOK(t, a, "--text", "before", "f1")
	old := linkOf(t, a, "f1")
	holder := filepath.Join(t.TempDir(), "peer")
	if n, out := follow(t, holder, old); n != "1" {
		t.Fatalf("follow delivered %s, want 1:\n%s", n, out)
	}

	out := mustOK(t, "room", "link", "--dir", a, "--rotate", "f1")
	if !strings.Contains(out, "is revoked; its holders are cut off") {
		t.Fatalf("the rotation revoked nothing:\n%s", out)
	}
	next := feedLinkRE.FindAllString(out, -1)
	if len(next) != 1 || next[0] == old {
		t.Fatalf("the rotation printed no new link:\n%s", out)
	}
	of, _ := invite.ParseFeed(old)
	nf, _ := invite.ParseFeed(next[0])
	if of.Token == nf.Token || string(of.Key) == string(nf.Key) {
		t.Fatal("the new link keeps the old token or key")
	}
	if _, err := relay.New(of.Relay, nil).PullRoom(context.Background(), id, of.Token, -1); !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("the old read token pulls: %v", err)
	}
	after, _ := roomSendOK(t, a, "--text", "after", "f1")

	out = mustOK(t, "serve", "--dir", holder, "--once")
	if !strings.Contains(out, "its owner made a new link") || strings.Contains(out, after) {
		t.Fatalf("the old holder's serve:\n%s", out)
	}
	if out := mustOK(t, "status", "--dir", holder); !strings.Contains(out, "cut — its owner made a new link") {
		t.Fatalf("the old holder's status:\n%s", out)
	}
	mustRefuse(t, "revoked", "room", "follow", "--dir", filepath.Join(t.TempDir(), "peer"), old)

	if n, out := follow(t, holder, next[0]); n != "1" || !strings.Contains(out, after) {
		t.Fatalf("the new link read %s records:\n%s", n, out)
	}
	if in := records(t, deliverDirOf(holder), deliver.Inbox); len(in) != 2 || in[after] == nil {
		t.Fatalf("the holder holds %d records after the new link", len(in))
	}
	if again := linkOf(t, a, "f1"); again != next[0] {
		t.Fatal("room link without --rotate printed another link")
	}
}

// Rule 6: a room is a trusted chat, so a v1 invite link and its code travel
// in it. Carol, who holds no channel with bob, sends an invite link into the
// room; bob accepts it from the delivered record and sends the code back
// the same way; carol confirms with the code from her delivered record, and
// the channel is confirmed on both sides.
func TestRule6InviteInsideRoom(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	bob, carol := tr.ab.guestParty, tr.ac.guestParty

	out := mustOK(t, "invite", "--dir", tr.c, "--relay", base, "--login", login, "bob")
	link, _, _ := strings.Cut(out, "\n")
	if _, err := invite.Parse(link, roomClock()); err != nil {
		t.Fatal(err)
	}
	lid, _ := roomSendOK(t, tr.c, "--text", link, tr.bcRoom)
	mustOK(t, "serve", "--dir", tr.b, "--once")
	rec := records(t, deliverDirOf(tr.b), deliver.Inbox)[lid]
	if rec == nil {
		t.Fatal("bob did not get the invite link")
	}
	roomRecord(t, rec, carol, bob, tr.id, link)
	_, _, got := frontMatter(t, rec)

	out = mustOK(t, "accept", "--dir", tr.b, "--name", "carol", got)
	code := codeRE.FindStringSubmatch(out)
	if code == nil {
		t.Fatalf("accept from the room record printed no code:\n%s", out)
	}
	cid, _ := roomSendOK(t, tr.b, "--text", code[1], tr.bcRoom)
	mustOK(t, "serve", "--dir", tr.c, "--once")
	rec = records(t, deliverDirOf(tr.c), deliver.Inbox)[cid]
	if rec == nil {
		t.Fatal("carol did not get the code")
	}
	roomRecord(t, rec, bob, carol, tr.id, code[1])
	_, _, gotCode := frontMatter(t, rec)

	if out := mustOK(t, "confirm", "--dir", tr.c, "--code", gotCode, "bob"); !strings.Contains(out, "confirmed bob ("+bob+")") {
		t.Fatalf("confirm:\n%s", out)
	}
	mustOK(t, "serve", "--dir", tr.b, "--once")
	mustOK(t, "serve", "--dir", tr.c, "--once")
	for _, side := range []struct{ dir, name, party string }{{tr.c, "bob", bob}, {tr.b, "carol", carol}} {
		_, ch, pe := channelOf(t, side.dir, side.name)
		if pe.State != roster.Confirmed || keys.PartyID(ch.Root()) != side.party {
			t.Fatalf("%s's channel to %s: %s", side.dir, side.name, pe.State)
		}
	}
}
