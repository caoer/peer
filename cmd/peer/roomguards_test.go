package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/sealed"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// putForged seals a text record as dir's party — its sign key, its idx in the
// header, a stanza for every member, its next ctr — after shape bends the
// header or the message, and puts it into the room with tokenDir's room
// token: a record no send writes, for the receiver's guards to refuse.
func putForged(t *testing.T, dir, name, tokenDir, tokenName string, shape func(*sealed.Header, *roomMessage)) string {
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
	m, err := newRoomMessage(p.partyID(), ref.ID, "text", []byte("forged"))
	if err != nil {
		t.Fatal(err)
	}
	ctr := c.st.NextCounter()
	if err := c.st.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	h := sealed.Header{Room: ref.ID, Idx: c.st.Idx(), Ctr: ctr, At: m.At}
	shape(&h, m)
	plain, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sealed.Seal(h, plain, c.recipients(m), c.st.SignKey())
	if err != nil {
		t.Fatal(err)
	}
	_, tref, _ := roomOf(t, tokenDir, tokenName)
	if _, err := c.rc.PutRecord(ctx, ref.ID, tref.Token, b, c.st.Membership(), false); err != nil {
		t.Fatal(err)
	}
	return m.ID
}

// refusedAtC serves C once and checks the forged record id was skipped:
// reported once more, nothing delivered, not in C's inbox.
func refusedAtC(t *testing.T, tr *trio, id, why string) {
	t.Helper()
	_, _, before := roomOf(t, tr.c, tr.bcRoom)
	out := mustOK(t, "serve", "--dir", tr.c, "--once")
	if !strings.Contains(out, why) || strings.Contains(out, "delivered") {
		t.Fatalf("C's serve of the forged record, want a skip naming %q:\n%s", why, out)
	}
	if _, _, after := roomOf(t, tr.c, tr.bcRoom); after.Reported() != before.Reported()+1 {
		t.Fatalf("C's reported count %d → %d, want one more", before.Reported(), after.Reported())
	}
	if in := withoutRoster(t, records(t, deliverDirOf(tr.c), deliver.Inbox)); in[id] != nil {
		t.Fatalf("C holds the forged record %s:\n%s", id, in[id])
	}
}

// A member signs with its own key at its own idx a message whose from names
// another member: the receiver skips it, reports it, and births nothing —
// member k never speaks as member j.
func TestRoomReceiverRefusesForgedFrom(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	id := putForged(t, tr.b, tr.bcRoom, tr.b, tr.bcRoom, func(_ *sealed.Header, m *roomMessage) {
		m.From = tr.ab.hostParty
	})
	refusedAtC(t, tr, id, "and the roster holds "+tr.ab.guestParty+" at idx 1")
}

// The receiver's room, idx and group guards, each on a record that passes
// every later check: the relay's idx is not the header's (A's record put
// with B's token); the header names another room, the message this one; the
// header names this room, the message another. Each is skipped, reported
// once, born nowhere.
func TestRoomReceiverGuards(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	other := func() string {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b[:])
	}
	// In this order: a record skipped before the counter check (idx, room)
	// leaves its ctr unread, so B's room case comes after its group case, or
	// C would report a gap besides.
	cases := []struct {
		name, dir, room, why string
		shape                func(*sealed.Header, *roomMessage)
	}{
		{"idx", tr.a, tr.aRoom, "the relay names writer idx 1 and the record idx 0", func(*sealed.Header, *roomMessage) {}},
		{"group", tr.b, tr.bcRoom, "the message names group ", func(_ *sealed.Header, m *roomMessage) { m.Group = other() }},
		{"room", tr.b, tr.bcRoom, "sealed for room ", func(h *sealed.Header, _ *roomMessage) { h.Room = other() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := putForged(t, tc.dir, tc.room, tr.b, tr.bcRoom, tc.shape)
			refusedAtC(t, tr, id, tc.why)
		})
	}
}

// A member's identity key is retired at its rotation. A roomcard record the
// relay stores after that, signed by the retired key under a header at from
// before it, is refused: the fold reads the retirement at the relay's at of
// the pulled record, never at the writer's own word — the member's keys stay
// as they were.
func TestRoomRetiredIdentityKeyReadAtRelayAt(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	ps := pagestest.New("state-0123456789abcdef", "zt:state-secret")
	t.Cleanup(ps.Close)
	a, b := newDir(t, config{}), newDir(t, config{State: stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}})
	handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	mustOK(t, "serve", "--dir", a, "--once")
	retired := mustParty(t, b).id
	backdated := time.Now().UTC().Truncate(time.Millisecond)

	// bob rotates his identity key; alice accepts it and folds his re-signed card.
	mustOK(t, "identity", "rotate", "--dir", b, "--yes")
	mustOK(t, "serve", "--dir", a, "--once")
	mustOK(t, "keys", "accept", "--dir", a, "bob")
	mustOK(t, "serve", "--dir", a, "--once")
	mustOK(t, "serve", "--dir", b, "--once")
	if out := mustOK(t, "serve", "--dir", a, "--once"); !strings.Contains(out, "bob's new room card is announced") {
		t.Fatalf("A's serve on bob's re-signed card:\n%s", out)
	}
	mustOK(t, "serve", "--dir", b, "--once")
	_, _, ast := roomOf(t, a, "r1")
	seal, dropped := ast.Member(1).Seal(), ast.Dropped()

	_, _, bst := roomOf(t, b, id[:8])
	evil, err := room.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := room.NewCard(id, 1, evil.PublicKey(), bst.SignKey().Public().(ed25519.PublicKey), time.Now()).Signed(retired)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(room.RoomCardBody{RoomCard: rc})
	if err != nil {
		t.Fatal(err)
	}
	putForged(t, b, id[:8], b, id[:8], func(h *sealed.Header, m *roomMessage) {
		h.At, m.At = backdated, backdated
		m.Kind, m.Body = room.KindRoomCard, body
	})
	out := mustOK(t, "serve", "--dir", a, "--once")
	_, _, ast = roomOf(t, a, "r1")
	if !ast.Member(1).Seal().Equal(seal) || ast.Dropped() != dropped+1 {
		t.Fatalf("A folded a room card signed by bob's retired key (dropped %d → %d):\n%s", dropped, ast.Dropped(), out)
	}
}
