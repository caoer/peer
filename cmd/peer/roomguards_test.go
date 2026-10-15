package main

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/sealed"
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
