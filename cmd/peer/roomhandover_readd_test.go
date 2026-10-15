package main

import (
	"context"
	"testing"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// A handover to a member that left and was added again at a new idx posts a
// new record and a new grant: the entry left from the earlier handover names
// an idx the relay revoked, so re-sending its token would hand over nothing.
func TestRoomHandoverAfterReAdd(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	mustOK(t, "room", "handover", "--dir", tr.a, "r1", "bob")
	mustOK(t, "serve", "--dir", tr.b, "--once")
	mustOK(t, "room", "leave", "--dir", tr.b, tr.bcRoom)
	mustOK(t, "serve", "--dir", tr.a, "--once")
	mustOK(t, "serve", "--dir", tr.c, "--once")
	addToRoom(t, tr.a, tr.b, "r1", "bob")
	mustOK(t, "serve", "--dir", tr.a, "--once")
	out := mustOK(t, "room", "handover", "--dir", tr.a, "r1", "bob")
	t.Logf("handover again:\n%s", out)
	outb := mustOK(t, "serve", "--dir", tr.b, "--once")
	t.Logf("bob serve:\n%s", outb)
	_, aref, ast := roomOf(t, tr.a, "r1")
	bref := refOf(t, tr.b, tr.bcRoom)
	if !ast.IsAdmin(bref.Idx) {
		t.Fatalf("bob at idx %d is not in A's admin set after the handover: admins %v handovers %+v", bref.Idx, ast.Admins(), aref.Handovers)
	}
	ms, err := relay.New(base, nil).ListMembers(ctx, tr.id, aref.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !ms.Members[bref.Idx].Admin {
		t.Fatalf("the relay holds no admin token for idx %d: %+v", bref.Idx, ms.Members)
	}
	if bref.Token == "" {
		t.Fatal("bob holds no token after the handover")
	}
}
