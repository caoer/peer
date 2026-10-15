package main

import (
	"strings"
	"testing"

	"github.com/caoer/peer/internal/relay/relaytest"
)

// A read member's add is refused at the gate: the relay mints for an admin
// token or, under add: members, a write token, so its invite would carry
// the roster to the peer and fail at the mint every time.
func TestRoomAddByReadMemberRefused(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	a, b := newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	mustOK(t, "room", "add", "--read", "--dir", a, "r1", "bob")
	for _, dir := range []string{b, a, b, a, b} { // accept, mint+seat, join, roster+token, token
		mustOK(t, "serve", "--dir", dir, "--once")
	}
	bref := refOf(t, b, id[:8])
	if bref.Stage != stageJoined || !bref.Read {
		t.Fatalf("bob: stage %s read %v, want joined and read", bref.Stage, bref.Read)
	}
	var o, e strings.Builder
	if code := run([]string{"room", "add", "--dir", b, id[:8], "alice"}, &o, &e); code == 0 {
		t.Fatalf("a read member's add ran: %s%s", o.String(), e.String())
	}
	if !strings.Contains(e.String(), "cannot add") {
		t.Fatalf("the refusal does not say so: %s", e.String())
	}
	if out := mustOK(t, "serve", "--dir", a, "--once"); strings.Contains(out, "room-invite") {
		t.Fatalf("an invite reached alice: %s", out)
	}
}
