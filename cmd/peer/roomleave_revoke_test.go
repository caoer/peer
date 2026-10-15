package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/relay"
)

// A leave whose record landed and whose DELETE …/self failed is finished by
// the next serve round: the revoke runs with the token the host still holds
// before the room is marked gone, so no seat stays live with its token
// forgotten.
func TestRoomLeaveRevokeFinishedByServe(t *testing.T) {
	ctx := context.Background()
	srv, base, front := startPathFront(t, http.MethodDelete, "/members/self")
	tr := newTrio(t, base, srv, config{})
	front.arm(fail503)
	var o, e strings.Builder
	if code := run([]string{"room", "leave", "--dir", tr.c, tr.bcRoom}, &o, &e); code == 0 {
		t.Fatalf("the leave with a failed revoke ran clean: %s%s", o.String(), e.String())
	}
	if ref := refOf(t, tr.c, tr.bcRoom); ref.Token == "" {
		t.Fatal("the token is gone before the revoke landed")
	}
	out := mustOK(t, "serve", "--dir", tr.c, "--once")
	t.Logf("serve C:\n%s", out)
	cref := refOf(t, tr.c, tr.bcRoom)
	aref := refOf(t, tr.a, "r1")
	ms, err := relay.New(base, nil).ListMembers(ctx, tr.id, aref.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !ms.Members[2].Revoked {
		t.Fatalf("C's seat is live on the relay after serve; C's stage %s token %q", cref.Stage, cref.Token)
	}
	if !cref.Stage.gone() || cref.Token != "" {
		t.Fatalf("C after serve: stage %s token %q, want gone with no token", cref.Stage, cref.Token)
	}
}
