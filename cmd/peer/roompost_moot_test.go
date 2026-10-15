package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
)

// A membership record whose fold at head changes nothing is not put: a
// room-join replayed with the card the roster already holds spends no ctr
// and sends no member an empty roster notice.
func TestRoomCardUpdateReplayPostsNothing(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	p, ref, st := roomOf(t, tr.b, tr.bcRoom)
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		t.Fatal(err)
	}
	pe := r.ByName("alice")
	if err := p.sendOnChannel(ctx, *pe, kindRoomJoin, roomJoin{Room: ref.ID, RoomCard: st.Member(st.Idx()).RoomCard}, io.Discard); err != nil {
		t.Fatal(err)
	}
	n0 := len(srv.RoomRecords(tr.id))
	out := mustOK(t, "serve", "--dir", tr.a, "--once")
	if n1 := len(srv.RoomRecords(tr.id)); n1 != n0 {
		t.Fatalf("a no-op card update put %d record(s):\n%s", n1-n0, out)
	}
	if !strings.Contains(out, "nothing posted") {
		t.Fatalf("the admin is not told the card is no newer:\n%s", out)
	}
	if outc := mustOK(t, "serve", "--dir", tr.c, "--once"); strings.Contains(outc, "delivered roster") {
		t.Fatalf("a member got a roster notice for nothing:\n%s", outc)
	}
}
