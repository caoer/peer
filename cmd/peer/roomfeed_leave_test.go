package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// A feed's owner cannot leave: the link's read seat is outside the roster
// and only the owner's admin token revokes it. close ends the feed and
// cuts the holder.
func TestRoomFeedOwnerLeaveRefused(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	a, d := newDir(t, config{}), newDir(t, config{})
	createRoom(t, a, base, "f1", "--feed")
	link := linkOf(t, a, "f1")
	follow(t, d, link)
	var o, e strings.Builder
	if code := run([]string{"room", "leave", "--dir", a, "f1"}, &o, &e); code == 0 {
		t.Fatalf("the feed owner's leave ran: %s%s", o.String(), e.String())
	}
	if !strings.Contains(e.String(), "peer room close f1") {
		t.Fatalf("the refusal does not point at close: %s", e.String())
	}
	if ref := refOf(t, a, "f1"); ref.Stage != stageJoined || ref.Token == "" {
		t.Fatalf("the owner's entry after the refused leave: stage %s token %q", ref.Stage, ref.Token)
	}
	f, err := invite.ParseFeed(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.New(base, nil).PullRoom(ctx, f.Room, f.Token, -1); err != nil {
		t.Fatalf("the link does not read after the refused leave: %v", err)
	}
	mustOK(t, "room", "close", "--dir", a, "f1")
	if _, err := relay.New(base, nil).PullRoom(ctx, f.Room, f.Token, -1); !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("the link's seat after close answers %v, want revoked", err)
	}
}
