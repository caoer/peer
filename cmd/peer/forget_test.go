package main

import (
	"context"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
)

// The host forgets the guest: a bye goes out, the roster entry and the
// channel state go, and the guest's sends stop delivering — one put before
// its serve read the bye lands on a channel nobody pulls, and after the bye
// its send is refused. Both sides then make the channel again under the
// same names.
func TestForgetFreesTheName(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)

	out := mustOK(t, "forget", "--dir", p.hostDir, "ancan")
	if !strings.Contains(out, "told ancan: bye") || !strings.Contains(out, "forgot ancan: channel "+p.channel+" dropped; the name is free") {
		t.Fatalf("forget:\n%s", out)
	}
	hp, err := openParty(p.hostDir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := roster.Load(ctx, hp.backend)
	if err != nil {
		t.Fatal(err)
	}
	if r.ByName("ancan") != nil || r.ByChannel(p.channel) != nil {
		t.Fatalf("host roster still holds the guest: %+v", r.Peers)
	}
	ch, err := hp.store.Channel(ctx, p.channel)
	if err != nil {
		t.Fatal(err)
	}
	if !ch.Gone() || ch.Root() != nil || ch.Card() != nil {
		t.Fatalf("channel record not a tombstone: gone %v", ch.Gone())
	}

	// The guest has not read the bye yet: its put lands, and the host
	// delivers nothing from the forgotten channel.
	sendOK(t, p.guestDir, "--text", "still there?", "zt")
	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if in := records(t, deliverDirOf(p.hostDir), deliver.Inbox); len(in) != 0 {
		t.Fatalf("host delivered %d records from a forgotten peer", len(in))
	}

	out = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.Contains(out, "zt forgot this channel") {
		t.Fatalf("guest serve:\n%s", out)
	}
	if _, _, gpe := channelOf(t, p.guestDir, "zt"); gpe.State != roster.Gone {
		t.Fatalf("guest state %s, want gone", gpe.State)
	}
	mustRefuse(t, "zt forgot this channel", "send", "--dir", p.guestDir, "--text", "hello?", "zt")
	mustRefuse(t, "zt forgot its channel with you", "invite", "--dir", p.guestDir, "--relay", base, "--login", login, "zt")
	out = mustOK(t, "forget", "--dir", p.guestDir, "zt")
	if strings.Contains(out, "bye") || !strings.Contains(out, "forgot zt") {
		t.Fatalf("guest forget of a gone peer:\n%s", out)
	}

	again := handshake(t, p.hostDir, p.guestDir, base)
	if again.channel == p.channel {
		t.Fatal("the new channel reuses the old id")
	}
	id, _ := sendOK(t, p.guestDir, "--text", "back again", "zt/advisor")
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "delivered text "+id) {
		t.Fatalf("host serve after the new channel:\n%s", out)
	}
}

// Forgetting a peer withdraws this party's add over its channel and leaves
// a room both are seated in as it was.
func TestForgetWithdrawsAddsKeepsSeats(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	createRoom(t, p.hostDir, base, "seated")
	addToRoom(t, p.hostDir, p.guestDir, "seated", "ancan")
	createRoom(t, p.hostDir, base, "pending")
	mustOK(t, "room", "add", "--dir", p.hostDir, "pending", "ancan")

	out := mustOK(t, "forget", "--dir", p.hostDir, "ancan")
	if !strings.Contains(out, "room pending: the add of ancan is withdrawn (invited)") || strings.Contains(out, "room seated") {
		t.Fatalf("forget:\n%s", out)
	}
	hp, err := openParty(p.hostDir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := loadRooms(context.Background(), hp.backend)
	if err != nil {
		t.Fatal(err)
	}
	if ref := l.byName("pending"); ref == nil || len(ref.Adds) != 0 {
		t.Fatalf("pending room adds after forget: %+v", ref)
	}

	mustOK(t, "send", "--dir", p.hostDir, "--text", "the room goes on", "seated")
	out = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.Contains(out, "delivered text") {
		t.Fatalf("guest serve of the room after the forget:\n%s", out)
	}
}
