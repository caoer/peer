package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/store"
)

// roomDuo is room r1, which A created and B joined over their channel; both
// served to quiet, then A's first text read by B's serve, so B's cursor is
// at the room's head and its next frame is no gap.
type roomDuo struct {
	srv      *relaytest.Server
	base     string
	a, b     string
	id, name string // the room id, and B's name for the room
	idx      int    // B's idx
	earlier  []string
}

func newRoomDuo(t *testing.T, cfgA, cfgB config) *roomDuo {
	t.Helper()
	srv, _, base := relaytest.Start(t, login)
	d := &roomDuo{srv: srv, base: base, a: newDir(t, cfgA), b: newDir(t, cfgB)}
	handshakeNamed(t, d.a, d.b, base, "bob", "alice")
	d.id = createRoom(t, d.a, base, "r1")
	d.name = d.id[:8]
	addToRoom(t, d.a, d.b, "r1", "bob")
	mustOK(t, "serve", "--dir", d.a, "--once")
	mid, _ := roomSendOK(t, d.a, "--text", "before serve", "r1")
	if out := mustOK(t, "serve", "--dir", d.b, "--once"); !strings.Contains(out, "delivered text "+mid) {
		t.Fatalf("B's serve did not deliver %s:\n%s", mid, out)
	}
	d.earlier = append(d.earlier, mid)
	d.idx = int(refOf(t, d.b, d.name).Idx)
	return d
}

// send is A's text into the room; its id.
func (d *roomDuo) send(t *testing.T, text string) string {
	t.Helper()
	mid, _ := roomSendOK(t, d.a, "--text", text, "r1")
	return mid
}

// waitRoom waits until n of B's sockets are open on the relay and it has
// answered pulls B's pulls.
func (d *roomDuo) waitRoom(t *testing.T, sockets, pulls int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for d.srv.RoomSockets(d.id, d.idx) < sockets || d.srv.RoomPulls(d.id, d.idx) < pulls {
		if time.Now().After(deadline) {
			t.Fatalf("the relay holds %d of B's sockets and answered %d pulls, want %d and %d", d.srv.RoomSockets(d.id, d.idx), d.srv.RoomPulls(d.id, d.idx), sockets, pulls)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settle runs serve on B until its room socket is open and the round's and
// the open's pulls have answered, then sends a warm-up only its frame can
// deliver and waits for that. It returns serve's output, the warm-up's id
// and B's pulls answered so far.
func (d *roomDuo) settle(t *testing.T) (*syncBuffer, string, int) {
	t.Helper()
	pulls := d.srv.RoomPulls(d.id, d.idx) + 2
	out := runServe(t, d.b, time.Hour)
	waitFor(t, out, "room "+d.name+": push socket open", 1)
	d.waitRoom(t, 1, pulls)
	id := d.send(t, "warm-up")
	waitFor(t, out, "delivered text "+id, 1)
	return out, id, d.srv.RoomPulls(d.id, d.idx)
}

// deliveredOnce checks each id was born once in serve's output and B's inbox
// holds those and the setup's records alone, roster notices aside.
func (d *roomDuo) deliveredOnce(t *testing.T, out *syncBuffer, ids ...string) {
	t.Helper()
	inbox := withoutRoster(t, records(t, deliverDirOf(d.b), deliver.Inbox))
	for _, id := range ids {
		if n := strings.Count(out.String(), "delivered text "+id+" → "); n != 1 {
			t.Errorf("%s delivered %d times", id, n)
		}
	}
	for _, id := range append(ids, d.earlier...) {
		if _, ok := inbox[id]; !ok {
			t.Errorf("%s not in the inbox", id)
		}
	}
	if want := len(ids) + len(d.earlier); len(inbox) != want {
		t.Errorf("inbox holds %d records, want %d", len(inbox), want)
	}
}

// A pushed room record is delivered once, by its frame: no pull runs for it.
func TestRoomPushDeliversAFrameOnce(t *testing.T) {
	d := newRoomDuo(t, config{}, config{})
	out, id0, pulls := d.settle(t)
	id1 := d.send(t, "pushed one")
	waitFor(t, out, "delivered text "+id1, 1)
	id2 := d.send(t, "pushed two")
	waitFor(t, out, "delivered text "+id2, 1)
	if n := d.srv.RoomPulls(d.id, d.idx); n != pulls {
		t.Fatalf("%d room pulls for two pushed frames, want none", n-pulls)
	}
	d.deliveredOnce(t, out, id0, id1, id2)
}

// A room socket closed mid-stream (1001, a deploy) is opened again and the
// pull on the reconnect reads what was put while it was down; a frame lost
// on an open socket shows as a gap at the next frame and is pulled. Nothing
// is delivered twice.
func TestRoomPushReconnectPullsTheGap(t *testing.T) {
	d := newRoomDuo(t, config{}, config{})
	out := runServe(t, d.b, time.Hour)
	waitFor(t, out, "room "+d.name+": push socket open", 1)
	d.waitRoom(t, 1, 0)
	id1 := d.send(t, "before the deploy")
	waitFor(t, out, "delivered text "+id1, 1)

	d.srv.NoPush(true)
	d.srv.CloseSockets()
	waitFor(t, out, "room "+d.name+": push socket closed (", 1)
	waitFor(t, out, "room "+d.name+": no push socket (", 1)
	id2 := d.send(t, "during the deploy")
	id3 := d.send(t, "still during it")
	d.srv.NoPush(false)
	waitFor(t, out, "room "+d.name+": push socket open", 2)
	waitFor(t, out, "delivered text "+id2, 1)
	waitFor(t, out, "delivered text "+id3, 1)
	d.waitRoom(t, 1, 0)

	d.srv.DropPushes(1)
	id4 := d.send(t, "its frame is lost")
	id5 := d.send(t, "its frame shows the gap")
	waitFor(t, out, "delivered text "+id5, 1)
	waitFor(t, out, "delivered text "+id4, 1)

	d.deliveredOnce(t, out, id1, id2, id3, id4, id5)
}

// push.pullEvery frames make one room pull, and fewer make none.
func TestRoomPushPullsAfterEveryNFrames(t *testing.T) {
	cfg := config{}
	cfg.Push.PullEvery = 3
	d := newRoomDuo(t, config{}, cfg)
	// The warm-up is the cycle's first frame.
	out, id0, pulls := d.settle(t)
	ids := []string{id0}
	send := func(text string) {
		id := d.send(t, text)
		waitFor(t, out, "delivered text "+id, 1)
		ids = append(ids, id)
	}
	send("the second frame")
	if n := d.srv.RoomPulls(d.id, d.idx) - pulls; n != 0 {
		t.Fatalf("%d room pulls after 2 frames with push.pullEvery 3, want 0", n)
	}
	send("the third frame")
	// The third frame's pull runs after its "delivered" line; the next
	// cycle's first frame goes once that pull answered.
	d.waitRoom(t, 1, pulls+1)
	send("the fourth frame")
	if n := d.srv.RoomPulls(d.id, d.idx) - pulls; n != 1 {
		t.Fatalf("%d room pulls after 4 frames with push.pullEvery 3, want 1", n)
	}
	d.deliveredOnce(t, out, ids...)
}

// A relay that never answers the room upgrade leaves serve pulling the room
// every round, and says so once.
func TestRoomPushAbsentServePulls(t *testing.T) {
	d := newRoomDuo(t, config{}, config{})
	d.srv.NoPush(true)
	out := runServe(t, d.b, 100*time.Millisecond)
	waitFor(t, out, "room "+d.name+": no push socket (", 1)
	id := d.send(t, "pulled")
	waitFor(t, out, "delivered text "+id, 1)
	time.Sleep(300 * time.Millisecond) // more rounds and failed upgrades
	if s := out.String(); strings.Contains(s, "room "+d.name+": push socket open") || strings.Count(s, "room "+d.name+": no push socket") != 1 {
		t.Fatalf("serve output without push:\n%s", s)
	}
	d.deliveredOnce(t, out, id)
}

// The admin's revoke closes B's room socket with 4401: B's serve says the
// room revoked it, the pull that follows marks the room removed, and the
// socket is not opened again.
func TestRoomPushRevokeStopsTheSocket(t *testing.T) {
	d := newRoomDuo(t, config{}, config{})
	pulls := d.srv.RoomPulls(d.id, d.idx) + 2
	out := runServe(t, d.b, time.Hour)
	waitFor(t, out, "room "+d.name+": push socket open", 1)
	// The round's and the open's pulls answered: the revoke reaches B on
	// its socket, not in a pull.
	d.waitRoom(t, 1, pulls)

	admin := refOf(t, d.a, "r1")
	if _, err := relay.New(d.base, nil).RemoveMember(context.Background(), d.id, admin.Token, d.idx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, out, "room "+d.name+": the relay closed the push socket: it has revoked this member", 1)
	waitFor(t, out, "room "+d.name+": "+errGone.Error(), 1)
	if ref := refOf(t, d.b, d.name); ref.Stage != stageRemoved || ref.Token != "" {
		t.Fatalf("B's room after the revoke: stage %q, token %q; want removed, no token", ref.Stage, ref.Token)
	}
	time.Sleep(300 * time.Millisecond) // past the reconnect backoff
	s := out.String()
	if n := strings.Count(s, "room "+d.name+": push socket open"); n != 1 || strings.Contains(s, "room "+d.name+": push socket closed") {
		t.Fatalf("the revoked room's socket was opened again:\n%s", s)
	}
	if n := d.srv.RoomSockets(d.id, d.idx); n != 0 {
		t.Fatalf("%d sockets open for the revoked idx", n)
	}
}

// Two hosts of one party serve one room on a shared state, each with its
// room socket open: every record pushed to both is born exactly once across
// the two, and both room spools end empty.
func TestTwoHostsPushOneRoom(t *testing.T) {
	cfgA := config{}
	cfgA.State.Dir = filepath.Join(t.TempDir(), "shared-state")
	d := newRoomDuo(t, cfgA, config{})
	hostB := secondHost(t, d.a)
	aIdx := int(refOf(t, d.a, "r1").Idx)
	fastBackoff(t)
	x, y := serveLoop(t, d.a, time.Hour), serveLoop(t, hostB, time.Hour)
	waitFor(t, x, "room r1: push socket open", 1)
	waitFor(t, y, "room r1: push socket open", 1)
	deadline := time.Now().Add(15 * time.Second)
	for d.srv.RoomSockets(d.id, aIdx) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("%d of A's sockets open, want 2", d.srv.RoomSockets(d.id, aIdx))
		}
		time.Sleep(5 * time.Millisecond)
	}

	var ids []string
	for _, text := range []string{"one", "two", "three"} {
		mid, _ := roomSendOK(t, d.b, "--text", "room message "+text, d.name)
		ids = append(ids, mid)
	}
	for _, mid := range ids {
		for deadline := time.Now().Add(15 * time.Second); !strings.Contains(x.String()+y.String(), "delivered text "+mid); {
			if time.Now().After(deadline) {
				t.Fatalf("%s not delivered on either host", mid)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	time.Sleep(300 * time.Millisecond) // a second birth, were there one
	born := map[string]int{}
	for _, dir := range []string{d.a, hostB} {
		for mid := range withoutRoster(t, records(t, deliverDirOf(dir), deliver.Inbox)) {
			born[mid]++
		}
		j, err := store.OpenJournal(filepath.Join(dir, roomSpoolDir))
		if err != nil {
			t.Fatal(err)
		}
		if es, _ := j.Entries(); len(es) != 0 {
			t.Errorf("%s: room spool holds %+v", dir, es)
		}
	}
	for _, mid := range ids {
		if born[mid] != 1 {
			t.Errorf("%s born %d times across the two hosts, want exactly once", mid, born[mid])
		}
		if n := strings.Count(x.String()+y.String(), "delivered text "+mid+" → "); n != 1 {
			t.Errorf("%s delivered %d times across the two hosts", mid, n)
		}
	}
}
