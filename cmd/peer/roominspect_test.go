package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
)

func inspect(t *testing.T, dir, name string) roomInspect {
	t.Helper()
	var v roomInspect
	if err := json.Unmarshal([]byte(mustOK(t, "room", "inspect", "--dir", dir, name)), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// inspect prints every record the relay holds for the caller's view, its
// own included, each as the relay holds it with its framing; the members
// to an admin token alone; and says what it did not show.
func TestRoomInspect(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	a, b := newDir(t, config{}), newDir(t, config{})
	handshakeNamed(t, a, b, base, "bob", "alice")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	putRoomText(t, a, "r1", "from alice")
	putRoomText(t, b, id[:8], "from bob")
	rows := srv.RoomRecords(id)

	va := inspect(t, a, "r1")
	if va.ID != id || va.Name != "r1" || va.Relay != base {
		t.Fatalf("room %s %s %s", va.ID, va.Name, va.Relay)
	}
	if va.You.Idx != 0 || va.You.Role != relay.RoleWrite || va.You.From != 0 || !va.You.Admin {
		t.Fatalf("alice's seat %+v", va.You)
	}
	if va.Room.Membership != srv.RoomMembership(id) || va.Room.Next != int64(len(rows)) || va.Room.Retention != 30*24*3600*1000 || va.Room.Add != relay.AddAdmins {
		t.Fatalf("room state %+v", va.Room)
	}
	if va.Room.Alarm == nil || *va.Room.Alarm != rows[0].At+va.Room.Retention+1 {
		t.Fatalf("alarm %v, want the oldest record's expiry + 1", va.Room.Alarm)
	}
	// Read a page of two records at a time, it prints the same.
	srv.PageSize = 2
	if paged := inspect(t, a, "r1"); len(paged.Records) != len(rows) || paged.Records[len(rows)-1].Seq != rows[len(rows)-1].Seq {
		t.Fatalf("paged by two: %d records, want %d", len(paged.Records), len(rows))
	}
	srv.PageSize = 100
	if va.Log.Count != int64(len(rows)) || va.Log.First == nil || *va.Log.First != 0 || *va.Log.Oldest != rows[0].At {
		t.Fatalf("log %+v", va.Log)
	}
	if len(va.Members) != 2 || va.Members[1] != (relay.Member{Idx: 1, Role: relay.RoleWrite, From: va.Members[1].From}) || len(va.Notes) != 0 {
		t.Fatalf("members %+v, notes %q", va.Members, va.Notes)
	}
	// Every record, alice's own among them, as the relay holds it.
	if len(va.Records) != len(rows) {
		t.Fatalf("%d records, the relay holds %d", len(va.Records), len(rows))
	}
	for i, r := range va.Records {
		row := rows[i]
		raw, _ := base64.StdEncoding.DecodeString(row.Body)
		sum := sha256.Sum256(raw)
		if r.Seq != row.Seq || r.Idx != row.Idx || r.Type != "sealed" || r.At != row.At || r.Expires != row.At+va.Room.Retention ||
			r.Size != len(raw) || r.SHA256 != hex.EncodeToString(sum[:]) || r.Body != row.Body || r.Head != "" || r.Error != "" {
			t.Fatalf("record %d: %+v, relay row %+v", i, r, row)
		}
		if r.Sealed == nil || int(r.Sealed.Idx) != row.Idx || r.Sealed.KH == "" {
			t.Fatalf("record %d framing %+v", i, r.Sealed)
		}
		if _, err := time.Parse(time.RFC3339, r.Sealed.At); err != nil {
			t.Fatalf("record %d header at %q: %v", i, r.Sealed.At, err)
		}
	}
	// #0, the creator's roster, is sealed to alice alone; the texts to both.
	if !slices.Equal(va.Records[0].Sealed.To, []uint16{0}) || !slices.Equal(va.Records[len(rows)-1].Sealed.To, []uint16{0, 1}) {
		t.Fatalf("recipients %v, %v", va.Records[0].Sealed.To, va.Records[len(rows)-1].Sealed.To)
	}
	if last := va.Records[len(rows)-1]; last.Idx != 1 {
		t.Fatalf("the last record is idx %d's, want bob's text", last.Idx)
	}

	// bob: no member list, nothing below his from, his own text in his view.
	vb := inspect(t, b, id[:8])
	from := vb.You.From
	if vb.You.Idx != 1 || vb.You.Admin || from == 0 || vb.Members != nil {
		t.Fatalf("bob's seat %+v, members %+v", vb.You, vb.Members)
	}
	var want []int64
	for _, row := range rows {
		if row.Seq >= from {
			want = append(want, row.Seq)
		}
	}
	var got []int64
	for _, r := range vb.Records {
		got = append(got, r.Seq)
	}
	if !slices.Equal(got, want) || vb.Records[len(vb.Records)-1].Idx != 1 || vb.Log.Count != int64(len(want)) || *vb.Log.First != from {
		t.Fatalf("bob's records %v, want %v; log %+v", got, want, vb.Log)
	}
	// His alarm is his own oldest record's: nothing below his from is timed.
	if first := rows[from]; vb.Room.Alarm == nil || *vb.Room.Alarm != first.At+vb.Room.Retention+1 {
		t.Fatalf("bob's alarm %v, want #%d's expiry + 1", vb.Room.Alarm, from)
	}
	if notes := strings.Join(vb.Notes, "\n"); !strings.Contains(notes, "members: ") || !strings.Contains(notes, "below #") {
		t.Fatalf("notes %q", vb.Notes)
	}
	if out := mustOK(t, "room", "inspect", "--dir", b, id[:8]); !strings.Contains(out, `"members": null`) {
		t.Fatalf("members is not null for a member token:\n%s", out)
	}

	mustRefuse(t, "no room named", "room", "inspect", "--dir", a, "nope")
}

// A large body prints its head and digest; a body that is no sealed record
// prints what it is and why its framing is missing; a malformed row keeps
// its seq.
func TestRoomInspectRow(t *testing.T) {
	big := make([]byte, inspectWhole+1)
	for i := range big {
		big[i] = byte(i)
	}
	at := time.UnixMilli(1_700_000_000_000)
	r := inspectRow(relay.RoomRecord{Seq: 7, Idx: 2, At: at, Body: big}, 10)
	sum := sha256.Sum256(big)
	if r.Body != "" || r.Head != base64.StdEncoding.EncodeToString(big[:inspectHead]) || r.SHA256 != hex.EncodeToString(sum[:]) ||
		r.Size != len(big) || r.Expires != at.UnixMilli()+10 || r.Sealed != nil || r.Error == "" {
		t.Fatalf("large row %+v", r)
	}
	small := inspectRow(relay.RoomRecord{Seq: 8, Idx: 2, At: at, Body: []byte("x")}, 10)
	if small.Body != "eA==" || small.Head != "" || small.Sealed != nil || small.Error == "" {
		t.Fatalf("small row %+v", small)
	}
	bad := inspectRow(relay.RoomRecord{Seq: 9, Idx: -1, At: at, Err: relay.ErrAnswer}, 10)
	if bad.Seq != 9 || bad.Error == "" || bad.Type != "" || bad.Size != 0 || bad.At != at.UnixMilli() {
		t.Fatalf("malformed row %+v", bad)
	}
}
