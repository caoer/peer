package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/sealed"
)

// What the relay holds for a room, from the client's side: three parties in
// a room with no feed, each says something into it and one record goes to a
// subset; every record the relay stored is a sealed record whose header —
// v, room, idx, ctr, kh, at — is the only plaintext, and neither the records,
// the JSON they are served in, nor the members answer hold the messages, the
// party ids, the petnames, the room's local name or the member cards'
// details — as text, inside any base64 run, or as hex. The milestone-2 run
// made the same scan of a live room once (results/milestone-v2.md § 7); this
// keeps it running. TestRelayHoldsCiphertextOnly is the channels' half.
func TestRoomRelayHoldsCiphertextOnly(t *testing.T) {
	const (
		textA, textB, textC = "room-text-a-relay-must-never-read", "room-text-b-relay-must-never-read", "room-text-c-relay-must-never-read"
		textSubset          = "room-subset-text-relay-must-never-read"
		bobName             = "bob-petname-relay-must-never-read"
		carolName           = "carol-petname-relay-must-never-read"
		aliceName           = "alice-petname-relay-must-never-read"
		roomName            = "room-name-relay-must-never-read"
		detailsMarker       = "room-details-relay-must-never-read"
	)
	srv, _, base := relaytest.Start(t, login)
	cfgA := config{
		Agents:  []card.Agent{{ID: "advisor", Accepts: []string{"text", "task"}}},
		Details: json.RawMessage(`{"advisor":{"type":"claude-code","note":"` + detailsMarker + `"}}`),
	}
	a, b, c := newDir(t, cfgA), newDir(t, config{}), newDir(t, config{})
	ab := handshakeNamed(t, a, b, base, bobName, aliceName)
	ac := handshakeNamed(t, a, c, base, carolName, aliceName)
	id := createRoom(t, a, base, roomName)
	addToRoom(t, a, b, roomName, bobName)
	addToRoom(t, a, c, roomName, carolName)
	for _, d := range []string{b, c, a} {
		mustOK(t, "serve", "--dir", d, "--once")
	}
	sent := map[string]string{} // id → text
	for d, text := range map[string]string{a: textA, b: textB, c: textC} {
		name := id[:8]
		if d == a {
			name = roomName
		}
		mid, _ := roomSendOK(t, d, "--text", "says: "+text, name)
		sent[mid] = text
	}
	subset, _ := roomSendOK(t, a, "--to", bobName, "--text", "says: "+textSubset, roomName)

	secrets := map[string]string{
		"A's text": textA, "B's text": textB, "C's text": textC, "subset text": textSubset,
		"A's party id": ab.hostParty, "B's party id": ab.guestParty, "C's party id": ac.guestParty,
		"petname of B": bobName, "petname of C": carolName, "petname of A": aliceName,
		"room's local name": roomName, "details": detailsMarker,
	}
	scan := func(where, text string) {
		t.Helper()
		for what, s := range secrets {
			if holds(text, s) {
				t.Errorf("the relay holds the %s in %s", what, where)
			}
		}
	}

	rows := srv.RoomRecords(id)
	if len(rows) < len(sent)+1 {
		t.Fatalf("the relay holds %d room records, want at least %d", len(rows), len(sent)+1)
	}
	served, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	scan("the records' JSON", string(served))
	wantKeys := []string{"at", "ctr", "idx", "kh", "room", "v"}
	for _, row := range rows {
		where := "record #" + strconv.FormatInt(row.Seq, 10)
		if row.Type != "sealed" {
			t.Errorf("%s is of type %q, not sealed", where, row.Type)
		}
		raw := mustB64(t, row.Body)
		rec, err := sealed.Parse(raw)
		if err != nil {
			t.Errorf("%s is not a sealed record: %v", where, err)
			continue
		}
		if rec.Header.Room != id || int(rec.Header.Idx) != row.Idx {
			t.Errorf("%s header room %s idx %d, relay idx %d", where, rec.Header.Room, rec.Header.Idx, row.Idx)
		}
		// The header is the one plaintext segment: its keys are the contract's six.
		hdr := raw[4 : 4+binary.BigEndian.Uint32(raw)]
		var h map[string]json.RawMessage
		if err := json.Unmarshal(hdr, &h); err != nil {
			t.Errorf("%s header: %v", where, err)
		}
		var keys []string
		for k := range h {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, wantKeys) {
			t.Errorf("%s header keys %v, want %v", where, keys, wantKeys)
		}
		scan(where, string(raw))
	}

	_, aref, _ := roomOf(t, a, roomName)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/r/"+id+"/members", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+aref.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	members, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("members answer %d: %v\n%s", resp.StatusCode, err, members)
	}
	var ms struct{ Members []json.RawMessage }
	if err := json.Unmarshal(members, &ms); err != nil || len(ms.Members) != 3 {
		t.Fatalf("members answer holds %d members (%v):\n%s", len(ms.Members), err, members)
	}
	scan("the members answer", string(members))

	// The scan is not vacuous: every message crossed and opened at the far ends.
	for _, d := range []string{a, b, c} {
		mustOK(t, "serve", "--dir", d, "--once")
	}
	for d, who := range map[string]string{a: "A", b: "B", c: "C"} {
		in := withoutRoster(t, records(t, deliverDirOf(d), deliver.Inbox))
		for mid, text := range sent {
			if rec, ok := in[mid]; ok && !strings.Contains(string(rec), text) {
				t.Fatalf("%s's record %s does not hold its text:\n%s", who, mid, rec)
			}
		}
		if want := 2 + map[string]int{a: 0, b: 1, c: 0}[d]; len(in) != want {
			t.Fatalf("%s holds %d records, want %d", who, len(in), want)
		}
	}
	if rec := withoutRoster(t, records(t, deliverDirOf(b), deliver.Inbox))[subset]; !strings.Contains(string(rec), textSubset) {
		t.Fatalf("B's inbox does not hold the subset text:\n%s", rec)
	}
}
