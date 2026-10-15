package room_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/room"
)

// Rule 7's table, one case per row.

func TestRule7RosterAddFromAdmin(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1 := newMember(t, 1)
	add(t, s, 1, 0, m1)
	if m := s.Member(1); m == nil || m.Party != m1.pid || !m.Seal().Equal(m1.keys.Seal.PublicKey()) {
		t.Fatalf("member 1: %+v", m)
	}
}

func TestRule7RosterAddFromMemberUnderMembers(t *testing.T) {
	s, _ := newRoom(t, room.AddMembers)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1)
	add(t, s, 2, 1, m2)
	if s.Member(2) == nil || len(s.Members()) != 3 {
		t.Fatal("member 1's add under add: members did not fold")
	}
}

func TestRule7RosterAddFromMemberUnderAdmins(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1)
	wantDropped(t, s, roster(2, 1, room.RosterBody{Members: []room.Entry{m2.entry(t, t0)}}), nil, "outside the admin set")
}

func TestRule7RosterRemoveFromAdmin(t *testing.T) {
	s, _ := newRoom(t, room.AddMembers)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1, m2)
	res := s.Fold(roster(2, 0, room.RosterBody{Removed: []uint16{2}}), nil)
	if !res.Folded() || !slices.Equal(res.Left, []uint16{2}) || s.Member(2) != nil || !s.Removed(2) {
		t.Fatalf("remove: %+v", res)
	}
	// Removing again changes nothing and reports nothing.
	if res = s.Fold(roster(3, 0, room.RosterBody{Removed: []uint16{2}}), nil); !res.Folded() || len(res.Left) != 0 {
		t.Fatalf("second remove: %+v", res)
	}
	// A non-admin's entry at the removed idx is refused on its own (sub-rule 1).
	res = s.Fold(roster(4, 1, room.RosterBody{Members: []room.Entry{m2.entry(t, t0.Add(time.Hour))}}), nil)
	if !res.Folded() || len(res.Joined) != 0 || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "removed") || s.Member(2) != nil {
		t.Fatalf("non-admin re-add at a removed idx: %+v", res)
	}
	// An admin's entry at a free idx folds, a removed one included: a
	// newcomer's state holds no removed set, so every member agrees.
	res = s.Fold(roster(5, 0, room.RosterBody{Members: []room.Entry{m2.entry(t, t0.Add(time.Hour))}}), nil)
	if !res.Folded() || !slices.Equal(res.Joined, []uint16{2}) || len(res.Refused) != 0 || s.Member(2) == nil || s.Removed(2) {
		t.Fatalf("admin re-add at a removed idx: %+v", res)
	}
}

func TestRule7RosterRemoveFromMember(t *testing.T) {
	s, _ := newRoom(t, room.AddMembers)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1, m2)
	wantDropped(t, s, roster(2, 1, room.RosterBody{Removed: []uint16{2}}), nil, "a member adds only")
}

// A handover extends the admin set: the admitted idx adds, removes and hands
// over, and keeps doing so after the creator leaves.
func TestHandoverExtendsAdminSet(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1, m2, m3 := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	add(t, s, 1, 0, m1, m2)
	res := s.Fold(rec(2, 0, room.KindHandover, room.HandoverBody{Idx: 1}), nil)
	if !res.Folded() || !slices.Equal(res.Admitted, []uint16{1}) || !slices.Equal(s.Admins(), []uint16{0, 1}) {
		t.Fatalf("handover: %+v admins %v", res, s.Admins())
	}
	if res = s.Fold(rec(3, 0, room.KindHandover, room.HandoverBody{Idx: 1}), nil); !res.Folded() || len(res.Admitted) != 0 {
		t.Fatalf("second handover to the same idx: %+v", res)
	}
	add(t, s, 4, 1, m3)
	if res = s.Fold(roster(5, 1, room.RosterBody{Removed: []uint16{2}}), nil); !slices.Equal(res.Left, []uint16{2}) {
		t.Fatalf("the new admin's remove: %+v", res)
	}
	if res = s.Fold(rec(6, 0, room.KindLeave, struct{}{}), nil); !slices.Equal(res.Left, []uint16{0}) || !slices.Equal(s.Admins(), []uint16{1}) {
		t.Fatalf("the creator's leave: %+v admins %v", res, s.Admins())
	}
	if res = s.Fold(rec(7, 1, room.KindHandover, room.HandoverBody{Idx: 3}), nil); !slices.Equal(res.Admitted, []uint16{3}) {
		t.Fatalf("the new admin's handover: %+v", res)
	}
	wantDropped(t, s, roster(8, 0, room.RosterBody{Members: []room.Entry{m2.entry(t, t0.Add(time.Hour))}}), nil, "outside the admin set")
}

func TestRule7HandoverFromMember(t *testing.T) {
	s, _ := newRoom(t, room.AddMembers)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1, m2)
	wantDropped(t, s, rec(2, 1, room.KindHandover, room.HandoverBody{Idx: 1}), nil, "outside the admin set")
}

func TestRule7LeaveFromLeavingIdx(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1 := newMember(t, 1)
	add(t, s, 1, 0, m1)
	res := s.Fold(rec(2, 1, room.KindLeave, struct{}{}), nil)
	if !res.Folded() || !slices.Equal(res.Left, []uint16{1}) || s.Member(1) != nil || !s.Removed(1) {
		t.Fatalf("leave: %+v", res)
	}
}

func TestRule7LeaveFromNonMember(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	wantDropped(t, s, rec(1, 5, room.KindLeave, struct{}{}), nil, "not a member")
	m1 := newMember(t, 1)
	add(t, s, 2, 0, m1)
	s.Fold(rec(3, 1, room.KindLeave, struct{}{}), nil)
	wantDropped(t, s, rec(4, 1, room.KindLeave, struct{}{}), nil, "not a member")
}

func TestRule7RoomCardFromOwnIdx(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1 := newMember(t, 1)
	add(t, s, 1, 0, m1)
	k2, _ := room.GenerateSealKey()
	m1.keys.Seal = k2
	res := s.Fold(rec(2, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: m1.roomCard(t, t0.Add(24*time.Hour))}), nil)
	if !res.Folded() || !slices.Equal(res.Updated, []uint16{1}) || !s.Member(1).Seal().Equal(k2.PublicKey()) || !s.Member(1).Sign().Equal(m1.keys.Sign.Public()) {
		t.Fatalf("roomcard: %+v", res)
	}
}

func TestRule7RoomCardFromOtherIdx(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1, m2)
	// m2 posts m1's own card: m1's identity signed it, not m2's.
	wantDropped(t, s, rec(2, 2, room.KindRoomCard, room.RoomCardBody{RoomCard: m1.roomCard(t, t0.Add(time.Hour))}), nil, "signature")
	// m2 posts a card for its own idx that m1's identity signed.
	forged, err := m2.keys.Card(roomID, 2, t0.Add(time.Hour)).Signed(m1.id)
	if err != nil {
		t.Fatal(err)
	}
	wantDropped(t, s, rec(3, 2, room.KindRoomCard, room.RoomCardBody{RoomCard: forged}), nil, "signature")
	// m2 posts a card its own identity signed for idx 1: keys for another idx.
	moved, err := m2.keys.Card(roomID, 1, t0.Add(time.Hour)).Signed(m2.id)
	if err != nil {
		t.Fatal(err)
	}
	wantDropped(t, s, rec(4, 2, room.KindRoomCard, room.RoomCardBody{RoomCard: moved}), nil, "card for idx 1")
}

// A roster entry or roomcard whose signing key is not 32 bytes is refused
// and named — the key a record's signature would be verified under never
// reaches ed25519.Verify, which panics on any other length.
func TestShortSigningKeyRefused(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1)
	short := *m2.keys.Card(roomID, 2, t0)
	short.Sign = base64.StdEncoding.EncodeToString(make([]byte, 16))
	body, _ := json.Marshal(&short)
	e := m2.entry(t, t0)
	e.RoomCard = signRaw(m2, body)
	res := s.Fold(roster(2, 0, room.RosterBody{Members: []room.Entry{e}}), nil)
	if !res.Folded() || len(res.Joined) != 0 || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "sign: 16 bytes") || s.Member(2) != nil {
		t.Fatalf("entry with a 16-byte signing key: %+v", res)
	}
	short = *m1.keys.Card(roomID, 1, t0.Add(time.Hour))
	short.Sign = base64.StdEncoding.EncodeToString(make([]byte, 16))
	body, _ = json.Marshal(&short)
	wantDropped(t, s, rec(3, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: signRaw(m1, body)}), nil, "sign: 16 bytes")
	if k := s.Member(1).Sign(); len(k) != ed25519.PublicKeySize {
		t.Fatalf("folded signing key %d bytes", len(k))
	}
}

// Every other signer, and every record outside the table, is dropped and named.
func TestRule7OtherSignersDropped(t *testing.T) {
	s, _ := newRoom(t, room.AddMembers)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1)
	cases := []struct {
		name string
		rec  room.Verified
		want string
	}{
		{"a v1 kind", rec(2, 0, "text", map[string]string{"x": "y"}), "outside the membership table"},
		{"a vendor kind", rec(2, 0, "vnd.example.nuke", map[string]any{}), "outside the membership table"},
		{"roster from an idx that is no member, under add: members", roster(2, 7, room.RosterBody{Members: []room.Entry{m2.entry(t, t0)}}), "not a member"},
		{"roomcard from an idx that is no member", rec(2, 7, room.KindRoomCard, room.RoomCardBody{RoomCard: m2.roomCard(t, t0)}), "not a member"},
		{"malformed roster body", room.Verified{Seq: 2, Idx: 0, Kind: room.KindRoster, Body: []byte("{"), At: at}, "malformed"},
		{"malformed handover body", room.Verified{Seq: 2, Idx: 0, Kind: room.KindHandover, Body: []byte(`{"idx":"one"}`), At: at}, "malformed"},
		{"malformed roomcard body", room.Verified{Seq: 2, Idx: 1, Kind: room.KindRoomCard, Body: []byte(`{"roomcard":1}`), At: at}, "malformed"},
		{"roomcard with a small-order seal key", rec(2, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: m1.smallOrderCard(t, t0.Add(time.Hour))}), "small-order point"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantDropped(t, s, c.rec, nil, c.want) })
	}
	// A roster entry whose room card carries a small-order seal key is
	// refused and named; the rest of the admin's record folds.
	bad := m2.entry(t, t0)
	bad.RoomCard = m2.smallOrderCard(t, t0)
	res := s.Fold(roster(2, 0, room.RosterBody{Members: []room.Entry{bad}}), nil)
	if !res.Folded() || len(res.Joined) != 0 || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "small-order point") || s.Member(2) != nil {
		t.Fatalf("entry with a small-order seal key: %+v", res)
	}
	if room.MembershipKind("text") || !room.MembershipKind(room.KindLeave) {
		t.Fatal("MembershipKind")
	}
}

// The contract's sub-rules, one case each.

// A non-admin roster (under add: members) carries members entries only — no
// removed, no add, and no entry at an idx another party holds in the fold.
func TestSubRuleMemberRosterEntriesOnly(t *testing.T) {
	s, _ := newRoom(t, room.AddMembers)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	add(t, s, 1, 0, m1)
	wantDropped(t, s, roster(2, 1, room.RosterBody{Add: room.AddAdmins, Members: []room.Entry{m2.entry(t, t0)}}), nil, "carries add or removed")
	wantDropped(t, s, roster(2, 1, room.RosterBody{Removed: []uint16{0}}), nil, "carries add or removed")
	stolen := memberOf(t, m2.party, 0) // m2's keys at the creator's idx
	wantDropped(t, s, roster(2, 1, room.RosterBody{Members: []room.Entry{stolen.entry(t, t0)}}), nil, "is held by")
	// From the admin the same entry is refused on its own and the record folds.
	res := s.Fold(roster(2, 0, room.RosterBody{Members: []room.Entry{stolen.entry(t, t0), m2.entry(t, t0)}}), nil)
	if !res.Folded() || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "held by") || !slices.Equal(res.Joined, []uint16{2}) {
		t.Fatalf("admin roster with a held idx: %+v", res)
	}
}

// add is read from record #0 alone and ignored elsewhere.
func TestSubRuleAddFromRecordZeroOnly(t *testing.T) {
	s, _ := newRoom(t, room.AddMembers)
	m1, m2 := newMember(t, 1), newMember(t, 2)
	res := s.Fold(roster(1, 0, room.RosterBody{Add: room.AddAdmins, Members: []room.Entry{m1.entry(t, t0)}}), nil)
	if !res.Folded() || !slices.Equal(res.Joined, []uint16{1}) || s.Add() != room.AddMembers {
		t.Fatalf("add on record 1: %+v add %s", res, s.Add())
	}
	add(t, s, 2, 1, m2)
	// A state born under one setting takes record #0's.
	adm := newMember(t, 0)
	s2, _ := room.New(newBackend(), roomID, 0, room.AddAdmins, adm.keys)
	if res = s2.Fold(roster(0, 0, room.RosterBody{Add: room.AddMembers, Members: []room.Entry{adm.entry(t, t0)}}), nil); !res.Folded() || s2.Add() != room.AddMembers {
		t.Fatalf("record #0's add: %+v add %s", res, s2.Add())
	}
	s3, _ := room.New(newBackend(), roomID, 0, room.AddAdmins, adm.keys)
	wantDropped(t, s3, roster(0, 0, room.RosterBody{Add: "anyone", Members: []room.Entry{adm.entry(t, t0)}}), nil, `add "anyone"`)
}

// handover {idx} names a current member.
func TestSubRuleHandoverNamesCurrentMember(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1 := newMember(t, 1)
	add(t, s, 1, 0, m1)
	wantDropped(t, s, rec(2, 0, room.KindHandover, room.HandoverBody{Idx: 9}), nil, "not a member")
	s.Fold(roster(3, 0, room.RosterBody{Removed: []uint16{1}}), nil)
	wantDropped(t, s, rec(4, 0, room.KindHandover, room.HandoverBody{Idx: 1}), nil, "not a member")
}

// roomcard.idx equals the header's idx; the identity-key signature verifies
// against that idx's party card — on roomcard records and roster entries.
func TestSubRuleRoomCardIdxAndSignature(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1, other := newMember(t, 1), newParty(t)
	add(t, s, 1, 0, m1)
	elsewhere, _ := m1.keys.Card(strings.Repeat("f", 32), 1, t0.Add(time.Hour)).Signed(m1.id)
	wantDropped(t, s, rec(2, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: elsewhere}), nil, "of room ffff")
	// The creator relays m1's card under its own idx: m1's signature, not the writer's.
	wantDropped(t, s, rec(2, 0, room.KindRoomCard, room.RoomCardBody{RoomCard: m1.roomCard(t, t0.Add(time.Hour))}), nil, "signature")
	// m1 posts a card its identity signed for idx 0.
	notMine, _ := m1.keys.Card(roomID, 0, t0.Add(time.Hour)).Signed(m1.id)
	wantDropped(t, s, rec(2, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: notMine}), nil, "card for idx 0")
	moved := m1.entry(t, t0.Add(time.Hour))
	moved.Idx = 5
	res := s.Fold(roster(3, 0, room.RosterBody{Members: []room.Entry{moved}}), nil)
	if !res.Folded() || len(res.Joined) != 0 || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "room card for idx 1") || s.Member(5) != nil {
		t.Fatalf("entry whose room card is at another idx: %+v", res)
	}
	forged := m1.entry(t, t0.Add(time.Hour))
	forged.RoomCard, _ = m1.keys.Card(roomID, 1, t0.Add(time.Hour)).Signed(other.id)
	res = s.Fold(roster(4, 0, room.RosterBody{Members: []room.Entry{forged}}), nil)
	if !res.Folded() || len(res.Updated) != 0 || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "signature") {
		t.Fatalf("entry whose room card another identity signed: %+v", res)
	}
	wrongParty := m1.entry(t, t0.Add(time.Hour))
	wrongParty.Card = room.PartyCard{Body: other.card.Body, Sig: other.card.Sig}
	res = s.Fold(roster(5, 0, room.RosterBody{Members: []room.Entry{wrongParty}}), nil)
	if !res.Folded() || len(res.Updated) != 0 || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "party card") {
		t.Fatalf("entry whose party card another root signed: %+v", res)
	}
}

// An entry or roomcard whose issued is older than the folded card for that
// idx is ignored; a newer one at the same idx for the same party is a card update.
func TestSubRuleOlderCardIgnoredNewerUpdates(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1 := newMember(t, 1)
	add(t, s, 1, 0, m1)
	firstPriv := m1.keys.Seal
	first := firstPriv.PublicKey()
	older, _ := room.GenerateSealKey()
	m1.keys.Seal = older
	quiet := func(what string, res room.Result) {
		t.Helper()
		if !res.Folded() || len(res.Updated) != 0 || len(res.Refused) != 0 || !s.Member(1).Seal().Equal(first) || !s.Member(1).Issued().Equal(t0) {
			t.Fatalf("%s: %+v, seal changed %v", what, res, !s.Member(1).Seal().Equal(first))
		}
	}
	quiet("older entry", s.Fold(roster(2, 0, room.RosterBody{Members: []room.Entry{m1.entry(t, t0.Add(-time.Hour))}}), nil))
	quiet("older roomcard", s.Fold(rec(3, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: m1.roomCard(t, t0.Add(-time.Hour))}), nil))
	quiet("same issued", s.Fold(rec(4, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: m1.roomCard(t, t0)}), nil))
	newer, _ := room.GenerateSealKey()
	m1.keys.Seal = newer
	res := s.Fold(roster(5, 0, room.RosterBody{Members: []room.Entry{m1.entry(t, t0.Add(time.Hour))}}), nil)
	if !slices.Equal(res.Updated, []uint16{1}) || !s.Member(1).Seal().Equal(newer.PublicKey()) || !s.Member(1).Issued().Equal(t0.Add(time.Hour)) {
		t.Fatalf("newer entry: %+v", res)
	}
	newest, _ := room.GenerateSealKey()
	m1.keys.Seal = newest
	if res = s.Fold(rec(6, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: m1.roomCard(t, t0.Add(2*time.Hour))}), nil); !slices.Equal(res.Updated, []uint16{1}) || !s.Member(1).Seal().Equal(newest.PublicKey()) {
		t.Fatalf("newer roomcard: %+v", res)
	}
	// The first key replayed never downgrades the member.
	m1.keys.Seal = firstPriv
	if res = s.Fold(rec(7, 1, room.KindRoomCard, room.RoomCardBody{RoomCard: m1.roomCard(t, t0)}), nil); !res.Folded() || len(res.Updated) != 0 || !s.Member(1).Seal().Equal(newest.PublicKey()) {
		t.Fatalf("replayed first card: %+v", res)
	}
}

// A fold whose sealed rm.<id> envelope would pass 256 KiB drops the entry and reports.
func TestSubRuleCapDropsEntry(t *testing.T) {
	ctx := context.Background()
	s, _ := newRoom(t, room.AddAdmins)
	pad := json.RawMessage(`{"pad":"` + strings.Repeat("a", 40_000) + `"}`)
	var body room.RosterBody
	for i := 1; i <= 6; i++ {
		root, _ := keys.GenerateRoot()
		id, _ := keys.GenerateIdentity(root.Public())
		body.Members = append(body.Members, memberOf(t, signParty(t, root, id, pad), uint16(i)).entry(t, t0))
	}
	res := s.Fold(roster(1, 0, body), nil)
	if !res.Folded() || len(res.Refused) == 0 || len(res.Joined) == 0 || len(res.Joined)+len(res.Refused) != 6 {
		t.Fatalf("cap: %+v", res)
	}
	for _, r := range res.Refused {
		if !strings.Contains(r, "would pass") {
			t.Fatalf("refusal %q does not name the cap", r)
		}
	}
	n, err := s.Size()
	if err != nil || n > room.MaxSealed {
		t.Fatalf("size %d after the fold, cap %d (%v)", n, room.MaxSealed, err)
	}
	if err := s.Commit(ctx); err != nil {
		t.Fatalf("commit under the cap: %v", err)
	}
	if len(s.Members()) != 1+len(res.Joined) {
		t.Fatalf("%d members, want %d", len(s.Members()), 1+len(res.Joined))
	}
	t.Logf("cap: %d of 6 padded entries folded, %d bytes sealed", len(res.Joined), n)
	// A plain entry still fits after the padded ones.
	add(t, s, 2, 0, newMember(t, 9))
}

// A membership record the sender itself puts is folded at send, before the
// put: its seq is unknown and its writer is the state's own idx.
func TestSubRuleOwnRecordFoldsAtSend(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	m1 := newMember(t, 1)
	res := s.Fold(roster(-1, 0, room.RosterBody{Members: []room.Entry{m1.entry(t, t0)}}), nil)
	if !slices.Equal(res.Joined, []uint16{1}) {
		t.Fatalf("own roster at send: %+v", res)
	}
	if res = s.Fold(rec(-1, 0, room.KindHandover, room.HandoverBody{Idx: 1}), nil); !slices.Equal(res.Admitted, []uint16{1}) {
		t.Fatalf("own handover at send: %+v", res)
	}
	if res = s.Fold(rec(-1, 0, room.KindLeave, struct{}{}), nil); !slices.Equal(res.Left, []uint16{0}) || !slices.Equal(s.Admins(), []uint16{1}) {
		t.Fatalf("own leave at send: %+v admins %v", res, s.Admins())
	}
}

// A read member cannot put: its new card travels in an admin's roster entry,
// its leave as the admin's roster removed.
func TestSubRuleReadMemberViaAdmin(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	r := newMember(t, 1)
	add(t, s, 1, 0, r)
	k2, _ := room.GenerateSealKey()
	r.keys.Seal = k2
	res := s.Fold(roster(2, 0, room.RosterBody{Members: []room.Entry{r.entry(t, t0.Add(24*time.Hour))}}), nil)
	if !slices.Equal(res.Updated, []uint16{1}) || !s.Member(1).Seal().Equal(k2.PublicKey()) {
		t.Fatalf("the reader's card through the admin: %+v", res)
	}
	if res = s.Fold(roster(3, 0, room.RosterBody{Removed: []uint16{1}}), nil); !slices.Equal(res.Left, []uint16{1}) || s.Member(1) != nil {
		t.Fatalf("the reader's leave through the admin: %+v", res)
	}
}

// Rule 4: a roster entry naming a party the member holds a confirmed channel
// with, under a different root, is refused and the human told.
func TestCrossCheckRefusal(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	x := newParty(t) // the peer on a confirmed channel
	channels := room.Channels(func(identity [32]byte) (ed25519.PublicKey, bool) {
		if identity == x.id.PublicKey() {
			return x.root.Public(), true
		}
		return nil, false
	})
	// A second root presenting x's identity key as its own, with a room card x's identity signed.
	y, _ := keys.GenerateRoot()
	puppet := memberOf(t, signParty(t, y, x.id, nil), 1)
	res := s.Fold(roster(1, 0, room.RosterBody{Members: []room.Entry{puppet.entry(t, t0)}}), channels)
	if !res.Folded() || len(res.Joined) != 0 || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "rule 4") || !strings.Contains(res.Refused[0], x.pid) || s.Member(1) != nil {
		t.Fatalf("puppet: %+v", res)
	}
	xm := memberOf(t, x, 2)
	if res = s.Fold(roster(2, 0, room.RosterBody{Members: []room.Entry{xm.entry(t, t0)}}), channels); !slices.Equal(res.Joined, []uint16{2}) || len(res.Refused) != 0 {
		t.Fatalf("the party itself matches its channel: %+v", res)
	}
	z := newMember(t, 3)
	if res = s.Fold(roster(3, 0, room.RosterBody{Members: []room.Entry{z.entry(t, t0)}}), channels); !slices.Equal(res.Joined, []uint16{3}) {
		t.Fatalf("a party on no channel is the admin's word: %+v", res)
	}
	// Seed applies the same check to an invite's roster, and takes the
	// invite's admin set as the starting one: a creator that left is out of it.
	n := newMember(t, 4)
	s2, _ := room.New(newBackend(), roomID, 4, room.AddAdmins, n.keys)
	res = s2.Seed([]room.Entry{puppet.entry(t, t0), xm.entry(t, t0), z.entry(t, t0)}, []uint16{2}, channels, at)
	if !slices.Equal(res.Joined, []uint16{2, 3}) || len(res.Refused) != 1 || !slices.Equal(res.Admitted, []uint16{2}) || !slices.Equal(s2.Admins(), []uint16{2}) {
		t.Fatalf("seed: %+v admins %v", res, s2.Admins())
	}
	// With no channels to check against, the entry is the admin's word.
	s3, _ := newRoom(t, room.AddAdmins)
	if res = s3.Fold(roster(1, 0, room.RosterBody{Members: []room.Entry{puppet.entry(t, t0)}}), nil); !slices.Equal(res.Joined, []uint16{1}) {
		t.Fatalf("no channels: %+v", res)
	}
}

// 100 members from realistic cards, the seen ring full, a retired key and
// every writer's counter: the record commits under the sealed cap.
func TestHundredMembersUnderCap(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	adm := newMember(t, 0)
	s, _ := room.New(b, roomID, 0, room.AddAdmins, adm.keys)
	s.Fold(roster(0, 0, room.RosterBody{Add: room.AddAdmins, Members: []room.Entry{adm.entry(t, t0)}}), nil)
	var body room.RosterBody
	for i := 1; i < 100; i++ {
		body.Members = append(body.Members, newMember(t, uint16(i)).entry(t, t0))
	}
	res := s.Fold(roster(1, 0, body), nil)
	if !res.Folded() || len(res.Joined) != 99 || len(res.Refused) != 0 {
		t.Fatalf("99 entries: joined %d refused %d: %v", len(res.Joined), len(res.Refused), res.Refused)
	}
	for i := 0; i < room.MaxSeen; i++ {
		s.MarkSeen(fmt.Sprintf("%022d", i), int64(i+2)) // v1 ids are 22 base64url characters
	}
	for i := 1; i < 100; i++ {
		s.CheckCounter(uint16(i), uint64(1000+i))
	}
	k2, _ := room.GenerateSealKey()
	s.Rotate(k2, t0)
	s.Posted(1)
	s.SetCursor(room.MaxSeen + 1)
	n, err := s.Size()
	if err != nil || n > room.MaxSealed {
		t.Fatalf("100 members: %d bytes sealed, cap %d (%v)", n, room.MaxSealed, err)
	}
	t.Logf("100 members, ring full: %d bytes sealed of %d", n, room.MaxSealed)
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := room.Load(ctx, b, roomID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Members()) != 100 || !got.Seen(fmt.Sprintf("%022d", 0)) || len(got.RetiredSealKeys()) != 1 {
		t.Fatalf("reload: %d members", len(got.Members()))
	}
}
