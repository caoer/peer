package room_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/store"
)

const roomID = "0123456789abcdef0123456789abcdef"

// t0 is when every fixture card is issued; records arrive an hour later.
var (
	t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	at = t0.Add(time.Hour)
)

// memBackend is a store.Backend in memory: versions under CAS, no sealing.
type memBackend struct {
	recs map[string]memRec
}

type memRec struct {
	data []byte
	v    int64
}

func newBackend() *memBackend { return &memBackend{recs: map[string]memRec{}} }

func (b *memBackend) Load(ctx context.Context, key string) ([]byte, int64, error) {
	r, ok := b.recs[key]
	if !ok {
		return nil, 0, nil
	}
	return r.data, r.v, nil
}

func (b *memBackend) Store(ctx context.Context, key string, data []byte, expect int64) (int64, error) {
	r := b.recs[key]
	if r.v != expect {
		return 0, &store.ConflictError{Key: key, Expected: expect, Found: r.v}
	}
	b.recs[key] = memRec{data: append([]byte(nil), data...), v: expect + 1}
	return expect + 1, nil
}

// party is a v1 party: its root, identity and root-signed card.
type party struct {
	root *keys.Root
	id   *keys.Identity
	card *card.Signed
	pid  string
}

var (
	agents = []card.Agent{{ID: "advisor", Accepts: []string{"text", "task"}}, {ID: "worker", Accepts: []string{"text"}}}
	relays = []string{"https://relay.example.test/peer"}
)

func newParty(t *testing.T) *party {
	t.Helper()
	root, err := keys.GenerateRoot()
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.GenerateIdentity(root.Public())
	if err != nil {
		t.Fatal(err)
	}
	return signParty(t, root, id, nil)
}

// signParty signs a card for root with id's keys; details, when given, go on the card.
func signParty(t *testing.T, root *keys.Root, id *keys.Identity, details json.RawMessage) *party {
	t.Helper()
	pk, err := keys.GeneratePartyKeys(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := card.New(id, pk, agents, relays, t0)
	c.Party = keys.PartyID(root.Public())
	c.Details = details
	signed, err := card.Sign(c, root)
	if err != nil {
		t.Fatal(err)
	}
	return &party{root: root, id: id, card: signed, pid: c.Party}
}

// member is a party at an idx with its own room keys.
type member struct {
	*party
	idx  uint16
	keys *room.OwnKeys
}

func newMember(t *testing.T, idx uint16) *member {
	t.Helper()
	return memberOf(t, newParty(t), idx)
}

func memberOf(t *testing.T, p *party, idx uint16) *member {
	t.Helper()
	k, err := room.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	return &member{party: p, idx: idx, keys: k}
}

// roomCard is the member's room card signed by its identity, issued at a time.
func (m *member) roomCard(t *testing.T, issued time.Time) []byte {
	t.Helper()
	rc, err := m.keys.Card(roomID, m.idx, issued).Signed(m.id)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

// smallOrderCard is the member's room card with seal u=1, a small-order
// point Signed refuses, signed by hand.
func (m *member) smallOrderCard(t *testing.T, issued time.Time) []byte {
	t.Helper()
	c := m.keys.Card(roomID, m.idx, issued)
	c.Seal = base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return signRaw(m, body)
}

// entry is the member's roster entry with a room card issued at a time.
func (m *member) entry(t *testing.T, issued time.Time) room.Entry {
	t.Helper()
	return room.Entry{Idx: m.idx, Party: m.pid, Card: room.PartyCard{Body: m.card.Body, Sig: m.card.Sig}, RoomCard: m.roomCard(t, issued)}
}

// rec is a verified record of kind from idx at seq with a JSON body.
func rec(seq int64, idx uint16, kind string, body any) room.Verified {
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return room.Verified{Seq: seq, Idx: idx, Kind: kind, Body: b, At: at}
}

func roster(seq int64, idx uint16, body room.RosterBody) room.Verified {
	return rec(seq, idx, room.KindRoster, body)
}

// newRoom is the creator's state at idx 0 with record #0 folded at send: its
// own entry and the add setting.
func newRoom(t *testing.T, add room.Add) (*room.State, *member) {
	t.Helper()
	adm := newMember(t, 0)
	s, err := room.New(newBackend(), roomID, 0, add, adm.keys)
	if err != nil {
		t.Fatal(err)
	}
	res := s.Fold(roster(0, 0, room.RosterBody{Add: add, Members: []room.Entry{adm.entry(t, t0)}}), nil)
	if !res.Folded() || len(res.Joined) != 1 || len(res.Refused) != 0 {
		t.Fatalf("record #0: %+v", res)
	}
	return s, adm
}

// add folds an admin roster record from `by` adding the members; every entry joins.
func add(t *testing.T, s *room.State, seq int64, by uint16, members ...*member) {
	t.Helper()
	body := room.RosterBody{}
	for _, m := range members {
		body.Members = append(body.Members, m.entry(t, t0))
	}
	res := s.Fold(roster(seq, by, body), nil)
	if !res.Folded() || len(res.Joined) != len(members) || len(res.Refused) != 0 {
		t.Fatalf("add at %d by %d: %+v", seq, by, res)
	}
}

// snapshot is the state's membership as a string, to show a dropped record changed nothing.
func snapshot(s *room.State) string {
	var sb strings.Builder
	for _, m := range s.Members() {
		fmt.Fprintf(&sb, "%d=%s/%x;", m.Idx, m.Party, m.Seal().Bytes()[:4])
	}
	fmt.Fprintf(&sb, " admins=%v add=%s", s.Admins(), s.Add())
	return sb.String()
}

func wantDropped(t *testing.T, s *room.State, rec room.Verified, ch room.Channels, want string) {
	t.Helper()
	before := snapshot(s)
	res := s.Fold(rec, ch)
	if res.Folded() {
		t.Fatalf("%s %d from %d folded: %+v", rec.Kind, rec.Seq, rec.Idx, res)
	}
	if !strings.Contains(res.Dropped, want) {
		t.Fatalf("dropped %q, want it to name %q", res.Dropped, want)
	}
	if after := snapshot(s); after != before {
		t.Fatalf("a dropped record changed the state:\n%s\n%s", before, after)
	}
}
