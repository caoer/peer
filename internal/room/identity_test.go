package room_test

import (
	"crypto/ecdh"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/room"
)

// rotatedParty is p after an identity change: the new party card, issued at
// a time, lists the old identity key retired at until and the new key. It
// returns the party under the new identity and the old identity.
func rotatedParty(t *testing.T, p *party, issued, until time.Time) (*party, *keys.Identity) {
	t.Helper()
	id2, err := keys.GenerateIdentity(p.root.Public())
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := keys.GeneratePartyKeys(id2, 2)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := card.Verify(p.card, p.root.Public())
	if err != nil {
		t.Fatal(err)
	}
	c2 := card.New(id2, pk2, agents, relays, issued)
	c2.Party = p.pid
	old := c1.Keys[0]
	u := until
	old.Until = &u
	c2.Keys = append([]card.Key{old}, c2.Keys...)
	signed, err := card.Sign(c2, p.root)
	if err != nil {
		t.Fatal(err)
	}
	return &party{root: p.root, id: id2, card: signed, pid: p.pid}, p.id
}

// rotation is a room under add: members whose idx 2 changed its identity:
// the admin's entry carrying the new party card (the old identity key
// retired at until, the new key) folded at t0+10m, before the retirement.
// old is idx 2 under the old identity — what someone holding the retired
// key can sign as; cur is idx 2 as the fold now holds it; mallory is a
// write member at idx 1.
type rotation struct {
	s       *room.State
	until   time.Time
	old     *member
	cur     *member
	mallory *member
	seal    *ecdh.PublicKey // idx 2's folded seal key after the identity change
}

func rotate(t *testing.T) *rotation {
	t.Helper()
	s, _ := newRoom(t, room.AddMembers)
	mallory := newMember(t, 1)
	old := newMember(t, 2)
	add(t, s, 1, 0, mallory, old)
	until := t0.Add(30 * time.Minute)
	np, _ := rotatedParty(t, old.party, t0.Add(5*time.Minute), until)
	seal, _ := room.GenerateSealKey()
	cur := &member{party: np, idx: 2, keys: &room.OwnKeys{Sign: old.keys.Sign, Seal: seal}}
	v := roster(2, 0, room.RosterBody{Members: []room.Entry{cur.entry(t, t0.Add(5*time.Minute))}})
	v.At = t0.Add(10 * time.Minute)
	if res := s.Fold(v, nil); !slices.Equal(res.Updated, []uint16{2}) || len(res.Refused) != 0 {
		t.Fatalf("identity change did not fold: %+v", res)
	}
	return &rotation{s: s, until: until, old: old, cur: cur, mallory: mallory, seal: s.Member(2).Seal()}
}

// unchanged fails unless idx 2 still holds the keys the identity change folded.
func (r *rotation) unchanged(t *testing.T, what string, res room.Result) {
	t.Helper()
	m := r.s.Member(2)
	if len(res.Updated) != 0 || !m.Seal().Equal(r.seal) || !m.Sign().Equal(r.cur.keys.Sign.Public()) {
		t.Fatalf("%s re-carded idx 2: %+v", what, res)
	}
}

// The release review's probe (sec F1): a write member holding idx 2's
// retired identity key cannot re-card idx 2 — not by a record the relay
// stored after the retirement, whatever header at the writer signed (the
// fold is handed the relay's at), and not by carrying idx 2's older party
// card, which never listed the retirement. Idx 2's own card afterwards
// folds as before.
func TestSubRuleRetiredIdentityKeyRefused(t *testing.T) {
	for _, vector := range []string{"backdated at", "older party card"} {
		t.Run(vector, func(t *testing.T) {
			r := rotate(t)
			evil, _ := room.GenerateKeys()
			forged := &member{party: r.old.party, idx: 2, keys: evil}
			e := forged.entry(t, t0.Add(24*365*time.Hour)) // the old party card, a room card signed by the retired key
			want := "before the folded party card"
			if vector == "backdated at" {
				e.Card = room.PartyCard{Body: r.cur.card.Body, Sig: r.cur.card.Sig} // the new party card, which retires the key
				want = room.ErrSignature.Error()
			}
			res := r.s.Fold(roster(3, 1, room.RosterBody{Members: []room.Entry{e}}), nil) // at: the relay's, after until
			if !res.Folded() || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], want) {
				t.Fatalf("forged entry: %+v, want one refusal naming %q", res, want)
			}
			r.unchanged(t, "the forged entry", res)
			// Idx 2's genuine rotation after it folds.
			nk, _ := room.GenerateSealKey()
			r.cur.keys.Seal = nk
			res = r.s.Fold(rec(4, 2, room.KindRoomCard, room.RoomCardBody{RoomCard: r.cur.roomCard(t, t0.Add(48*time.Hour))}), nil)
			if !slices.Equal(res.Updated, []uint16{2}) || !r.s.Member(2).Seal().Equal(nk.PublicKey()) {
				t.Fatalf("idx 2's own roomcard after the forgery: %+v", res)
			}
		})
	}
}

// Identity-key retirement is read at the record's At — the relay's at of a
// pulled record — and nothing the writer chose: a room card signed by the
// retired key does not verify in a record stored at the retirement, however
// far ahead its issued lies.
func TestSubRuleIdentityRetirementReadAtRecordAt(t *testing.T) {
	r := rotate(t)
	late, _ := room.GenerateSealKey()
	signer := &member{party: r.old.party, idx: 2, keys: &room.OwnKeys{Sign: r.cur.keys.Sign, Seal: late}}
	v := rec(3, 2, room.KindRoomCard, room.RoomCardBody{RoomCard: signer.roomCard(t, t0.Add(24*365*time.Hour))})
	v.At = r.until
	wantDropped(t, r.s, v, nil, room.ErrSignature.Error())
}

// An entry for an idx the fold holds for the same party folds only if its
// party card is issued no earlier than the folded one: an older card, which
// may still list a retired key, is refused and named, from an admin too; the
// same card again with a newer room card is the card update it always was.
func TestSubRuleOlderPartyCardRefused(t *testing.T) {
	r := rotate(t)
	stale, _ := room.GenerateSealKey()
	signer := &member{party: r.old.party, idx: 2, keys: &room.OwnKeys{Sign: r.cur.keys.Sign, Seal: stale}}
	res := r.s.Fold(roster(3, 0, room.RosterBody{Members: []room.Entry{signer.entry(t, t0.Add(2*time.Hour))}}), nil)
	if !res.Folded() || len(res.Refused) != 1 || !strings.Contains(res.Refused[0], "before the folded party card") {
		t.Fatalf("admin's entry with the older party card: %+v", res)
	}
	r.unchanged(t, "the older party card", res)
	fresh, _ := room.GenerateSealKey()
	r.cur.keys.Seal = fresh
	res = r.s.Fold(roster(4, 0, room.RosterBody{Members: []room.Entry{r.cur.entry(t, t0.Add(2*time.Hour))}}), nil)
	if !slices.Equal(res.Updated, []uint16{2}) || len(res.Refused) != 0 || !r.s.Member(2).Seal().Equal(fresh.PublicKey()) {
		t.Fatalf("admin's entry with the folded party card: %+v", res)
	}
}

// A record the relay stored while the key was live folds whenever it is
// pulled — a member offline past the retirement folds it as everyone did —
// because the fold reads the relay's at, never the local clock.
func TestSubRuleOldRecordFoldsLate(t *testing.T) {
	r := rotate(t)
	grace, _ := room.GenerateSealKey()
	signer := &member{party: r.old.party, idx: 2, keys: &room.OwnKeys{Sign: r.cur.keys.Sign, Seal: grace}}
	v := rec(3, 2, room.KindRoomCard, room.RoomCardBody{RoomCard: signer.roomCard(t, t0.Add(20*time.Minute))})
	v.At = t0.Add(20 * time.Minute) // before until; folded now, long after it
	res := r.s.Fold(v, nil)
	if !slices.Equal(res.Updated, []uint16{2}) || !r.s.Member(2).Seal().Equal(grace.PublicKey()) {
		t.Fatalf("a roomcard signed before the retirement, folded after it: %+v", res)
	}
}
