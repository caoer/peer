package room

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
)

// The membership record kinds (contract § Kinds). Every other kind in a room
// is a v1 message kind, delivered unchanged; the fold drops anything else.
const (
	KindRoster   = "roster"
	KindLeave    = "leave"
	KindRoomCard = "roomcard"
	KindHandover = "handover"
)

// MembershipKind reports whether kind is one the fold reads.
func MembershipKind(kind string) bool {
	switch kind {
	case KindRoster, KindLeave, KindRoomCard, KindHandover:
		return true
	}
	return false
}

// RosterBody is a roster record's body: entries added or re-carded, idxs
// removed, and on record #0 the add setting.
type RosterBody struct {
	Add     Add      `json:"add,omitempty"`
	Members []Entry  `json:"members,omitempty"`
	Removed []uint16 `json:"removed,omitempty"`
}

// RoomCardBody is a roomcard record's body: the writer's new room card.
type RoomCardBody struct {
	RoomCard []byte `json:"roomcard"`
}

// HandoverBody is a handover record's body: the idx that joins the admin set.
type HandoverBody struct {
	Idx uint16 `json:"idx"`
}

// Verified is a record after the sealed layer opened it — the seam the room
// commands wire from internal/sealed: the fields the fold reads. The relay's
// idx and the header's already agree, the signature verified under the
// roster's key for Idx, the body key hashed to kh.
type Verified struct {
	// Seq is the relay's seq; -1 for an own record folded at send before its put.
	Seq int64
	// Idx is the writer's idx.
	Idx uint16
	// Kind and Body are the message's kind and body JSON.
	Kind string
	Body []byte
	// At is when the relay stored the record (its `at`) — the moment a party
	// card's key retirement is read against, never the header's `at`, which
	// the writer chooses and signs. An own record folded at send takes the
	// local clock.
	At time.Time
}

// Channels answers rule 4 for the fold: the root a confirmed v1 channel pins
// for the peer that holds an identity key, ok false when no confirmed channel
// holds it. nil skips the cross-check.
type Channels func(identity [32]byte) (root ed25519.PublicKey, ok bool)

// Result is what one fold did.
type Result struct {
	// Dropped is why the whole record was dropped — rule 7, a malformed body,
	// a kind outside the table — the line the human is told; "" when it folded.
	Dropped string
	// Refused lists the entries the fold set aside and the human is told of:
	// rule 4, the cap, a card that does not verify, a held or removed idx.
	Refused []string
	// Joined, Updated and Left are the idxs the record added, re-carded and
	// removed; Admitted the idx a handover added to the admin set.
	Joined, Updated, Left, Admitted []uint16
}

// Folded reports whether the record was applied (entries may still be refused).
func (r *Result) Folded() bool { return r.Dropped == "" }

func (r *Result) refuse(format string, args ...any) {
	r.Refused = append(r.Refused, fmt.Sprintf(format, args...))
}

// Fold applies one membership record to the state in memory: rule 7's
// table (who may author which record), rule 4's cross-check of every entry
// against the member's channels, and the contract's sub-rules. The caller
// folds in seq order and commits; an own record folds at send, before its
// put. Anything the table does not allow is dropped and named in the
// Result; an entry that does not hold is refused and named, the rest fold.
func (s *State) Fold(rec Verified, ch Channels) Result {
	switch rec.Kind {
	case KindRoster:
		return s.foldRoster(rec, ch)
	case KindLeave:
		return s.foldLeave(rec)
	case KindRoomCard:
		return s.foldRoomCard(rec)
	case KindHandover:
		return s.foldHandover(rec)
	}
	return Result{Dropped: fmt.Sprintf("record %d from idx %d: kind %q is outside the membership table", rec.Seq, rec.Idx, rec.Kind)}
}

// Seed folds the roster a room-invite carries into a newcomer's fresh state
// — the inviter's word, bounded by rule 4 and each entry's signatures as a
// roster record is, with no author to authorize — and takes the admin set
// the invite names as the starting one: record #0 and the handovers before
// the newcomer's from are below it, and a creator that left is out of it.
func (s *State) Seed(entries []Entry, admins []uint16, ch Channels, at time.Time) Result {
	var res Result
	for _, e := range entries {
		s.applyEntry(e, ch, at, true, &res)
	}
	s.admins = nil
	for _, a := range admins {
		if s.admit(a) {
			res.Admitted = append(res.Admitted, a)
		}
	}
	return res
}

func (s *State) foldRoster(rec Verified, ch Channels) Result {
	var body RosterBody
	if err := json.Unmarshal(rec.Body, &body); err != nil {
		return Result{Dropped: fmt.Sprintf("roster %d from idx %d: malformed body: %v", rec.Seq, rec.Idx, err)}
	}
	if !s.IsAdmin(rec.Idx) {
		// A member's roster under add: members — entries only (contract sub-rule 1).
		if s.add != AddMembers {
			return Result{Dropped: fmt.Sprintf("roster %d from idx %d: outside the admin set, and the room's add setting is %s", rec.Seq, rec.Idx, s.add)}
		}
		if s.Member(rec.Idx) == nil {
			return Result{Dropped: fmt.Sprintf("roster %d from idx %d: not a member", rec.Seq, rec.Idx)}
		}
		if body.Add != "" || len(body.Removed) > 0 {
			return Result{Dropped: fmt.Sprintf("roster %d from member idx %d carries add or removed; a member adds only", rec.Seq, rec.Idx)}
		}
		for _, e := range body.Members {
			if cur := s.Member(e.Idx); cur != nil && cur.Party != e.Party {
				return Result{Dropped: fmt.Sprintf("roster %d from member idx %d: entry idx %d is held by %s", rec.Seq, rec.Idx, e.Idx, cur.Party)}
			}
		}
	}
	if rec.Seq == 0 && body.Add != "" {
		// The add setting is read from record #0 alone and ignored elsewhere.
		if !body.Add.valid() {
			return Result{Dropped: fmt.Sprintf("roster 0 from idx %d: add %q", rec.Idx, body.Add)}
		}
		s.add = body.Add
	}
	var res Result
	admin := s.IsAdmin(rec.Idx)
	for _, e := range body.Members {
		s.applyEntry(e, ch, rec.At, admin, &res)
	}
	for _, idx := range body.Removed {
		if s.remove(idx) {
			res.Left = append(res.Left, idx)
		}
	}
	return res
}

func (s *State) foldLeave(rec Verified) Result {
	// leave is from the leaving idx alone: the writer's.
	if !s.remove(rec.Idx) {
		return Result{Dropped: fmt.Sprintf("leave %d from idx %d: not a member", rec.Seq, rec.Idx)}
	}
	return Result{Left: []uint16{rec.Idx}}
}

func (s *State) foldRoomCard(rec Verified) Result {
	var body RoomCardBody
	if err := json.Unmarshal(rec.Body, &body); err != nil {
		return Result{Dropped: fmt.Sprintf("roomcard %d from idx %d: malformed body: %v", rec.Seq, rec.Idx, err)}
	}
	cur := s.Member(rec.Idx)
	if cur == nil {
		return Result{Dropped: fmt.Sprintf("roomcard %d from idx %d: not a member", rec.Seq, rec.Idx)}
	}
	pc, err := partyCard(cur)
	if err != nil {
		return Result{Dropped: fmt.Sprintf("roomcard %d from idx %d: folded party card: %v", rec.Seq, rec.Idx, err)}
	}
	rc, err := Verify(body.RoomCard, pc, rec.At)
	if err != nil {
		return Result{Dropped: fmt.Sprintf("roomcard %d from idx %d: %v", rec.Seq, rec.Idx, err)}
	}
	if rc.Idx != rec.Idx || rc.Room != s.id {
		return Result{Dropped: fmt.Sprintf("roomcard %d from idx %d: card for idx %d of room %s", rec.Seq, rec.Idx, rc.Idx, rc.Room)}
	}
	var res Result
	if !rc.Issued.After(cur.issued) {
		return res // a card no newer than the folded one is ignored (a replay never downgrades)
	}
	old := *cur
	*cur = *newMember(Entry{Idx: cur.Idx, Party: cur.Party, Card: cur.Card, RoomCard: body.RoomCard}, rc)
	if s.overCap() {
		*cur = old
		res.refuse("roomcard %d from idx %d: the room record would pass %d bytes sealed; not folded", rec.Seq, rec.Idx, MaxSealed)
		return res
	}
	res.Updated = []uint16{rec.Idx}
	return res
}

func (s *State) foldHandover(rec Verified) Result {
	if !s.IsAdmin(rec.Idx) {
		return Result{Dropped: fmt.Sprintf("handover %d from idx %d: outside the admin set", rec.Seq, rec.Idx)}
	}
	var body HandoverBody
	if err := json.Unmarshal(rec.Body, &body); err != nil {
		return Result{Dropped: fmt.Sprintf("handover %d from idx %d: malformed body: %v", rec.Seq, rec.Idx, err)}
	}
	// The idx names a current member; the relay's admin route holds it to a write idx.
	if s.Member(body.Idx) == nil {
		return Result{Dropped: fmt.Sprintf("handover %d from idx %d: idx %d is not a member", rec.Seq, rec.Idx, body.Idx)}
	}
	var res Result
	if s.admit(body.Idx) {
		res.Admitted = []uint16{body.Idx}
	}
	return res
}

// applyEntry folds one roster entry: both cards verify, the idx is free or
// the party's own, the party card is issued no earlier than the folded one
// (an older card may still list a retired identity key), the cross-check
// holds (rule 4), the record stays under the cap. An entry whose room card
// is no newer than the folded card at its idx is ignored. An
// admin's entry (and the invite's, which Seed folds) may take a removed or
// left idx — a newcomer's state holds no removed set, so the fold agrees
// everywhere; a non-admin's entry there is refused (sub-rule 1).
func (s *State) applyEntry(e Entry, ch Channels, at time.Time, admin bool, res *Result) {
	where := fmt.Sprintf("entry idx %d (%s)", e.Idx, e.Party)
	if !admin && s.Removed(e.Idx) {
		res.refuse("%s: the idx was removed", where)
		return
	}
	root, err := keys.ParsePartyID(e.Party)
	if err != nil {
		res.refuse("%s: %v", where, err)
		return
	}
	pc, err := card.Verify(&card.Signed{Body: e.Card.Body, Sig: e.Card.Sig}, root)
	if err != nil {
		res.refuse("%s: party card: %v", where, err)
		return
	}
	cur := s.Member(e.Idx)
	if cur != nil && cur.Party != e.Party {
		res.refuse("%s: the idx is held by %s", where, cur.Party)
		return
	}
	if cur != nil {
		folded, err := partyCard(cur)
		if err != nil {
			res.refuse("%s: folded party card: %v", where, err)
			return
		}
		if pc.Issued.Before(folded.Issued) {
			res.refuse("%s: party card issued %s, before the folded party card's %s", where, pc.Issued.UTC().Format(time.RFC3339), folded.Issued.UTC().Format(time.RFC3339))
			return
		}
	}
	rc, err := Verify(e.RoomCard, pc, at)
	if err != nil {
		res.refuse("%s: %v", where, err)
		return
	}
	if rc.Room != s.id || rc.Idx != e.Idx {
		res.refuse("%s: room card for idx %d of room %s", where, rc.Idx, rc.Room)
		return
	}
	if ch != nil {
		for i := range pc.Keys {
			raw, err := keys.ParseCurve(pc.Keys[i].Identity)
			if err != nil {
				continue // card.Verify checked every key
			}
			if known, ok := ch(raw); ok && !known.Equal(root) {
				res.refuse("%s: its card carries the identity key of your channel with %s (rule 4)", where, keys.PartyID(known))
				return
			}
		}
	}
	m := newMember(e, rc)
	if cur != nil {
		if !rc.Issued.After(cur.issued) {
			return
		}
		old := *cur
		*cur = *m
		if s.overCap() {
			*cur = old
			res.refuse("%s: the room record would pass %d bytes sealed; the card update is not folded", where, MaxSealed)
			return
		}
		res.Updated = append(res.Updated, e.Idx)
		return
	}
	i, _ := slices.BinarySearchFunc(s.members, e.Idx, func(m *Member, idx uint16) int { return int(m.Idx) - int(idx) })
	s.members = slices.Insert(s.members, i, m)
	if s.overCap() {
		s.members = slices.Delete(s.members, i, i+1)
		res.refuse("%s: the room record would pass %d bytes sealed; the member is not folded", where, MaxSealed)
		return
	}
	// An admin's re-add makes the idx a member again, as a newcomer folds it.
	s.removed = slices.DeleteFunc(s.removed, func(r uint16) bool { return r == e.Idx })
	res.Joined = append(res.Joined, e.Idx)
}

func (s *State) overCap() bool {
	n, err := s.Size()
	return err != nil || n > MaxSealed
}

// partyCard parses a folded member's party card; the fold verified it.
func partyCard(m *Member) (*card.Card, error) {
	var pc card.Card
	if err := json.Unmarshal(m.Card.Body, &pc); err != nil {
		return nil, err
	}
	return &pc, nil
}
