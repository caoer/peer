package room

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/caoer/peer/internal/store"
)

const recordVersion = 1

// Key is the room record's key in the store.
func Key(id string) string { return "rm." + id }

// MaxSeen is how many message ids a room record remembers (plan decision 2);
// the oldest go first. The relay's seq and the writer's ctr already order a
// writer; the ring is the fleet's dedupe by message id.
const MaxSeen = 200

// Retention is how long a replaced seal key is kept after the commit that
// replaced it: one rotation plus a margin (rule 3).
const Retention = 48 * time.Hour

// MaxSealed is the fleet store's cap on a record: the UTF-8 bytes of the
// pages envelope {"schema","data"} with the sealed record in standard base64
// (internal/store/pages MaxEnvelope). SealedSize measures a record against it.
const MaxSealed = 256 * 1024

const (
	// sealOverhead is store.Sealed's nonce and tag.
	sealOverhead = 12 + 16
	// envelopeOverhead is the pages envelope around the base64 data.
	envelopeOverhead = len(`{"schema":"peer-store@1","data":""}`)
)

// SealedSize is the envelope size of a record of n plaintext bytes on the fleet store.
func SealedSize(n int) int { return envelopeOverhead + base64.StdEncoding.EncodedLen(n+sealOverhead) }

// Add is the room's add setting, fixed at creation (rule 5): who may post a
// roster add.
type Add string

const (
	// AddAdmins: the admin set adds.
	AddAdmins Add = "admins"
	// AddMembers: any write member adds (entries only).
	AddMembers Add = "members"
)

func (a Add) valid() bool { return a == AddAdmins || a == AddMembers }

// Errors a caller can match.
var (
	ErrNoRoom = errors.New("room: no state record")
	ErrCap    = errors.New("room: the record would pass the sealed cap")
)

// Entry is one roster entry as it travels in a roster record's `members`
// and a room-invite's `roster`, and as the state keeps it: the member's idx,
// its party id, its root-signed party card and its identity-signed room card
// (Card.Signed's bytes, standard base64 in JSON).
type Entry struct {
	Idx      uint16    `json:"idx"`
	Party    string    `json:"party"`
	Card     PartyCard `json:"card"`
	RoomCard []byte    `json:"roomcard"`
}

// PartyCard is a party card as it travels inside an entry: the exact bytes
// and the root's detached signature (internal/card Signed).
type PartyCard struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
}

// Member is one folded roster entry with its room card opened.
type Member struct {
	Entry
	seal   *ecdh.PublicKey
	sign   ed25519.PublicKey
	issued time.Time
}

// Seal is the member's current X25519 seal public key — the stanza's recipient key.
func (m *Member) Seal() *ecdh.PublicKey { return m.seal }

// Sign is the member's Ed25519 signing public key — what its records verify under.
func (m *Member) Sign() ed25519.PublicKey { return m.sign }

// Issued is when the member's folded room card was issued.
func (m *Member) Issued() time.Time { return m.issued }

func newMember(e Entry, rc *Card) *Member {
	seal, _ := rc.SealKey() // parse checked both keys
	sign, _ := rc.SignKey()
	return &Member{Entry: e, seal: seal, sign: sign, issued: rc.Issued}
}

type stateRecord struct {
	V    int    `json:"v"`
	Room string `json:"room"`
	// Gone marks a tombstone (Drop): the party left or was removed, or the
	// room closed. Load answers ErrNoRoom for it, and a fresh state's Commit
	// takes its version.
	Gone       bool              `json:"gone,omitempty"`
	Idx        uint16            `json:"idx"`
	Add        Add               `json:"add"`
	Membership int64             `json:"membership"`
	Cursor     int64             `json:"cursor"`
	Members    []Entry           `json:"members"`
	Admins     []uint16          `json:"admins"`
	Removed    []uint16          `json:"removed,omitempty"`
	Keys       ownKeyRecord      `json:"keys"`
	Seen       []seenID          `json:"seen"`
	Counters   map[uint16]uint64 `json:"counters,omitempty"`
	Ctr        uint64            `json:"ctr"`
	Dropped    int64             `json:"dropped,omitempty"`
	Reported   int64             `json:"reported,omitempty"`
	// Link is a feed's link, on its owner's state alone.
	Link *Link `json:"link,omitempty"`
}

type ownKeyRecord struct {
	// Sign is the Ed25519 seed; Seal the X25519 private key.
	Sign    []byte       `json:"sign"`
	Seal    []byte       `json:"seal"`
	Retired []retiredKey `json:"retired,omitempty"`
}

type retiredKey struct {
	Seal     []byte    `json:"seal"`
	Replaced time.Time `json:"replaced"`
	// Seq is the relay seq of the roomcard that announced the replacing key, -1 until it is posted.
	Seq int64 `json:"seq"`
}

type retired struct {
	key      *ecdh.PrivateKey
	replaced time.Time
	seq      int64
}

type seenID struct {
	ID  string `json:"id"`
	Seq int64  `json:"seq"`
}

// State is a room's record `rm.<id>`, loaded at a version: the folded
// roster and admin set, the member's own keys, the pull cursor, the seen
// ids, the writers' counters, the relay's membership version and the add
// setting. Mutations stay in memory until Commit; a Commit that finds
// another host's version refuses with store.ErrConflict and changes
// nothing — reload and redo the work (plan decision 5).
type State struct {
	b       store.Backend
	version int64

	id         string
	idx        uint16
	add        Add
	membership int64
	cursor     int64
	members    []*Member // sorted by idx
	admins     []uint16
	removed    []uint16
	sign       ed25519.PrivateKey
	seal       *ecdh.PrivateKey
	retired    []retired
	seen       []seenID
	counters   map[uint16]uint64
	ctr        uint64
	dropped    int64
	reported   int64
	link       *Link
}

// New is a fresh state at version 0 for the member at idx of room id with its
// own keys; the admin set is idx 0. Commit births the record, and refuses
// with store.ErrConflict when one exists.
func New(b store.Backend, id string, idx uint16, add Add, own *OwnKeys) (*State, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("room: %q is not a room id", id)
	}
	if !add.valid() {
		return nil, fmt.Errorf("room: add %q, want %q or %q", add, AddAdmins, AddMembers)
	}
	return &State{
		b: b, id: id, idx: idx, add: add, cursor: -1,
		admins: []uint16{0}, sign: own.Sign, seal: own.Seal,
		counters: map[uint16]uint64{},
	}, nil
}

// Load reads the room's record; ErrNoRoom when absent.
func Load(ctx context.Context, b store.Backend, id string) (*State, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("room: %q is not a room id", id)
	}
	key := Key(id)
	data, v, err := b.Load(ctx, key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoRoom, id)
	}
	var rec stateRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", store.ErrCorrupt, key, err)
	}
	if rec.V != recordVersion {
		return nil, fmt.Errorf("%w: %s: record version %d, want %d", store.ErrCorrupt, key, rec.V, recordVersion)
	}
	if rec.Gone {
		return nil, fmt.Errorf("%w: %s (left)", ErrNoRoom, id)
	}
	if rec.Room != id || !rec.Add.valid() {
		return nil, fmt.Errorf("%w: %s: room %q add %q", store.ErrCorrupt, key, rec.Room, rec.Add)
	}
	s := &State{
		b: b, version: v, id: id, idx: rec.Idx, add: rec.Add,
		membership: rec.Membership, cursor: rec.Cursor,
		admins: rec.Admins, removed: rec.Removed, seen: rec.Seen,
		counters: rec.Counters, ctr: rec.Ctr,
		dropped: rec.Dropped, reported: rec.Reported,
	}
	if rec.Link != nil {
		if err := s.SetLink(*rec.Link); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", store.ErrCorrupt, key, err)
		}
	}
	if s.counters == nil {
		s.counters = map[uint16]uint64{}
	}
	if len(rec.Keys.Sign) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: %s: signing key seed %d bytes", store.ErrCorrupt, key, len(rec.Keys.Sign))
	}
	s.sign = ed25519.NewKeyFromSeed(rec.Keys.Sign)
	if s.seal, err = ecdh.X25519().NewPrivateKey(rec.Keys.Seal); err != nil {
		return nil, fmt.Errorf("%w: %s: seal key: %v", store.ErrCorrupt, key, err)
	}
	for _, r := range rec.Keys.Retired {
		k, err := ecdh.X25519().NewPrivateKey(r.Seal)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: retired seal key: %v", store.ErrCorrupt, key, err)
		}
		s.retired = append(s.retired, retired{key: k, replaced: r.Replaced, seq: r.Seq})
	}
	for _, e := range rec.Members {
		if len(e.RoomCard) <= SigSize {
			return nil, fmt.Errorf("%w: %s: member %d: room card %d bytes", store.ErrCorrupt, key, e.Idx, len(e.RoomCard))
		}
		rc, err := parse(e.RoomCard[:len(e.RoomCard)-SigSize])
		if err != nil {
			return nil, fmt.Errorf("%w: %s: member %d: %v", store.ErrCorrupt, key, e.Idx, err)
		}
		s.members = append(s.members, newMember(e, rc))
	}
	slices.SortFunc(s.members, func(a, b *Member) int { return int(a.Idx) - int(b.Idx) })
	return s, nil
}

func (s *State) marshal() ([]byte, error) {
	rec := stateRecord{
		V: recordVersion, Room: s.id, Idx: s.idx, Add: s.add,
		Membership: s.membership, Cursor: s.cursor,
		Members: make([]Entry, 0, len(s.members)),
		Admins:  s.admins, Removed: s.removed,
		Keys: ownKeyRecord{Sign: s.sign.Seed(), Seal: s.seal.Bytes()},
		Seen: s.seen, Counters: s.counters, Ctr: s.ctr,
		Dropped: s.dropped, Reported: s.reported, Link: s.link,
	}
	for _, m := range s.members {
		rec.Members = append(rec.Members, m.Entry)
	}
	for _, r := range s.retired {
		rec.Keys.Retired = append(rec.Keys.Retired, retiredKey{Seal: r.key.Bytes(), Replaced: r.replaced, Seq: r.seq})
	}
	return json.Marshal(rec)
}

// Version is the loaded version; Commit raises it.
func (s *State) Version() int64 { return s.version }

// Size is the record's sealed envelope size as it stands, against MaxSealed.
func (s *State) Size() (int, error) {
	data, err := s.marshal()
	if err != nil {
		return 0, err
	}
	return SealedSize(len(data)), nil
}

// Commit writes the record as version Version()+1; a record past MaxSealed
// refuses with ErrCap before the store sees it, another host's version with
// store.ErrConflict.
func (s *State) Commit(ctx context.Context) error {
	data, err := s.marshal()
	if err != nil {
		return err
	}
	if n := SealedSize(len(data)); n > MaxSealed {
		return fmt.Errorf("%w: %d bytes, cap %d", ErrCap, n, MaxSealed)
	}
	v, err := s.b.Store(ctx, Key(s.id), data, s.version)
	if errors.Is(err, store.ErrConflict) && s.version == 0 {
		// A fresh state over a tombstone: the party is seated again after
		// it left, and the record is its own to take.
		if tv, gone := tombstone(ctx, s.b, s.id); gone {
			v, err = s.b.Store(ctx, Key(s.id), data, tv)
		}
	}
	if err != nil {
		return err
	}
	s.version = v
	return nil
}

// Drop replaces the record with a tombstone at the next version: the party
// left or was removed, or the room closed, and its keys and roster are not
// kept. Load answers ErrNoRoom from then on; a fresh state's Commit takes the
// tombstone's place. Another host's version refuses with store.ErrConflict.
func (s *State) Drop(ctx context.Context) error {
	data, err := json.Marshal(stateRecord{V: recordVersion, Room: s.id, Gone: true})
	if err != nil {
		return err
	}
	v, err := s.b.Store(ctx, Key(s.id), data, s.version)
	if err != nil {
		return err
	}
	s.version = v
	return nil
}

// tombstone reports whether the room's record is a tombstone, and its version.
func tombstone(ctx context.Context, b store.Backend, id string) (int64, bool) {
	data, v, err := b.Load(ctx, Key(id))
	if err != nil || data == nil {
		return 0, false
	}
	var rec stateRecord
	if json.Unmarshal(data, &rec) != nil || !rec.Gone {
		return 0, false
	}
	return v, true
}

// ID is the room id.
func (s *State) ID() string { return s.id }

// Idx is the member's own idx.
func (s *State) Idx() uint16 { return s.idx }

// Add is the room's add setting.
func (s *State) Add() Add { return s.add }

// Membership is the relay's membership version as last observed — what a put carries.
func (s *State) Membership() int64 { return s.membership }

// ObserveMembership records the membership version a relay answer carried;
// the version only rises.
func (s *State) ObserveMembership(v int64) { s.membership = max(s.membership, v) }

// Cursor is the relay seq of the last record pulled, -1 before the first.
func (s *State) Cursor() int64 { return s.cursor }

// SetCursor records the relay seq of the last record pulled.
func (s *State) SetCursor(seq int64) { s.cursor = seq }

// Seen reports whether a message id was marked seen.
func (s *State) Seen(id string) bool {
	return slices.ContainsFunc(s.seen, func(x seenID) bool { return x.ID == id })
}

// MarkSeen records a message id with the relay seq it arrived under; the
// ring keeps the last MaxSeen.
func (s *State) MarkSeen(id string, seq int64) {
	if s.Seen(id) {
		return
	}
	s.seen = append(s.seen, seenID{ID: id, Seq: seq})
	if n := len(s.seen) - MaxSeen; n > 0 {
		s.seen = append([]seenID(nil), s.seen[n:]...)
	}
}

// Counter is the highest ctr seen from a writer, false before its first record.
func (s *State) Counter(idx uint16) (uint64, bool) {
	n, ok := s.counters[idx]
	return n, ok
}

// CheckCounter records a writer's ctr and reports whether it continued the
// writer's count (rule 10): true in order, false on a gap or a step back —
// reported by the caller, reading continues. A writer's first record is in
// order whatever it carries: a newcomer's floor hides what came before.
func (s *State) CheckCounter(idx uint16, ctr uint64) bool {
	last, ok := s.counters[idx]
	s.counters[idx] = max(last, ctr)
	return !ok || ctr == last+1
}

// NextCounter is the ctr the member's next record carries: its own count of
// records put in this room, +1 each.
func (s *State) NextCounter() uint64 {
	s.ctr++
	return s.ctr
}

// Dropped is how many records and roster entries the fold set aside (rules
// 7 and 4): a record dropped whole, an entry refused.
func (s *State) Dropped() int64 { return s.dropped }

// NoteDropped counts n more records or entries the fold set aside.
func (s *State) NoteDropped(n int) { s.dropped += int64(n) }

// Reported is how many records the receiver reported: a counter gap or step
// back, a stanza that did not open, a record that did not verify.
func (s *State) Reported() int64 { return s.reported }

// NoteReported counts one more reported record.
func (s *State) NoteReported() { s.reported++ }

// Members is the folded roster in idx order.
func (s *State) Members() []*Member { return slices.Clone(s.members) }

// Member is the folded entry at idx, nil when none.
func (s *State) Member(idx uint16) *Member {
	for _, m := range s.members {
		if m.Idx == idx {
			return m
		}
	}
	return nil
}

// Admins is the admin set: idx 0 plus folded handovers, less whoever left or was removed.
func (s *State) Admins() []uint16 { return slices.Clone(s.admins) }

// IsAdmin reports whether idx is in the admin set.
func (s *State) IsAdmin(idx uint16) bool { return slices.Contains(s.admins, idx) }

// Removed reports whether idx was removed or left and no admin has re-added it.
func (s *State) Removed(idx uint16) bool { return slices.Contains(s.removed, idx) }

func (s *State) admit(idx uint16) bool {
	if s.IsAdmin(idx) {
		return false
	}
	s.admins = append(s.admins, idx)
	return true
}

// remove drops idx from the roster and the admin set and remembers it; false when it was no member.
func (s *State) remove(idx uint16) bool {
	i := slices.IndexFunc(s.members, func(m *Member) bool { return m.Idx == idx })
	if i < 0 {
		return false
	}
	s.members = slices.Delete(s.members, i, i+1)
	s.admins = slices.DeleteFunc(s.admins, func(a uint16) bool { return a == idx })
	if !s.Removed(idx) {
		s.removed = append(s.removed, idx)
	}
	return true
}

// SignKey is the member's room signing key.
func (s *State) SignKey() ed25519.PrivateKey { return s.sign }

// SealKey is the member's current seal key: what the next room card announces.
func (s *State) SealKey() *ecdh.PrivateKey { return s.seal }

// RetiredSealKeys lists the replaced seal keys still held, newest first —
// tried after the current one on a record's own stanza.
func (s *State) RetiredSealKeys() []*ecdh.PrivateKey {
	out := make([]*ecdh.PrivateKey, 0, len(s.retired))
	for i := len(s.retired) - 1; i >= 0; i-- {
		out = append(out, s.retired[i].key)
	}
	return out
}

// Rotate makes k the current seal key and retires the one it replaces,
// stamped with the time of the commit that follows (rule 9: commit, then
// post the roomcard; Posted records where it landed).
func (s *State) Rotate(k *ecdh.PrivateKey, now time.Time) {
	s.retired = append(s.retired, retired{key: s.seal, replaced: now.UTC(), seq: -1})
	s.seal = k
}

// Posted records the relay seq the roomcard announcing the current seal key
// landed at, on every retired key still waiting for it.
func (s *State) Posted(seq int64) {
	for i := range s.retired {
		if s.retired[i].seq < 0 {
			s.retired[i].seq = seq
		}
	}
}

// Retire drops the retired seal keys whose time is up: Retention past the
// commit that replaced them, and never while the cursor is below the seq of
// the roomcard that replaced them (rule 3) — a key whose roomcard was never
// Posted is kept. It returns how many it dropped.
func (s *State) Retire(now time.Time) int {
	before := len(s.retired)
	s.retired = slices.DeleteFunc(s.retired, func(r retired) bool {
		return r.seq >= 0 && s.cursor >= r.seq && !now.Before(r.replaced.Add(Retention))
	})
	return before - len(s.retired)
}

// OwnCard is the unsigned room card for the member's current keys; the
// caller signs it with the party's identity key (Card.Signed).
func (s *State) OwnCard(issued time.Time) *Card {
	return NewCard(s.id, s.idx, s.seal.PublicKey(), s.sign.Public().(ed25519.PublicKey), issued)
}
