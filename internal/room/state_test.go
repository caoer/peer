package room_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages"
)

func TestStateRoundTrip(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	adm, m1 := newMember(t, 0), newMember(t, 1)
	s, err := room.New(b, roomID, 0, room.AddMembers, adm.keys)
	if err != nil {
		t.Fatal(err)
	}
	if res := s.Fold(roster(0, 0, room.RosterBody{Add: room.AddMembers, Members: []room.Entry{adm.entry(t, t0), m1.entry(t, t0)}}), nil); len(res.Joined) != 2 {
		t.Fatalf("record #0: %+v", res)
	}
	s.SetCursor(7)
	s.ObserveMembership(3)
	s.ObserveMembership(2) // only rises
	s.MarkSeen("a", 5)
	s.MarkSeen("b", 6)
	s.CheckCounter(1, 4)
	if n := s.NextCounter(); n != 1 {
		t.Fatalf("first own ctr %d, want 1", n)
	}
	k2, _ := room.GenerateSealKey()
	s.Rotate(k2, t0)
	s.Posted(9)
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Version() != 1 {
		t.Fatalf("version %d after birth", s.Version())
	}

	got, err := room.Load(ctx, b, roomID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version() != 1 || got.ID() != roomID || got.Idx() != 0 || got.Add() != room.AddMembers ||
		got.Cursor() != 7 || got.Membership() != 3 || !got.Seen("a") || !got.Seen("b") || got.Seen("c") {
		t.Fatalf("scalars: %+v", got)
	}
	if n, ok := got.Counter(1); !ok || n != 4 {
		t.Fatalf("counter(1) = %d %v", n, ok)
	}
	if n := got.NextCounter(); n != 2 {
		t.Fatalf("own ctr after reload %d, want 2", n)
	}
	if !got.SignKey().Equal(s.SignKey()) || !got.SealKey().Equal(k2) {
		t.Fatal("own keys differ after reload")
	}
	retired := got.RetiredSealKeys()
	if len(retired) != 1 || !retired[0].Equal(adm.keys.Seal) {
		t.Fatalf("retired keys after reload: %d", len(retired))
	}
	ms := got.Members()
	if len(ms) != 2 || ms[0].Idx != 0 || ms[1].Idx != 1 || ms[1].Party != m1.pid ||
		!ms[1].Seal().Equal(m1.keys.Seal.PublicKey()) || !ms[1].Sign().Equal(m1.keys.Sign.Public()) || !ms[1].Issued().Equal(t0) {
		t.Fatalf("members after reload: %+v", ms)
	}
	if a := got.Admins(); len(a) != 1 || a[0] != 0 {
		t.Fatalf("admins %v", a)
	}
	// The retired key's seq survived: cursor 7 < 9 holds it, cursor 9 frees it after Retention.
	if n := got.Retire(t0.Add(room.Retention)); n != 0 {
		t.Fatalf("retired %d keys with the cursor below the roomcard", n)
	}
	got.SetCursor(9)
	if n := got.Retire(t0.Add(room.Retention)); n != 1 {
		t.Fatalf("retired %d keys, want 1", n)
	}
}

func TestLoadAbsentAndCorrupt(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	if _, err := room.Load(ctx, b, roomID); !errors.Is(err, room.ErrNoRoom) {
		t.Fatalf("err = %v, want ErrNoRoom", err)
	}
	if _, err := room.Load(ctx, b, "not-a-room"); err == nil {
		t.Fatal("a bad id loaded")
	}
	if _, err := b.Store(ctx, room.Key(roomID), []byte(`{"v":1,"room":"`+roomID+`","add":"admins"}`), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := room.Load(ctx, b, roomID); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestCommitConflict(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	adm := newMember(t, 0)
	s, _ := room.New(b, roomID, 0, room.AddAdmins, adm.keys)
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := room.Load(ctx, b, roomID)
	c, _ := room.Load(ctx, b, roomID)
	a.SetCursor(1)
	if err := a.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	c.SetCursor(2)
	if err := c.Commit(ctx); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	// A second birth over an existing record is a conflict too.
	again, _ := room.New(b, roomID, 0, room.AddAdmins, adm.keys)
	if err := again.Commit(ctx); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rebirth err = %v, want ErrConflict", err)
	}
	got, _ := room.Load(ctx, b, roomID)
	if got.Cursor() != 1 || got.Version() != 2 {
		t.Fatalf("cursor %d version %d", got.Cursor(), got.Version())
	}
}

func TestSeenRing(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	for i := 0; i <= room.MaxSeen; i++ {
		s.MarkSeen(fmt.Sprint(i), int64(i))
	}
	if s.Seen("0") || !s.Seen("1") || !s.Seen(fmt.Sprint(room.MaxSeen)) {
		t.Fatal("the ring did not drop the oldest id alone")
	}
	if room.MaxSeen != 200 {
		t.Fatalf("MaxSeen %d, want 200 (plan decision 2)", room.MaxSeen)
	}
}

func TestCheckCounter(t *testing.T) {
	s, _ := newRoom(t, room.AddAdmins)
	if !s.CheckCounter(4, 17) {
		t.Fatal("a writer's first record is in order whatever it carries")
	}
	if !s.CheckCounter(4, 18) {
		t.Fatal("17 → 18 reported")
	}
	if s.CheckCounter(4, 20) {
		t.Fatal("a gap went unreported")
	}
	if s.CheckCounter(4, 19) {
		t.Fatal("a step back went unreported")
	}
	if n, _ := s.Counter(4); n != 20 {
		t.Fatalf("counter %d after a step back, want the high-water 20", n)
	}
	if !s.CheckCounter(4, 21) {
		t.Fatal("the count continues from the high-water mark")
	}
}

// Sub-rule: a seal key retires two days after the commit that replaced it,
// never while the cursor is below the replacing roomcard's seq (rule 3).
func TestNoRetirementBelowReplacingRoomcard(t *testing.T) {
	s, adm := newRoom(t, room.AddAdmins)
	s.SetCursor(40)
	k2, _ := room.GenerateSealKey()
	s.Rotate(k2, t0)
	if !s.SealKey().Equal(k2) || len(s.RetiredSealKeys()) != 1 || !s.RetiredSealKeys()[0].Equal(adm.keys.Seal) {
		t.Fatal("rotate did not swap the keys")
	}
	late := t0.Add(room.Retention + 24*time.Hour)
	if n := s.Retire(late); n != 0 {
		t.Fatalf("a key whose roomcard was never posted retired (%d)", n)
	}
	s.Posted(50)
	s.SetCursor(49)
	if n := s.Retire(late); n != 0 {
		t.Fatalf("retired with the cursor at 49, below the roomcard at 50 (%d)", n)
	}
	s.SetCursor(50)
	if n := s.Retire(t0.Add(room.Retention - time.Second)); n != 0 {
		t.Fatalf("retired before Retention elapsed (%d)", n)
	}
	if n := s.Retire(t0.Add(room.Retention)); n != 1 || len(s.RetiredSealKeys()) != 0 {
		t.Fatalf("retired %d keys at Retention with the cursor at the roomcard, want 1", n)
	}
	// The card for the current keys names the new seal key.
	if c := s.OwnCard(t0); c.Seal != base64.StdEncoding.EncodeToString(k2.PublicKey().Bytes()) || c.Idx != 0 || c.Room != roomID {
		t.Fatalf("own card %+v", c)
	}
	if room.Retention != 48*time.Hour {
		t.Fatalf("Retention %v, want two days (rule 3)", room.Retention)
	}
}

// SealedSize measures what the pages backend measures: the JSON envelope
// around the base64 of store.Sealed's bytes.
func TestSealedSizeMatchesPagesEnvelope(t *testing.T) {
	ctx := context.Background()
	if room.MaxSealed != pages.MaxEnvelope {
		t.Fatalf("MaxSealed %d, pages.MaxEnvelope %d", room.MaxSealed, pages.MaxEnvelope)
	}
	plain := make([]byte, 1000)
	raw := newBackend()
	sealed := store.Sealed(raw, [32]byte{1})
	if _, err := sealed.Store(ctx, "k", plain, 0); err != nil {
		t.Fatal(err)
	}
	blob := raw.recs["k"].data
	env, _ := json.Marshal(struct {
		Schema string `json:"schema"`
		Data   string `json:"data"`
	}{pages.Schema, base64.StdEncoding.EncodeToString(blob)})
	if got := room.SealedSize(len(plain)); got != len(env) {
		t.Fatalf("SealedSize(%d) = %d, the pages envelope is %d bytes", len(plain), got, len(env))
	}
}
