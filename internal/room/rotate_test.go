package room_test

import (
	"context"
	"crypto/ecdh"
	"errors"
	"testing"
	"time"

	"github.com/caoer/peer/internal/room"
)

// The rotation clock: due once the folded own card is RotateEvery old,
// not while a rotation waits for its roomcard, and from the commit that
// replaced the key once one is retired.
func TestRotationDue(t *testing.T) {
	s, adm := newRoom(t, room.AddAdmins)
	if s.RotationDue(t0.Add(room.RotateEvery-time.Second)) || !s.RotationDue(t0.Add(room.RotateEvery)) {
		t.Fatal("due is not read off the folded own card's issued time")
	}
	if !s.CardCurrent() || s.RotationPending() {
		t.Fatal("a fresh state has its card current and nothing pending")
	}
	k2, _ := room.GenerateSealKey()
	s.Rotate(k2, t0.Add(room.RotateEvery))
	if s.CardCurrent() || !s.RotationPending() || s.RotationDue(t0.Add(3*room.RotateEvery)) {
		t.Fatal("after Rotate the card is stale, a rotation pends and none is due")
	}
	// The write member's own roomcard folds at send, then the put records where it landed.
	res := s.Fold(rec(7, 0, room.KindRoomCard, room.RoomCardBody{RoomCard: cardFor(t, adm, k2, t0.Add(room.RotateEvery))}), nil)
	if !res.Folded() || len(res.Updated) != 1 || !s.CardCurrent() {
		t.Fatalf("own roomcard: %+v", res)
	}
	s.Posted(7)
	if s.RotationPending() || s.RotationDue(t0.Add(2*room.RotateEvery-time.Second)) || !s.RotationDue(t0.Add(2*room.RotateEvery)) {
		t.Fatal("after the post, due counts from the commit that replaced the key")
	}
	if !s.LastRotated().Equal(t0.Add(room.RotateEvery)) {
		t.Fatalf("LastRotated %v", s.LastRotated())
	}
	// Without an own entry nothing is due.
	fresh, _ := room.New(newBackend(), roomID, 3, room.AddAdmins, adm.keys)
	if fresh.RotationDue(t0.Add(48 * time.Hour)) {
		t.Fatal("a state without its own entry rotates")
	}
}

// cardFor is the member's room card announcing seal key k, signed by its identity.
func cardFor(t *testing.T, m *member, k *ecdh.PrivateKey, issued time.Time) []byte {
	t.Helper()
	m.keys.Seal = k
	return m.roomCard(t, issued)
}

// Drop leaves a tombstone: Load answers ErrNoRoom, and a fresh state at the
// same room commits over it; a live record still refuses a fresh state.
func TestDropTombstone(t *testing.T) {
	ctx := context.Background()
	b := newBackend()
	adm := newMember(t, 0)
	s, err := room.New(b, roomID, 0, room.AddAdmins, adm.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	again, _ := room.New(b, roomID, 1, room.AddAdmins, adm.keys)
	if err := again.Commit(ctx); err == nil {
		t.Fatal("a fresh state committed over a live record")
	}
	if err := s.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := room.Load(ctx, b, roomID); !errors.Is(err, room.ErrNoRoom) {
		t.Fatalf("Load after Drop: %v, want ErrNoRoom", err)
	}
	if err := again.Commit(ctx); err != nil {
		t.Fatalf("a fresh state over the tombstone: %v", err)
	}
	if got, err := room.Load(ctx, b, roomID); err != nil || got.Idx() != 1 || got.Version() != again.Version() || again.Version() != 3 {
		t.Fatalf("after the re-seat: idx %d version %d (%v)", got.Idx(), got.Version(), err)
	}
}
