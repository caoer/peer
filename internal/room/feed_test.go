package room_test

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/caoer/peer/internal/room"
)

// The link stanza key derives from the link key and the room alone; the
// link survives a Commit and a Load; a room without one is no feed.
func TestLinkSealKeyAndState(t *testing.T) {
	key := bytes.Repeat([]byte{9}, room.LinkKeySize)
	k1, err := room.LinkSealKey(key, roomID)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := room.LinkSealKey(key, roomID)
	if !k1.Equal(k2) {
		t.Fatal("the link stanza key is not a function of the link key and room")
	}
	other := "ffffffffffffffffffffffffffffffff"
	if k3, _ := room.LinkSealKey(key, other); k1.Equal(k3) {
		t.Fatal("two rooms derive one link stanza key")
	}
	if _, err := room.LinkSealKey(key[:31], roomID); err == nil {
		t.Fatal("a short link key derived a key")
	}

	ctx := context.Background()
	b := newBackend()
	s, err := room.New(b, roomID, 0, room.AddAdmins, newMember(t, 0).keys)
	if err != nil {
		t.Fatal(err)
	}
	if s.Feed() || s.Link() != nil {
		t.Fatal("a new room is a feed")
	}
	tok := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := s.SetLink(room.Link{Key: key, Token: tok, Idx: 1, Owner: 0, Revoke: []uint16{4}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := room.Load(ctx, b, roomID)
	if err != nil {
		t.Fatal(err)
	}
	l := got.Link()
	if !got.Feed() || l == nil || !bytes.Equal(l.Key, key) || l.Token != tok || l.Idx != 1 || l.Owner != 0 || !slices.Equal(l.Revoke, []uint16{4}) {
		t.Fatalf("link after load: %+v", l)
	}
	l.Key[0] ^= 1
	if got.Link().Key[0] != key[0] {
		t.Fatal("Link hands out the state's own bytes")
	}
}
