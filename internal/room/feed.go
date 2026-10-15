package room

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"slices"
)

// LinkKeySize is a feed link key's length in bytes.
const LinkKeySize = 32

// linkInfo prefixes the room id in the link stanza key's HKDF info.
const linkInfo = "peer feed link v1"

// Link is a feed's link as its owner's state holds it (contract § Sealed
// record, Feed link): the link key, the multi-use read token and its relay
// idx, the roster idx whose room signing key the link names, and the idxs
// of earlier links whose revoke has not landed yet.
type Link struct {
	Key    []byte   `json:"key"`
	Token  string   `json:"token"`
	Idx    uint16   `json:"idx"`
	Owner  uint16   `json:"owner"`
	Revoke []uint16 `json:"revoke,omitempty"`
}

// LinkSealKey is the link stanza's X25519 key: HKDF-SHA256 over the link key
// with info "peer feed link v1" ‖ room. The owner seals to its public half;
// a link holder opens the stanza at idx 65535 with it.
func LinkSealKey(linkKey []byte, room string) (*ecdh.PrivateKey, error) {
	if len(linkKey) != LinkKeySize {
		return nil, fmt.Errorf("room: link key is %d bytes, want %d", len(linkKey), LinkKeySize)
	}
	if !ValidID(room) {
		return nil, fmt.Errorf("room: %q is not a room id", room)
	}
	k, err := hkdf.Key(sha256.New, linkKey, nil, linkInfo+room, 32)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(k)
}

// Feed reports whether the room is a feed this state holds the link of.
func (s *State) Feed() bool { return s.link != nil }

// Link is the feed's link, nil for a room that is not a feed.
func (s *State) Link() *Link {
	if s.link == nil {
		return nil
	}
	l := *s.link
	l.Key, l.Revoke = slices.Clone(l.Key), slices.Clone(l.Revoke)
	return &l
}

// SetLink makes the room a feed with link l, or replaces its link; Commit
// keeps it.
func (s *State) SetLink(l Link) error {
	if len(l.Key) != LinkKeySize {
		return fmt.Errorf("room: link key is %d bytes, want %d", len(l.Key), LinkKeySize)
	}
	l.Key, l.Revoke = slices.Clone(l.Key), slices.Clone(l.Revoke)
	s.link = &l
	return nil
}
