package room

import (
	"bytes"
	"time"
)

// The daily rotation (rule 8): only the seal key rotates, and it follows the
// send order (rule 9) — generate, Rotate, Commit the state, then post the
// roomcard; a host that loses the Commit discards its key and reads the
// winner's. The state knows when the next rotation is due and whether one
// waits for its roomcard.

// RotateEvery is how old a member's folded room card may be before serve
// rotates the seal key.
const RotateEvery = 24 * time.Hour

// LastRotated is when the seal key last changed: the commit that replaced
// the newest retired key, else the folded own card's issued time; zero while
// the party's own entry is not folded.
func (s *State) LastRotated() time.Time {
	if n := len(s.retired); n > 0 {
		return s.retired[n-1].replaced
	}
	if m := s.Member(s.idx); m != nil {
		return m.issued
	}
	return time.Time{}
}

// RotationPending reports whether a rotation committed and its roomcard has
// not been recorded as posted (Posted) — the next round posts it, nobody
// rotates again.
func (s *State) RotationPending() bool {
	for _, r := range s.retired {
		if r.seq < 0 {
			return true
		}
	}
	return false
}

// RotationDue reports whether serve rotates now: the party's own entry is
// folded, no rotation is pending, and RotateEvery has passed since the key
// last changed.
func (s *State) RotationDue(now time.Time) bool {
	last := s.LastRotated()
	return !last.IsZero() && !s.RotationPending() && !now.Before(last.Add(RotateEvery))
}

// CardCurrent reports whether the folded own entry announces the current
// seal key — false after a rotation until the roomcard that carries it is
// folded (at send for a write member, from an admin's roster entry for a
// read member).
func (s *State) CardCurrent() bool {
	m := s.Member(s.idx)
	return m != nil && bytes.Equal(m.seal.Bytes(), s.seal.PublicKey().Bytes())
}
