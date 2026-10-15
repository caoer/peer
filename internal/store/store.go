// Package store is the party's session-state store: the records every fleet
// host shares, loaded as a snapshot at version v, mutated in memory through
// the libsignal store interfaces, and written back by Commit under
// compare-and-swap. A Commit that finds another host's version refuses with
// ErrConflict and changes nothing; the caller reloads and redoes its work
// (plan decision 5).
//
// Two record kinds: `keys`, the party keys record (package keys), and one
// `ss.<channel>` per channel — the Signal session, the remote identity, the
// seen message ids, the pull cursor and the pinned peer. A Backend holds
// them: file (JSON + flock) for one machine, pages (a ccc-pages /d/ data
// record) for a fleet, wrapped in Sealed so the page holds ciphertext only.
//
// The orders decision 5 fixes: serve = decrypt → spool → Commit → inbox
// birth from the spool; send = encrypt → outbox → Commit → put → clear. The
// Journal is the spool and the outbox; ReplaySpool and ReplayOutbox run every
// serve round and finish what a crash or a failed step interrupted.
package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/caoer/peer/internal/keys"
)

// Backend holds versioned records by key.
type Backend interface {
	// Load returns a record's bytes and version; an absent key is nil, 0, nil.
	Load(ctx context.Context, key string) ([]byte, int64, error)
	// Store writes data as version expect+1 when the stored version is expect
	// (0 for an absent key); another version refuses with a *ConflictError.
	Store(ctx context.Context, key string, data []byte, expect int64) (int64, error)
}

// Errors a caller can match with errors.Is.
var (
	ErrConflict = errors.New("store: version conflict")
	ErrTooLarge = errors.New("store: record too large")
	ErrCorrupt  = errors.New("store: record does not open")
	ErrNoKeys   = errors.New("store: party keys record absent")
)

// ConflictError is a Store that found another version than expected.
type ConflictError struct {
	Key             string
	Expected, Found int64
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("store: %s: expected version %d, found %d", e.Key, e.Expected, e.Found)
}

// Is makes errors.Is(err, ErrConflict) true.
func (e *ConflictError) Is(target error) bool { return target == ErrConflict }

// KeysKey is the party keys record's key.
const KeysKey = "keys"

// ChannelKey is a channel record's key.
func ChannelKey(channel string) string { return "ss." + channel }

// keyRE is the /d/ key rule: one segment of a-z 0-9 . _ -, at most 128 bytes.
var keyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// ValidKey reports whether key is a record key both backends accept.
func ValidKey(key string) bool { return keyRE.MatchString(key) }

// Store is a party's state store: a backend plus the identity the libsignal
// identity store serves.
type Store struct {
	backend  Backend
	identity *keys.Identity
}

// New opens a store over b for the party whose identity is id.
func New(b Backend, id *keys.Identity) *Store { return &Store{backend: b, identity: id} }
