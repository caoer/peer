package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Journal is a crash-safe local list of entries that wait on a Commit, in a
// directory outside the tree: the serve spool (a decrypted message awaiting
// its inbox birth) and the send outbox (a ciphertext awaiting its relay
// put). The sequence is Add → Commit → MarkCommitted → deliver or put →
// Remove; a CAS loser Removes its entry; on start ReplaySpool and
// ReplayOutbox finish what a crash cut.
type Journal struct{ dir string }

// Entry is one journaled message.
type Entry struct {
	// ID is the message id; Channel the channel it belongs to.
	ID      string `json:"id"`
	Channel string `json:"channel"`
	// Seq is the relay seq the envelope arrived under (spool); 0 in the outbox.
	Seq int64 `json:"seq"`
	// Type is the envelope type; Body the plaintext (spool) or ciphertext (outbox).
	Type string `json:"type"`
	Body []byte `json:"body"`
	// Committed is set by MarkCommitted once the Commit this entry waited on landed.
	Committed bool `json:"committed"`

	path string
}

// OpenJournal opens (creating) the journal directory.
func OpenJournal(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Journal{dir: dir}, nil
}

// Add journals e, uncommitted. Entries replay in Add order.
func (j *Journal) Add(e *Entry) error {
	var r [4]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	e.Committed = false
	e.path = filepath.Join(j.dir, fmt.Sprintf("%020d-%s.json", time.Now().UnixNano(), hex.EncodeToString(r[:])))
	return j.write(e)
}

// MarkCommitted records that e's Commit landed.
func (j *Journal) MarkCommitted(e *Entry) error {
	e.Committed = true
	return j.write(e)
}

// Remove deletes e; an entry already gone is not an error.
func (j *Journal) Remove(e *Entry) error {
	if err := os.Remove(e.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Entries lists the journal in Add order.
func (j *Journal) Entries() ([]*Entry, error) {
	names, err := filepath.Glob(filepath.Join(j.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []*Entry
	for _, p := range names {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		e := &Entry{path: p}
		if err := json.Unmarshal(b, e); err != nil {
			return nil, fmt.Errorf("journal %s: %w", p, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// write lands e atomically: a temp file, synced, renamed over e.path.
func (j *Journal) write(e *Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tmp := e.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, e.path)
}

// ReplaySpool runs on start: it delivers the spool entries whose Commit
// landed — marked committed, or whose id the channel record has seen — and
// drops the rest, whose message the cursor will pull again. A delivered
// entry is removed, so a replay delivers each message once; an entry
// another host also committed may be delivered twice — a duplicate at most,
// never a loss (decision 5).
func (s *Store) ReplaySpool(ctx context.Context, j *Journal, deliver func(*Entry) error) error {
	entries, err := j.Entries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Committed {
			ch, err := s.Channel(ctx, e.Channel)
			if err != nil {
				return err
			}
			if !ch.Seen(e.ID) {
				if err := j.Remove(e); err != nil {
					return err
				}
				continue
			}
		}
		if err := deliver(e); err != nil {
			return err
		}
		if err := j.Remove(e); err != nil {
			return err
		}
	}
	return nil
}

// ReplayOutbox runs on start: it puts the outbox entries whose Commit landed
// and drops the uncommitted ones — a ciphertext whose session state was
// never committed must not reach the relay, since the next send reuses its
// counter. A put the relay already holds is refused by the receiver's
// ratchet as a replay; a committed entry never put leaves a counter gap the
// receiver's skipped-key store absorbs.
func ReplayOutbox(j *Journal, put func(*Entry) error) error {
	entries, err := j.Entries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Committed {
			if err := j.Remove(e); err != nil {
				return err
			}
			continue
		}
		if err := put(e); err != nil {
			return err
		}
		if err := j.Remove(e); err != nil {
			return err
		}
	}
	return nil
}
