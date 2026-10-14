// Package deliver is the host's end of design §3.5 for a message the
// session verified: the kind table that sends it to the inbox or the
// quarantine, and the record that is the delivery (UCC design v2 § 5
// § Intake). Receiver types do not branch here: every type is served into
// the delivery directory — codex, kimi and grok as generic (plan U8),
// claude-code without UCC, human and service until U16 — and the UCC seat
// map and wake are U11.
package deliver

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Place is where a record is born under the delivery directory.
type Place string

const (
	Inbox      Place = "inbox"
	Quarantine Place = "quarantine"
)

// Route is the kind table. doc and file are quarantined whatever the agent
// accepts — a peer's method never applies on its own (design §10 #8); a
// kind outside the agent's accepts list is quarantined — the border for what
// arrives despite the card (UCC design v2 § 5); everything else is the
// inbox. A nil accepts takes every kind. A card is not routed: it is the
// session's own rule.
func Route(kind string, accepts []string) Place {
	if kind == "doc" || kind == "file" {
		return Quarantine
	}
	if accepts == nil {
		return Inbox
	}
	for _, k := range accepts {
		if k == kind {
			return Inbox
		}
	}
	return Quarantine
}

// Record is an inbox or quarantine record: frontmatter from, to, kind,
// verified, at — exactly those — and the envelope body. From and To are
// protocol addresses, <party key>/<agent id>, nothing local: a petname is
// the reader's to resolve.
type Record struct {
	From, To, Kind string
	At             time.Time
	Body           []byte
}

var (
	addrRE = regexp.MustCompile(`^ed25519:[A-Za-z0-9_-]{43}(/[!-.0-~]{1,64})?$`)
	kindRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	idRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// ValidID reports whether a message id can name the record's file.
func ValidID(id string) bool { return idRE.MatchString(id) }

// Bytes is the record as written; a field that cannot sit on its
// frontmatter line refuses.
func (r Record) Bytes() ([]byte, error) {
	if !addrRE.MatchString(r.From) {
		return nil, fmt.Errorf("deliver: from %q is not a protocol address", r.From)
	}
	if !addrRE.MatchString(r.To) {
		return nil, fmt.Errorf("deliver: to %q is not a protocol address", r.To)
	}
	if !kindRE.MatchString(r.Kind) {
		return nil, fmt.Errorf("deliver: kind %q cannot sit on a frontmatter line", r.Kind)
	}
	b := fmt.Appendf(nil, "---\nfrom: %s\nto: %s\nkind: %s\nverified: true\nat: %s\n---\n",
		r.From, r.To, r.Kind, r.At.UTC().Format(time.RFC3339Nano))
	return append(b, r.Body...), nil
}

// Write births the record as <dir>/<place>/<id>.md: written whole beside
// its place, then linked into it, so a reader never sees a partial file and
// a second birth of the same id — a replay, a second host's spool — finds
// the first and keeps it: born is false and the file is untouched.
func Write(dir string, place Place, id string, r Record) (path string, born bool, err error) {
	if !ValidID(id) {
		return "", false, fmt.Errorf("deliver: message id %q cannot name a file", id)
	}
	data, err := r.Bytes()
	if err != nil {
		return "", false, err
	}
	pdir := filepath.Join(dir, string(place))
	if err := os.MkdirAll(pdir, 0o700); err != nil {
		return "", false, err
	}
	path = filepath.Join(pdir, id+".md")
	var rnd [4]byte
	rand.Read(rnd[:])
	tmp := filepath.Join(pdir, "."+id+"."+hex.EncodeToString(rnd[:])+".tmp")
	if err := writeSynced(tmp, data); err != nil {
		return "", false, err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return path, false, nil
		}
		return "", false, err
	}
	return path, true, nil
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
