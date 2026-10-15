// Package deliver is the host's end of design §3.5 for a message the
// session verified: the kind table that sends it to the inbox or the
// quarantine, and the record that is the delivery (UCC design v2 § 5
// § Intake). Receiver types do not branch here: every type is served into
// the delivery directory — codex, kimi and grok as generic (plan U8),
// claude-code without UCC — and the UCC seat map and wake are U11, its
// service callback U16.
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
	"strings"
	"time"
)

// KindRoster is a room's membership notice (wire contract v2 § Kinds): one
// record per roster or leave record the fold accepted, born in the inbox of
// every seat the room reaches — the rooms column is its acceptance, so an
// agent's accepts list does not quarantine it.
const KindRoster = "roster"

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
// inbox. A nil accepts takes every kind, an empty one takes none — the
// difference between an agent with no list and an address with no agent
// behind it. A card is not routed: it is the session's own rule.
func Route(kind string, accepts []string) Place {
	if kind == "doc" || kind == "file" {
		return Quarantine
	}
	if kind == KindRoster || accepts == nil {
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
// verified, at — exactly those — and the envelope body; a record that came
// through a room carries group, the room id, as its sixth key (plan v2
// decision 3). From and To are protocol addresses, <party key>/<agent id>,
// nothing local: a petname is the reader's to resolve, and so is a room's
// local name — the record carries the id.
type Record struct {
	From, To, Kind string
	At             time.Time
	Body           []byte
	// Group is the room id; "" for a channel message, which has no group key.
	Group string
}

// The record grammar: what a field can be and still sit on its frontmatter
// line. It is the one border — peer send checks what it builds, serve checks
// what it decrypted, Bytes checks what it writes — so a message that reaches
// the spool can always be born.
var (
	partyRE  = regexp.MustCompile(`^ed25519:[A-Za-z0-9_-]{43}$`)
	agentRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	kindRE   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	vendorRE = regexp.MustCompile(`^vnd\.ed25519:[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{1,64}$`)
	idRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	groupRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// ErrRecord is a record whose own fields cannot be written. No retry fixes
// it, so a replay drops the entry instead of failing (serve's start).
var ErrRecord = errors.New("deliver: record cannot be written")

// ValidID reports whether a message id can name the record's file.
func ValidID(id string) bool { return idRE.MatchString(id) }

// ValidAgent reports whether agent can be an address's agent segment.
func ValidAgent(agent string) bool { return agentRE.MatchString(agent) }

// ValidAddr reports whether s is a protocol address — a party id, with an
// optional agent segment — that a record can carry.
func ValidAddr(s string) bool {
	party, agent, hasAgent := strings.Cut(s, "/")
	if !partyRE.MatchString(party) {
		return false
	}
	return !hasAgent || ValidAgent(agent)
}

// ValidVendorKind reports whether kind is a vendor kind in the one shape a
// record carries: vnd.<party id>.<name> (design §3.5).
func ValidVendorKind(kind string) bool { return vendorRE.MatchString(kind) }

// Bytes is the record as written; a field that cannot sit on its
// frontmatter line refuses with ErrRecord. A kind holding the party id's
// colon is written as a quoted scalar; a group is a room id, 32 lowercase hex.
func (r Record) Bytes() ([]byte, error) {
	if !ValidAddr(r.From) {
		return nil, fmt.Errorf("%w: from %q is not a protocol address", ErrRecord, r.From)
	}
	if !ValidAddr(r.To) {
		return nil, fmt.Errorf("%w: to %q is not a protocol address", ErrRecord, r.To)
	}
	if !kindRE.MatchString(r.Kind) && !ValidVendorKind(r.Kind) {
		return nil, fmt.Errorf("%w: kind %q cannot sit on a frontmatter line", ErrRecord, r.Kind)
	}
	if r.Group != "" && !groupRE.MatchString(r.Group) {
		return nil, fmt.Errorf("%w: group %q is not a room id", ErrRecord, r.Group)
	}
	kind := r.Kind
	if strings.ContainsRune(kind, ':') {
		kind = `"` + kind + `"`
	}
	b := fmt.Appendf(nil, "---\nfrom: %s\nto: %s\nkind: %s\nverified: true\nat: %s\n",
		r.From, r.To, kind, r.At.UTC().Format(time.RFC3339Nano))
	if r.Group != "" {
		b = fmt.Appendf(b, "group: %s\n", r.Group)
	}
	b = append(b, "---\n"...)
	return append(b, r.Body...), nil
}

// Write births the record as <dir>/<place>/<id>.md: written whole beside
// its place, then linked into it, so a reader never sees a partial file and
// a second birth of the same id — a replay, a second host's spool — finds
// the first and keeps it: born is false and the file is untouched.
func Write(dir string, place Place, id string, r Record) (path string, born bool, err error) {
	if !ValidID(id) {
		return "", false, fmt.Errorf("%w: message id %q cannot name a file", ErrRecord, id)
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
