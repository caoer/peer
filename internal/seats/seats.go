// Package seats reads the party's seat map — peers/seats.md on the fleet's
// sessions root (UCC design v2 § 5 § Address): one row per label, the agent
// id a sender addresses, naming where a message to it lands and the kinds
// the row accepts. UCC writes the map; peer reads it for its card and at the
// border of every delivery.
//
// The grammar (K0, proposed by plan unit U11): the record's body holds one
// markdown table whose header names the columns label, to and accepts, in
// any order; other columns and the frontmatter are UCC's and are ignored.
//
//	| label  | to                                                                         | accepts                       |
//	|--------|----------------------------------------------------------------------------|-------------------------------|
//	| leader | [[projects/demo/rosters/leader-peer-v1]]  | text task question answer ack |
//	| zt     | human [[projects/demo/rosters/advisor-demo]] | text question answer |
//	| hook   | service https://example.net/peer/hook                                      | text                          |
//
// The columns:
//
//   - label: an agent id, [A-Za-z0-9._-]{1,64}, unique in the map.
//   - to: a seat — [[<session>/rosters/<role>-<slug>]], the roster record's
//     path under the root, so the seat's session is the part before
//     /rosters/ — or human [[<session>/rosters/<role>-<slug>]], a person,
//     whose messages are born in the session of the seat that relays to
//     them (UCC's amendment; a bare human names no session and is refused),
//     or service <url> with an https URL.
//   - accepts: one or more of the eight kinds — text task question answer doc
//     file card ack — separated by spaces.
//
// A row outside the grammar makes the whole map invalid: nothing is
// delivered by a map that cannot be read, and nothing is consumed.
package seats

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/session"
)

// Kind is what a row's to column names.
type Kind int

const (
	Seat    Kind = iota + 1 // [[<session>/rosters/<role>-<slug>]]
	Human                   // human [[<session>/rosters/<role>-<slug>]]
	Service                 // service <url>
)

func (k Kind) String() string {
	switch k {
	case Seat:
		return "seat"
	case Human:
		return "human"
	case Service:
		return "service"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// Row is one label of the map.
type Row struct {
	Label string
	Kind  Kind
	// Seat rows, and human rows for the seat that relays to the person:
	// Session is the session's path under the root, Seat the roster
	// record's path under it (the wikilink's text).
	Session, Seat string
	// Service rows: the callback URL.
	URL string
	// Accepts is the row's subset of the eight kinds, in the row's order.
	Accepts []string
}

// Map is a parsed seat map.
type Map struct {
	rows  map[string]Row
	order []string
}

// Kinds is the vocabulary accepts draws from.
var Kinds = []string{
	session.KindText, session.KindTask, session.KindQuestion, session.KindAnswer,
	session.KindDoc, session.KindFile, session.KindCard, session.KindAck,
}

// ErrMap is a map outside the grammar.
var ErrMap = errors.New("seats: the map cannot be read")

var (
	seatRE      = regexp.MustCompile(`^([A-Za-z0-9=._-]+(?:/[A-Za-z0-9=._-]+)*)/rosters/([A-Za-z0-9._-]+)$`)
	separatorRE = regexp.MustCompile(`^:?-+:?$`)
)

// Load reads and parses the map at path.
func Load(path string) (*Map, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seat map %s: %w", path, err)
	}
	m, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("seat map %s: %w", path, err)
	}
	return m, nil
}

// Parse reads the map's bytes.
func Parse(b []byte) (*Map, error) {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMap, err)
	}
	// The table: the first line opening with a pipe is the header, the next
	// the separator, and every pipe line after it a row, until the first
	// line that is not one.
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "|") {
			start = i
			break
		}
	}
	if start < 0 || start+1 >= len(lines) {
		return nil, fmt.Errorf("%w: no table with a header row", ErrMap)
	}
	header := cells(lines[start])
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(h)] = i
	}
	for _, want := range []string{"label", "to", "accepts"} {
		if _, ok := col[want]; !ok {
			return nil, fmt.Errorf("%w: the table has no %s column", ErrMap, want)
		}
	}
	sep := cells(lines[start+1])
	if len(sep) == 0 {
		return nil, fmt.Errorf("%w: the header row is not followed by its separator", ErrMap)
	}
	for _, s := range sep {
		if !separatorRE.MatchString(s) {
			return nil, fmt.Errorf("%w: the header row is not followed by its separator", ErrMap)
		}
	}
	m := &Map{rows: map[string]Row{}}
	for _, l := range lines[start+2:] {
		if !strings.HasPrefix(strings.TrimSpace(l), "|") {
			break
		}
		c := cells(l)
		at := func(name string) string {
			if i := col[name]; i < len(c) {
				return c[i]
			}
			return ""
		}
		r, err := parseRow(at("label"), at("to"), at("accepts"))
		if err != nil {
			return nil, err
		}
		if _, dup := m.rows[r.Label]; dup {
			return nil, fmt.Errorf("%w: label %q appears twice", ErrMap, r.Label)
		}
		m.rows[r.Label] = r
		m.order = append(m.order, r.Label)
	}
	return m, nil
}

// cells splits a table line into its trimmed cells.
func cells(line string) []string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "|")
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func parseRow(label, to, accepts string) (Row, error) {
	r := Row{Label: label}
	if !deliver.ValidAgent(label) {
		return r, fmt.Errorf("%w: label %q is not an agent id: letters, digits, dot, dash, underscore, at most 64", ErrMap, label)
	}
	switch {
	case strings.HasPrefix(to, "service "):
		raw := strings.TrimSpace(strings.TrimPrefix(to, "service "))
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return r, fmt.Errorf("%w: label %q: service %q is not an https URL", ErrMap, label, raw)
		}
		r.Kind, r.URL = Service, raw
	case strings.HasPrefix(to, "human [["):
		var err error
		r.Kind = Human
		if r.Session, r.Seat, err = parseSeat(label, strings.TrimSpace(strings.TrimPrefix(to, "human "))); err != nil {
			return r, err
		}
	case strings.HasPrefix(to, "[[") && strings.HasSuffix(to, "]]"):
		var err error
		r.Kind = Seat
		if r.Session, r.Seat, err = parseSeat(label, to); err != nil {
			return r, err
		}
	default:
		return r, fmt.Errorf("%w: label %q: to %q is none of [[<session>/rosters/<role>-<slug>]], human [[<session>/rosters/<role>-<slug>]], service <url>", ErrMap, label, to)
	}
	seen := map[string]bool{}
	for _, k := range strings.Fields(accepts) {
		if !known(k) {
			return r, fmt.Errorf("%w: label %q accepts %q, not one of %s", ErrMap, label, k, strings.Join(Kinds, " "))
		}
		if !seen[k] {
			seen[k] = true
			r.Accepts = append(r.Accepts, k)
		}
	}
	if len(r.Accepts) == 0 {
		return r, fmt.Errorf("%w: label %q accepts nothing: name one or more of %s", ErrMap, label, strings.Join(Kinds, " "))
	}
	return r, nil
}

// parseSeat reads a seat wikilink: its session and the roster record's path.
func parseSeat(label, link string) (session, seat string, err error) {
	inner, ok := strings.CutPrefix(link, "[[")
	if ok {
		inner, ok = strings.CutSuffix(inner, "]]")
	}
	sm := seatRE.FindStringSubmatch(inner)
	if !ok || sm == nil || strings.Contains("/"+inner+"/", "/../") {
		return "", "", fmt.Errorf("%w: label %q: %q is not a seat, [[<session>/rosters/<role>-<slug>]]", ErrMap, label, link)
	}
	return sm[1], inner, nil
}

func known(kind string) bool {
	for _, k := range Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Row is the label's row.
func (m *Map) Row(label string) (Row, bool) {
	r, ok := m.rows[label]
	return r, ok
}

// Len is the number of rows.
func (m *Map) Len() int { return len(m.order) }

// Agents is the map as the card's agent list, in the map's order: every row
// is an agent of the party with the row's accepts (design §3.3).
func (m *Map) Agents() []card.Agent {
	out := make([]card.Agent, 0, len(m.order))
	for _, l := range m.order {
		r := m.rows[l]
		out = append(out, card.Agent{ID: l, Accepts: append([]string(nil), r.Accepts...)})
	}
	return out
}
