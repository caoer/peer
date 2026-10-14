package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/seats"
	"github.com/caoer/peer/internal/session"
)

// uccConfig is config.json's ucc: the fleet's sessions root and the seat map
// on it (UCC design v2 § 5; plan decision 12). With it the card's agents are
// the map's rows, and serve delivers by the map — <root>/<seat's
// session>/inbox/<id>.md, quarantine/ beside it — instead of the delivery
// directory. The record is the delivery: which host holds the seat, and its
// wake, are UCC's. Without ucc, serve keeps the local delivery (design §7.3).
//
// The birth is the same tmp + link write as the local one: the face has no
// birth a process without a session identity can call (MCP put is served per
// session; mrd put refuses a missing path; mrd new needs a def page the root
// does not carry), the daemon's sub drain sees a raw birth, and the
// born-identity middleware stamps nothing on it — so the record keeps exactly
// its five keys and carries no actor.
type uccConfig struct {
	// Root is the sessions root's absolute path — what `ccc-statusd
	// sessions-root` prints on a UCC host.
	Root string `json:"root"`
	// Seats is the map's path under the root; default peers/seats.md.
	Seats string `json:"seats,omitempty"`
	// ServiceRetries is how many rounds a failed service POST is tried
	// again before it is quarantined locally (service.go); default 20.
	ServiceRetries int `json:"serviceRetries,omitempty"`
}

const seatsFile = "peers/seats.md"

func (u *uccConfig) seatsPath() string {
	s := u.Seats
	if s == "" {
		s = seatsFile
	}
	return filepath.Join(u.Root, filepath.FromSlash(s))
}

// loadSeats reads the seat map when config names ucc and makes its rows the
// card's agents (§ 5: peer reads the map for its card). Nil without ucc. A
// map that is absent or outside its grammar refuses: on a UCC host the map
// is the card, and nothing is delivered until UCC has written it.
func (p *party) loadSeats() (*seats.Map, error) {
	u := p.cfg.UCC
	if u == nil {
		return nil, nil
	}
	if !filepath.IsAbs(u.Root) {
		return nil, fmt.Errorf("%s: ucc.root %q is not an absolute path", configFile, u.Root)
	}
	m, err := seats.Load(u.seatsPath())
	if err != nil {
		return nil, fmt.Errorf("%w — UCC writes it; nothing is delivered until it is there", err)
	}
	p.cfg.Agents = m.Agents()
	return m, nil
}

// loadSeats is the server's: read again every round, since UCC may change
// the map while serve runs.
func (sv *server) loadSeats() error {
	m, err := sv.p.loadSeats()
	if err != nil {
		return err
	}
	sv.seats = m
	return nil
}

// errWait is a message not consumed yet: its seat's session is not on this
// root. The channel stops before it for the round and the cursor stays, so
// the next round pulls it again — the root replicates, or the map is wrong
// and every round says so.
var errWait = errors.New("not on this root")

// seatRow is the map lookup for a message's to — the label after the party.
// A label the map does not carry is refused. A human row is delivered as a
// seat row into the session of the seat that relays to the person, to:
// still the human's address; that seat decides what the person reads. A
// service row is delivered by its callback (service.go).
func (sv *server) seatRow(to string) (seats.Row, error) {
	_, label := splitAddr(to)
	if label == "" {
		return seats.Row{}, fmt.Errorf("unmapped label %q: refused — %s names no agent", label, to)
	}
	row, ok := sv.seats.Row(label)
	if !ok {
		return seats.Row{}, fmt.Errorf("unmapped label %q: refused", label)
	}
	return row, nil
}

// sessionDir is the seat's session on this root.
func (sv *server) sessionDir(row seats.Row) string {
	return filepath.Join(sv.p.cfg.UCC.Root, filepath.FromSlash(row.Session))
}

// uccBorder is the map lookup at the border (§ 5 § Address), after the
// address check and before the spool and the commit: a refused label is
// consumed with its reason and born nowhere; a seat whose session is not on
// this root waits. A service row has no session to wait for.
func (sv *server) uccBorder(m *session.Message) error {
	row, err := sv.seatRow(m.To)
	if err != nil || row.Kind == seats.Service {
		return err
	}
	if _, err := os.Stat(sv.sessionDir(row)); err != nil {
		return fmt.Errorf("%s's session %s is %w", row.Label, row.Session, errWait)
	}
	return nil
}

// uccPlace is where a spooled message is born (§ 5 § Intake): its seat's
// session, and the inbox or — doc, file, a kind the row does not accept —
// the quarantine beside it. A label the map no longer carries (it moved
// since the border) has nowhere to land: the entry is dropped from the spool
// with its reason, the map being UCC's to write.
func (sv *server) uccPlace(m *session.Message) (string, deliver.Place, error) {
	row, err := sv.seatRow(m.To)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", deliver.ErrRecord, err)
	}
	return sv.sessionDir(row), deliver.Route(m.Kind, row.Accepts), nil
}
