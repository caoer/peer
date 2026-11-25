package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/seats"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
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

// checkFrom refuses a send --from a label the seat map has no row for: the
// peer answers <party>/<label>, and this party's border refuses a label its
// map does not carry (seatRow), so the answer would be lost. The error names
// the map and the labels the calling seat may send from. No --from (the
// party itself) and a party without ucc pass. Rule 7 (R1250 (4)): a tool
// checking what it is handed — at its first wrong refusal this check is
// taken out.
func (p *party) checkFrom(from string) error {
	if from == "" || p.seats == nil {
		return nil
	}
	if _, ok := p.seats.Row(from); ok {
		return nil
	}
	path := p.cfg.UCC.seatsPath()
	head := fmt.Sprintf("--from %q: the seat map %s has no row for it, so an answer to it is refused at this party's border", from, path)
	seat, err := callingSeat(p.cfg.UCC.Root)
	if err != nil {
		return fmt.Errorf("%s; this seat was not resolved (%v) — the map's labels: %s; or omit --from to send as the party", head, err, labelList(p.seats.Labels()))
	}
	return fmt.Errorf("%s; this seat (%s) may send from: %s; or omit --from to send as the party", head, seat, labelList(p.seats.LabelsOfSeat(seat)))
}

func labelList(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

// callingSeat is the seat of the agent running this command: its session id
// in CLAUDE_CODE_SESSION_ID, whose first eight characters name its card at
// <root>/agents/<short>/<short>.md, whose seat: is a wikilink to the roster
// record — the text a seat row's to carries.
func callingSeat(root string) (string, error) {
	id := os.Getenv("CLAUDE_CODE_SESSION_ID")
	if len(id) < 8 {
		return "", errors.New("CLAUDE_CODE_SESSION_ID is not set")
	}
	short := id[:8]
	if !deliver.ValidAgent(short) {
		return "", fmt.Errorf("CLAUDE_CODE_SESSION_ID %q is not a session id", id)
	}
	card := filepath.Join(root, "agents", short, short+".md")
	b, err := os.ReadFile(card)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return "", fmt.Errorf("%s has no frontmatter", card)
	}
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) == "---" {
			break
		}
		v, ok := strings.CutPrefix(l, "seat:")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		v = strings.TrimSuffix(strings.TrimPrefix(v, "[["), "]]")
		v, _, _ = strings.Cut(v, "|")
		v = strings.TrimSuffix(v, ".md")
		if v == "" {
			break
		}
		return v, nil
	}
	return "", fmt.Errorf("%s names no seat", card)
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

// unlabeledError is the border's refusal of a message that names no agent of
// this party, or a label its seat map does not carry. The message is still
// consumed with this reason and born nowhere — the grammar rules out a
// guessed seat (ruling on task peer-unlabeled-message-silent-drop) — but the
// refusal is not silent: the host whose commit consumed the message answers
// the sender on the same line and notices the seat bound to the sending
// party (answerUnlabeled).
type unlabeledError struct{ label, to string }

func (e unlabeledError) Error() string {
	if e.label == "" {
		return fmt.Sprintf("unmapped label %q: refused — %s names no agent", e.label, e.to)
	}
	return fmt.Sprintf("unmapped label %q: refused", e.label)
}

// seatRow is the map lookup for a message's to — the label after the party.
// A label the map does not carry is refused. A human row is delivered as a
// seat row into the session of the seat that relays to the person, to:
// still the human's address; that seat decides what the person reads. A
// service row is delivered by its callback (service.go).
func (sv *server) seatRow(to string) (seats.Row, error) {
	_, label := splitAddr(to)
	if label == "" {
		return seats.Row{}, unlabeledError{label: "", to: to}
	}
	row, ok := sv.seats.Row(label)
	if !ok {
		return seats.Row{}, unlabeledError{label: label}
	}
	return row, nil
}

// refusedType marks a spool entry whose step is the unlabeled refusal's —
// the answer and the notice, not a birth — so ReplaySpool runs the step a
// crash or a landed-but-errored commit cut, instead of delivering the refused
// message.
func refusedType(env string) string { return "refused/" + env }

func isRefusedType(t string) bool { return strings.HasPrefix(t, "refused/") }

// consumeUnlabeled is the refusal's decision-5 order, the delivered path's
// shape (receive): spool the owed step, commit the channel past the message,
// run the step, settle the entry. The commit is the claim — a conflict loser
// removes its entry and answers nothing, the winner did — and an error after
// a write that landed leaves the entry for the next round's ReplaySpool seen
// check, which runs the step once when the commit landed and drops it when
// it did not. The refusal was never silent about its reason; with this it is
// not silent about its answer either.
func (c *channelServe) consumeUnlabeled(ctx context.Context, rec relay.Record, m *session.Message) error {
	plain, err := m.Marshal()
	if err != nil {
		return c.commit(ctx, rec)
	}
	e := &store.Entry{ID: m.ID, Channel: c.ch.Name(), Seq: rec.Seq, Type: refusedType(rec.Env.Type.String()), Body: plain}
	if err := c.sv.spool.Add(e); err != nil {
		return err
	}
	if c.sv.beforeCommit != nil {
		if err := c.sv.beforeCommit(e); err != nil {
			c.sv.spool.Remove(e)
			return err
		}
	}
	if err := c.ch.Commit(ctx); err != nil {
		if errors.Is(err, store.ErrConflict) {
			c.sv.spool.Remove(e)
		}
		return err
	}
	if err := c.sv.spool.MarkCommitted(e); err != nil {
		return err
	}
	c.commitKeys(ctx, rec)
	if c.sv.beforeRefusal != nil {
		if err := c.sv.beforeRefusal(e); err != nil {
			return err
		}
	}
	if err := c.sv.runRefusalStep(ctx, c.pe, m); err != nil {
		return err
	}
	// Settled before anything that can fail after the send: a reload that
	// errors here costs a stale snapshot (one extra pull), never a re-run of
	// the step. The answer is idempotent on the line anyway (its id is
	// derived; the receiver's replay protection refuses the second).
	if err := c.sv.spool.Remove(e); err != nil {
		return err
	}
	return c.load(ctx)
}

// replayRefusalStep runs a refusal step whose claim landed and whose run a
// crash or an error cut (replaySpool, refusedType entries).
func (sv *server) replayRefusalStep(ctx context.Context, e *store.Entry, m *session.Message) error {
	r, err := roster.Load(ctx, sv.p.backend)
	if err != nil {
		return err
	}
	pe := r.ByChannel(e.Channel)
	if pe == nil {
		fmt.Fprintf(sv.out, "dropped the %s refusal from the spool: no peer on channel %s\n", m.ID, e.Channel)
		return nil
	}
	return sv.runRefusalStep(ctx, *pe, m)
}

// runRefusalStep answers the sender and notices the bound seat — once per
// refused message, from receive or from ReplaySpool. The answer is best
// effort (a send that failed after its commit leaves it in the outbox and it
// goes out on the next round, as peer send promises); the notice records
// what the answer actually did.
func (sv *server) runRefusalStep(ctx context.Context, pe roster.Peer, m *session.Message) error {
	var e unlabeledError
	if _, label := splitAddr(m.To); label == "" {
		e = unlabeledError{to: m.To}
	} else {
		e = unlabeledError{label: label}
	}
	outcome := "answered"
	switch {
	case strings.HasSuffix(m.Kind, ".unlabeled"):
		outcome = "withheld: a refusal-kind message is answered never"
	default:
		from := sv.p.partyID()
		body := fmt.Sprintf("your %s message was not delivered: it ", m.Kind)
		if e.label == "" {
			body += "named no agent of this party"
		} else {
			body += fmt.Sprintf("named %q, a label this party does not map", e.label)
		}
		if labels := sv.seatLabels(m.Kind); len(labels) > 0 {
			body += fmt.Sprintf(". Address one of our labels — %s — as %s/<label>.", strings.Join(labels, ", "), from)
		} else {
			body += fmt.Sprintf(". No seat of this party accepts a %s.", m.Kind)
		}
		// The answer's id is derived from the refused message's, so however
		// many hosts replay the step — a commit error that landed, a crash
		// after the send — every send carries the same id and the receiver's
		// replay protection (its channel's seen set) refuses the second: one
		// answer on the line, whatever the hosts do. A far party that
		// pre-sends an id of this shape hides its own answer alone.
		sum := sha256.Sum256([]byte(m.ID))
		ans := &session.Message{
			V: session.MessageVersion, ID: "unlabeled-" + hex.EncodeToString(sum[:20]),
			From: from, To: m.From, Kind: "vnd." + from + ".unlabeled",
			At: time.Now().UTC().Truncate(time.Millisecond), Body: []byte(body),
		}
		if !session.ValidKind(ans.Kind) {
			outcome = "not sent: the answer could not be composed (see the journal)"
			fmt.Fprintf(sv.out, "unlabeled answer to %s did not compose (kind %q)\n", pe.Name, ans.Kind)
		} else if err := sv.p.sendMessage(ctx, pe, ans, sv.out); err != nil {
			outcome = "not sent: the send failed (see the journal)"
			fmt.Fprintf(sv.out, "unlabeled answer to %s did not go out (%v); the message stays consumed\n", pe.Name, err)
		} else {
			// The answer's id is the one the sender's inbox record carries: this
			// line and that record are the two sides of one answer.
			fmt.Fprintf(sv.out, "unlabeled answer %s → %s for %s\n", ans.ID, pe.Name, m.ID)
		}
	}
	sv.noticeUnlabeled(m, e, outcome)
	return nil
}

// noticeUnlabeled births the refused message's notice record in the inbox of
// the session peers/parties.md binds the sending party to — the same place
// its delivered records land, so the position's holder reads it beside them.
// The birth line carries the delivered shape peer-wake follows, so the bound
// position is told as it is for a delivery. Without a binding, without UCC,
// or on a root the bound session is not on, the journal's refusal line is
// the notice — no directory is created for a session that is not here, which
// would fool the delivery path's wait into birthing into a placeholder.
func (sv *server) noticeUnlabeled(m *session.Message, e unlabeledError, outcome string) {
	u := sv.p.cfg.UCC
	if u == nil {
		return
	}
	from, _ := splitAddr(m.From)
	bound, ok := partySeat(filepath.Join(u.Root, filepath.FromSlash(partiesFile)), from)
	if !ok {
		fmt.Fprintf(sv.out, "unlabeled message from %s: peers/parties.md binds no seat; the notice stays here\n", from)
		return
	}
	dir := filepath.Join(u.Root, filepath.FromSlash(bound))
	if _, err := os.Stat(dir); err != nil {
		fmt.Fprintf(sv.out, "unlabeled notice for %s: session %s is not on this root; the notice stays here\n", from, bound)
		return
	}
	// The id is this party's own derivation — deterministic, so a replay
	// writes the same record once, and in its own namespace, so no far-chosen
	// message id overflows the grammar or collides with a record a delivery
	// birthed.
	sum := sha256.Sum256([]byte(m.ID))
	id := "refused-" + hex.EncodeToString(sum[:20])
	kind := "vnd." + sv.p.partyID() + ".unlabeled"
	body := fmt.Sprintf("NOT DELIVERED — refused at the border: %s.\nThe %s from %s was consumed and born nowhere. The answer was %s; a send the relay refused stays with the outbox and goes out on the next round. The record exists so the refusal is seen, not the message.\n", e.Error(), m.Kind, m.From, outcome)
	path, born, err := deliver.Write(dir, deliver.Inbox, id, deliver.Record{
		From: m.From, To: m.To, Kind: kind, At: m.At, Body: []byte(body),
	})
	if err != nil {
		fmt.Fprintf(sv.out, "unlabeled notice for %s did not land (%v)\n", from, err)
		return
	}
	verb := "delivered"
	if !born {
		verb = "already delivered"
	}
	fmt.Fprintf(sv.out, "%s %s %s → %s\n", verb, kind, id, path)
}

// seatLabels is the labels a kind may be addressed to, from the party's
// published card — a row the live map added since the last card publish is
// not named to a sender whose copy of the card predates it — falling back to
// the map's labels when there is no card to read. Nil without a seat map
// (the border refuses nothing then, so it has no one to list for).
func (sv *server) seatLabels(kind string) []string {
	if sv.seats == nil {
		return nil
	}
	if own, _, ok := sv.ownCard(context.Background()); ok {
		if c, err := card.Verify(own, sv.p.id.Party); err == nil {
			var out []string
			for _, a := range c.Agents {
				if row, has := sv.seats.Row(a.ID); has && slices.Contains(row.Accepts, kind) {
					out = append(out, a.ID)
				}
			}
			return out
		}
	}
	return sv.seats.LabelsAccepting(kind)
}

// sessionDir is the seat's session on this root.
func (sv *server) sessionDir(row seats.Row) string {
	return filepath.Join(sv.p.cfg.UCC.Root, filepath.FromSlash(row.Session))
}

// uccBorder is the map lookup at the border (§ 5 § Address), after the
// address check and before the spool and the commit: a refused label is
// consumed with its reason and born nowhere; a seat whose session is not on
// this root waits. A service row has no session to wait for. An unlabeled
// refusal whose bound seat's session is not on this root waits the same
// way — the notice is the refusal's delivery, and a root the session has
// not reached yet must not lose it.
func (sv *server) uccBorder(m *session.Message) error {
	row, err := sv.seatRow(m.To)
	if err != nil {
		var unlabeled unlabeledError
		if errors.As(err, &unlabeled) && sv.noticeWaits(m) {
			return fmt.Errorf("the notice's bound session is %w", errWait)
		}
		return err
	}
	if row.Kind == seats.Service {
		return nil
	}
	if _, err := os.Stat(sv.sessionDir(row)); err != nil {
		return fmt.Errorf("%s's session %s is %w", row.Label, row.Session, errWait)
	}
	return nil
}

// noticeWaits reports whether an unlabeled refusal's notice has a bound seat
// whose session is not on this root: the refusal waits before its consume
// until the session reaches this root, as a delivery waits. No binding — no
// seat to wait for — does not wait: the notice lands as the journal's
// refusal line.
func (sv *server) noticeWaits(m *session.Message) bool {
	u := sv.p.cfg.UCC
	if u == nil {
		return false
	}
	from, _ := splitAddr(m.From)
	bound, ok := partySeat(filepath.Join(u.Root, filepath.FromSlash(partiesFile)), from)
	if !ok {
		return false
	}
	_, err := os.Stat(filepath.Join(u.Root, filepath.FromSlash(bound)))
	return err != nil
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
