package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/status"
)

// rosterConfig is config.json's roster: the private roster page serve keeps
// current (design §8), Page + Slug (+ Login, default the config login).
// Absent, serve writes no page.
type rosterConfig struct {
	Page  string `json:"page,omitempty"`
	Slug  string `json:"slug,omitempty"`
	Login string `json:"login,omitempty"`
}

// rosterPage opens the roster page the config names; nil when it names none.
func rosterPage(cfg config) (*status.Page, error) {
	rc := cfg.Roster
	if rc.Page == "" && rc.Slug == "" {
		return nil, nil
	}
	if rc.Login == "" {
		rc.Login = cfg.Login
	}
	if rc.Page == "" || rc.Slug == "" || rc.Login == "" {
		return nil, fmt.Errorf("%s: roster.page, roster.slug and a login (roster.login or login) go together", configFile)
	}
	return status.NewPage(rc.Page, rc.Slug, rc.Login, nil), nil
}

// peerView is what the party's store says about one peer.
type peerView struct {
	pe     roster.Peer
	root   ed25519.PublicKey // nil while the host waits for the guest's card
	cursor int64
	act    *status.Activity
}

func (p *party) peerView(ctx context.Context, pe roster.Peer) (*peerView, error) {
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return nil, err
	}
	act, _, err := status.LoadActivity(ctx, p.backend, pe.Channel)
	if err != nil {
		return nil, err
	}
	return &peerView{pe: pe, root: ch.Root(), cursor: ch.Cursor(), act: act}, nil
}

func (v *peerView) party() string {
	if v.root == nil {
		return ""
	}
	return keys.PartyID(v.root)
}

// row is the peer's roster page record as of now.
func (v *peerView) row(beat time.Duration, now time.Time) *status.Row {
	r := &status.Row{
		Name: v.pe.Name, Party: v.party(), Channel: v.pe.Channel,
		Side: string(v.pe.Side), State: string(v.pe.State),
		LastKind: v.act.LastKind, Unread: v.act.Unread,
		Beat: int64(beat / time.Second), At: now.UTC(),
	}
	if !v.act.LastAt.IsZero() {
		at := v.act.LastAt.UTC()
		r.LastAt = &at
		r.Active = serves(v.pe) && now.Sub(at) < status.ActiveWindow
	}
	return r
}

// openRoster gives the server its roster page and beat.
func (sv *server) openRoster(beat time.Duration) (err error) {
	sv.beat = beat
	sv.page, err = rosterPage(sv.p.cfg)
	return err
}

// writeRoster is a round's last step: one row per peer whose party is known,
// after every commit of the round. A page write failure is logged and stops
// the page writes of this round alone — the round, its deliveries and the
// message path never see it.
func (sv *server) writeRoster(ctx context.Context) {
	if sv.page == nil {
		return
	}
	r, err := roster.Load(ctx, sv.p.backend)
	if err != nil {
		fmt.Fprintf(sv.out, "roster page: %v\n", err)
		return
	}
	now := time.Now()
	for _, pe := range r.Peers {
		v, err := sv.p.peerView(ctx, pe)
		if err != nil {
			fmt.Fprintf(sv.out, "roster page: %s: %v\n", pe.Name, err)
			continue
		}
		if v.root == nil {
			continue
		}
		if err := sv.page.Put(ctx, status.RowKey(v.root), v.row(sv.beat, now)); err != nil {
			fmt.Fprintf(sv.out, "roster page: %s: %v\n", pe.Name, err)
			return
		}
	}
}

// noteIn records a born message on the channel's activity; a failure is
// logged, the message is already delivered.
func (sv *server) noteIn(ctx context.Context, channel string, seq int64, at time.Time, kind string) {
	if err := status.NoteIn(ctx, sv.p.backend, channel, seq, at, kind); err != nil {
		fmt.Fprintf(sv.out, "activity %s #%d: %v\n", channel, seq, err)
	}
}

// noteOut records a committed send on the channel's activity; a failure is
// a warning, the message is already committed.
func (p *party) noteOut(ctx context.Context, warn io.Writer, channel string, at time.Time) {
	if err := status.NoteOut(ctx, p.backend, channel, at); err != nil {
		fmt.Fprintf(warn, "peer send: activity not noted: %v\n", err)
	}
}

// statusJSON is one peer as peer status --json prints it.
type statusJSON struct {
	Name     string      `json:"name"`
	Party    string      `json:"party"`
	Channel  string      `json:"channel"`
	Side     string      `json:"side"`
	State    string      `json:"state"`
	Cursor   int64       `json:"cursor"`
	LastAt   *time.Time  `json:"lastAt"`
	LastKind string      `json:"lastKind"`
	Unread   int         `json:"unread"`
	SentAt   *time.Time  `json:"sentAt"`
	Active   bool        `json:"active"`
	Page     *pageStatus `json:"page,omitempty"`
}

// pageStatus is the peer's row on the roster page as status read it.
type pageStatus struct {
	At    *time.Time `json:"at,omitempty"`
	Stale bool       `json:"stale"`
	Error string     `json:"error,omitempty"`
}

func (ps *pageStatus) String(now time.Time) string {
	switch {
	case ps.Error != "":
		return "error: " + ps.Error
	case ps.At == nil:
		return "absent"
	case ps.Stale:
		return "stale " + ago(now, *ps.At)
	}
	return "fresh " + ago(now, *ps.At)
}

func ago(now, t time.Time) string { return now.Sub(t).Truncate(time.Second).String() }

// cmdStatus prints every peer from the party's store, and its roster page
// row when config names the page. Read-only: it writes nothing and never
// asks the relay.
func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("status", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	asJSON := fl.Bool("json", false, "print the peers as a JSON array")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: peer status [--dir D] [--json]")
		return 2
	}
	rows, err := runStatus(context.Background(), *dirFlag, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "peer status: %v\n", err)
		return 1
	}
	if *asJSON {
		if rows == nil {
			rows = []statusJSON{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(stderr, "peer status: %v\n", err)
			return 1
		}
		return 0
	}
	printStatus(stdout, rows, time.Now())
	return 0
}

func runStatus(ctx context.Context, dir string, now time.Time) ([]statusJSON, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, err
	}
	page, err := rosterPage(p.cfg)
	if err != nil {
		return nil, err
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return nil, err
	}
	var out []statusJSON
	for _, pe := range r.Peers {
		v, err := p.peerView(ctx, pe)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pe.Name, err)
		}
		row := v.row(0, now)
		s := statusJSON{
			Name: pe.Name, Party: v.party(), Channel: pe.Channel, Side: row.Side, State: row.State,
			Cursor: v.cursor, LastAt: row.LastAt, LastKind: row.LastKind, Unread: row.Unread, Active: row.Active,
		}
		if !v.act.SentAt.IsZero() {
			at := v.act.SentAt.UTC()
			s.SentAt = &at
		}
		if page != nil && v.root != nil {
			s.Page = &pageStatus{}
			switch pr, err := page.Get(ctx, status.RowKey(v.root)); {
			case err != nil:
				s.Page.Error = err.Error()
			case pr != nil:
				at := pr.At
				s.Page.At, s.Page.Stale = &at, pr.Stale(now)
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// tail is a party id's last 8 characters, the way a person tells keys apart.
func tail(party string) string {
	if party == "" {
		return "?"
	}
	if len(party) <= 8 {
		return party
	}
	return "…" + party[len(party)-8:]
}

func printStatus(w io.Writer, rows []statusJSON, now time.Time) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "no peers")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPARTY\tSIDE\tSTATE\tCURSOR\tLAST\tUNREAD\tACTIVE\tPAGE")
	for _, s := range rows {
		last := "-"
		if s.LastAt != nil {
			last = s.LastKind + " " + s.LastAt.Format(time.RFC3339)
		}
		active := "no"
		if s.Active {
			active = "yes"
		}
		pg := "-"
		if s.Page != nil {
			pg = s.Page.String(now)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%d\t%s\t%s\n", s.Name, tail(s.Party), s.Side, s.State, s.Cursor, last, s.Unread, active, pg)
	}
	tw.Flush()
}
