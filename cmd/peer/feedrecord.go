package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/e2e"
	"github.com/caoer/peer/internal/feed"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/seats"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/timeline"
)

// A channel's messages, received and sent, also reach the party's reader
// pages live through the feed named by config.json feed.url: a source socket
// on <url>/feed/<party id> (internal/feed), the host saying hello with the
// source secret the shared state record feed holds (feed.go, decision 33),
// each record a frame the worker fans out to the pages and stores nowhere
// (plan-delivery decisions 15, 23, 30, 31), the record carrying the sender's
// party name as this host knows it (feedData). What a page missed it asks for
// on connect: the host replays the inbox records it holds for received
// messages and, for sent ones, the local record this file keeps —
// <dir>/feed/<peer name>/out-<seq>.json, the peer-timeline@1 data of the
// message, 30 days. A page's reader key rides the replay request and lands
// in readers-pending (readers.go). feed.only "e2e" keeps plain messages off
// the worker: only encrypted records are fed and replayed. A host with
// feed.url and no feed record says so once at start and once per round, and
// feeds nothing.

// feedConfig is config.json "feed": {"url", "only"?} — no secret in the file.
type feedConfig struct {
	URL  string `json:"url"`
	Only string `json:"only,omitempty"`
}

const (
	// feedDir holds, under the peer directory, the local records of sent
	// messages by peer name.
	feedDir = "feed"
	// feedKeep is how long a local record is kept for the replay.
	feedKeep = 30 * 24 * time.Hour
	// feedOnlyE2E is the one value of feed.only: encrypted records alone.
	feedOnlyE2E = "e2e"
)

// feedData is a record as it travels on the feed, the live frame and the
// replay alike: the peer-timeline@1 data with its body cut once, and the
// sender's party name as this host knows it (senderName, forward.go) — absent
// when it knows none, and the page then names the side alone.
type feedData struct {
	forwardData
	FromName string `json:"from_name,omitempty"`
}

// check refuses a feed whose url is not https or whose only is not e2e: on
// this binary each would leave the feed silently off or wide open.
func (f *feedConfig) check() error {
	if f == nil {
		return nil
	}
	if u, err := url.Parse(f.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s: feed.url is not an https URL", configFile)
	}
	if f.Only != "" && f.Only != feedOnlyE2E {
		return fmt.Errorf("%s: feed.only %q: the one value is %q", configFile, f.Only, feedOnlyE2E)
	}
	return nil
}

// e2eOnly reports whether plain records stay off the feed.
func (f *feedConfig) e2eOnly() bool { return f != nil && f.Only == feedOnlyE2E }

// feedLine is serve's start line on stderr, the journal: the feed's URL,
// off, or not set up while the feed record is absent.
func (p *party) feedLine(ctx context.Context) string {
	if p.cfg.Feed == nil {
		return "feed: off"
	}
	if secret, err := p.feedSecret(ctx); err != nil {
		return "feed: " + err.Error()
	} else if secret == "" {
		return feedNotSetUp
	}
	if p.cfg.Feed.e2eOnly() {
		return "feed: " + p.cfg.Feed.URL + " · only e2e"
	}
	return "feed: " + p.cfg.Feed.URL
}

// feedSecret is the source secret the feed record holds; "" while the record
// is absent.
func (p *party) feedSecret(ctx context.Context) (string, error) {
	f, err := p.store.Feed(ctx)
	if err != nil {
		return "", err
	}
	return f.Source, nil
}

// feedHost is the name this host says hello with: its hostname, in the
// worker's grammar.
func feedHost() string {
	h, _ := os.Hostname()
	h = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '-'
	}, h)
	if len(h) > 64 {
		h = h[:64]
	}
	if h == "" {
		h = "host"
	}
	return h
}

// feedLog writes to the party's current timeline log, whichever round it is.
type feedLog struct{ p *party }

func (l feedLog) Write(b []byte) (int, error) { return l.p.timelineLog().Write(b) }

// feedDial opens a source socket on the party's feed with the record's secret.
func (p *party) feedDial(ctx context.Context, secret string) *feed.Client {
	return feed.Dial(ctx, p.cfg.Feed.URL, p.partyID(), secret, feedHost(), feed.Options{
		HTTPClient: serviceClient,
		Log:        feedLog{p},
		Replay:     p.replayFeed,
		Key:        p.readerKey,
	})
}

// feedStart opens the party's feed socket for the caller's life — a serve's
// — replaying the inbox records under inbox; nothing without a feed, and
// nothing yet while the feed record is absent (feedRound dials once it is).
func (p *party) feedStart(ctx context.Context, inbox string) {
	if p.cfg.Feed == nil {
		return
	}
	p.feedInbox, p.feedServe = inbox, true
	p.feedRound(ctx)
}

// feedRound is a serve round's feed step: a socket not yet open — the record
// was absent — or one the worker refused is opened again with the record's
// current secret; while the record is absent the journal says so.
func (p *party) feedRound(ctx context.Context) {
	if p.cfg.Feed == nil || !p.feedServe {
		return
	}
	if p.feed != nil {
		if !p.feed.Refused() {
			return
		}
		p.feed.Close()
		p.feed = nil
	}
	secret, err := p.feedSecret(ctx)
	switch {
	case err != nil:
		fmt.Fprintf(p.timelineLog(), "feed: %v\n", err)
	case secret == "":
		fmt.Fprintln(p.timelineLog(), feedNotSetUp)
	default:
		p.feed = p.feedDial(ctx, secret)
	}
}

// feedStop waits for the acks of what was sent, one timeout at most, and
// closes the socket.
func (p *party) feedStop() {
	if p.feed == nil {
		return
	}
	p.feedFlush(p.feed)
	p.feed.Close()
	p.feed = nil
}

// feedFlush waits for c's acks, one timeout at most; the records still
// pending are logged and dropped — the feed stores nothing, and the local and
// inbox records serve the replay.
func (p *party) feedFlush(c *feed.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()
	if err := c.Flush(ctx); err != nil && c.Pending() > 0 {
		fmt.Fprintf(p.timelineLog(), "feed: %d records not acked (%v); the replay serves them\n", c.Pending(), err)
	}
}

// feedTimeline is writeTimeline's feed step for message m in direction dir
// under relay seq on the channel with peer name: a sent message's local
// record, then the frame — on the serve's socket, or for a command on one
// socket opened, flushed and closed for this record.
func (p *party) feedTimeline(ctx context.Context, name, dir string, seq int64, m *session.Message) {
	if p.cfg.Feed == nil {
		return
	}
	log := p.timelineLog()
	rec, err := timeline.Of(dir, m)
	if err != nil {
		fmt.Fprintf(log, "feed %s: %s: %v\n", name, m.ID, err)
		return
	}
	if dir == timeline.Out {
		if err := p.writeFeedRecord(name, seq, rec); err != nil {
			fmt.Fprintf(log, "feed %s: %s: local record not written: %v\n", name, m.ID, err)
		}
	}
	if p.cfg.Feed.e2eOnly() && !rec.E2E {
		return
	}
	data, err := json.Marshal(feedData{forwardData: cutData(rec), FromName: p.senderName(dir, name)})
	if err != nil {
		fmt.Fprintf(log, "feed %s: %s: %v\n", name, m.ID, err)
		return
	}
	n := p.feedN.Add(1)
	if p.feed != nil {
		p.feed.Send(data, n)
		return
	}
	if p.feedServe {
		// A serve whose record is absent: the round said so; the records
		// wait in the inbox and the local record for the replay.
		return
	}
	secret, err := p.feedSecret(ctx)
	if err != nil {
		fmt.Fprintf(log, "feed %s: %s: %v\n", name, m.ID, err)
		return
	}
	if secret == "" {
		fmt.Fprintln(log, feedNotSetUp)
		return
	}
	c := p.feedDial(ctx, secret)
	c.Send(data, n)
	p.feedFlush(c)
	c.Close()
}

// feedRecordPath is the local record of the message sent under seq to the
// peer called name; "" for a name that cannot be a directory.
func (p *party) feedRecordPath(name string, seq int64) string {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return ""
	}
	return filepath.Join(p.dir, feedDir, name, fmt.Sprintf("out-%08d.json", seq))
}

// writeFeedRecord keeps rec as the local record of a sent message, 0600,
// create-only: a record already there is the same message, written before.
func (p *party) writeFeedRecord(name string, seq int64, rec *timeline.Record) error {
	path := p.feedRecordPath(name, seq)
	if path == "" {
		return fmt.Errorf("peer name %q cannot name a directory", name)
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// pruneFeed drops the local records older than feedKeep; once a round.
func (p *party) pruneFeed() {
	if p.cfg.Feed == nil {
		return
	}
	names, _ := filepath.Glob(filepath.Join(p.dir, feedDir, "*", "out-*.json"))
	cutoff := time.Now().Add(-feedKeep)
	for _, n := range names {
		if st, err := os.Stat(n); err == nil && st.ModTime().Before(cutoff) {
			if err := os.Remove(n); err != nil && !errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintf(p.timelineLog(), "feed: %s: %v\n", n, err)
			}
		}
	}
}

// replayFeed answers a viewer's connect: every record this host holds, the
// inbox records for received messages and the local records for sent ones,
// in at order, each naming its sender as the live frame does, then the card's
// current reader keys.
func (p *party) replayFeed(ctx context.Context, r feed.Replay, send func(json.RawMessage) error) ([]string, error) {
	recs, err := p.feedRecords()
	if err != nil {
		return p.ownReaders(ctx), err
	}
	names := p.peerNames(ctx)
	for _, rec := range recs {
		if p.cfg.Feed.e2eOnly() && !rec.E2E {
			continue
		}
		party, _, _ := strings.Cut(rec.From, "/")
		data, err := json.Marshal(feedData{forwardData: cutData(rec), FromName: p.senderName(rec.Dir, names[party])})
		if err != nil {
			return p.ownReaders(ctx), err
		}
		if err := send(data); err != nil {
			return p.ownReaders(ctx), err
		}
	}
	return p.ownReaders(ctx), nil
}

// peerNames is the roster name of every peer whose party is known, by party
// id: how the replay names a received record's sender. A roster that does not
// load names nobody, with a line.
func (p *party) peerNames(ctx context.Context) map[string]string {
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		fmt.Fprintf(p.timelineLog(), "feed: %v\n", err)
		return nil
	}
	names := map[string]string{}
	for _, pe := range r.Peers {
		ch, err := p.store.Channel(ctx, pe.Channel)
		if err != nil || ch.Root() == nil {
			continue
		}
		names[keys.PartyID(ch.Root())] = pe.Name
	}
	return names
}

// feedRecords is every record the replay serves, in at order: the local
// records of sent messages and the inbox records of received ones. A file
// that does not read as one is skipped with a line; the rest are served.
func (p *party) feedRecords() ([]*timeline.Record, error) {
	log := p.timelineLog()
	var out []*timeline.Record
	names, err := filepath.Glob(filepath.Join(p.dir, feedDir, "*", "out-*.json"))
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		var rec timeline.Record
		b, err := os.ReadFile(n)
		if err == nil {
			err = json.Unmarshal(b, &rec)
		}
		if err != nil {
			fmt.Fprintf(log, "feed: %s: %v\n", n, err)
			continue
		}
		out = append(out, &rec)
	}
	for _, dir := range p.inboxDirs() {
		names, err := filepath.Glob(filepath.Join(dir, "*.md"))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			m, ok := parseInboxRecord(n)
			if !ok {
				continue
			}
			rec, err := timeline.Of(timeline.In, m)
			if err != nil {
				fmt.Fprintf(log, "feed: %s: %v\n", n, err)
				continue
			}
			out = append(out, rec)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// inboxDirs is where this party's received messages are born: the delivery
// directory's inbox, or under ucc the inbox of every session the seat map
// names.
func (p *party) inboxDirs() []string {
	if u := p.cfg.UCC; u != nil {
		m, err := seats.Load(u.seatsPath())
		if err != nil {
			fmt.Fprintf(p.timelineLog(), "feed: %v\n", err)
			return nil
		}
		seen := map[string]bool{}
		var dirs []string
		for _, a := range m.Agents() {
			row, ok := m.Row(a.ID)
			if !ok || row.Session == "" || seen[row.Session] {
				continue
			}
			seen[row.Session] = true
			dirs = append(dirs, filepath.Join(u.Root, filepath.FromSlash(row.Session), string(deliver.Inbox)))
		}
		return dirs
	}
	dir := p.feedInbox
	if dir == "" {
		dir = p.cfg.Deliver
	}
	if dir == "" {
		dir = filepath.Join(p.dir, deliverDir)
	}
	return []string{filepath.Join(dir, string(deliver.Inbox))}
}

// parseInboxRecord reads an inbox record (deliver.Record.Bytes) back into the
// message it was born from: from, to, kind, at and the body; the id is the
// file's name. A file that is not a channel message of this protocol — no
// frontmatter, an address outside the grammar, a room record (group) — is
// not one.
func parseInboxRecord(path string) (*session.Message, bool) {
	id := strings.TrimSuffix(filepath.Base(path), ".md")
	if !deliver.ValidID(id) {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(b, []byte("---\n")) {
		return nil, false
	}
	head, body, ok := bytes.Cut(b[4:], []byte("\n---\n"))
	if !ok {
		return nil, false
	}
	fm := map[string]string{}
	for _, line := range strings.Split(string(head), "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			return nil, false
		}
		fm[k] = v
	}
	if _, room := fm["group"]; room || fm["verified"] != "true" {
		return nil, false
	}
	m := &session.Message{V: 1, ID: id, From: fm["from"], To: fm["to"], Kind: strings.Trim(fm["kind"], `"`), Body: body}
	if !deliver.ValidAddr(m.From) || !deliver.ValidAddr(m.To) || !session.ValidKind(m.Kind) {
		return nil, false
	}
	if m.At, err = time.Parse(time.RFC3339Nano, fm["at"]); err != nil {
		return nil, false
	}
	return m, true
}

// ownReaders is the reader keys on this party's card as the state holds it;
// nil when it holds none or no card.
func (p *party) ownReaders(ctx context.Context) []string {
	oc, err := p.store.OwnCard(ctx)
	if err != nil || !oc.Present() {
		return nil
	}
	c, err := card.Verify(oc.Details, p.id.Party)
	if err != nil {
		return nil
	}
	d, err := e2e.ParseDetails(c.Details)
	if err != nil || d == nil {
		return nil
	}
	return d.Keys
}
