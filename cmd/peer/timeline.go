package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/status"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/timeline"
)

// timelineConfig is one peer's collaboration page (design §8): config.json
// "timelines": {"<peer name>": {"page", "slug", "login"}}, login defaulting
// to the config login. It is host-local config like the roster page, not a
// field of the shared roster record: the login is this host's secret. A peer
// with no entry gets no timeline writes.
type timelineConfig struct {
	Page  string `json:"page,omitempty"`
	Slug  string `json:"slug,omitempty"`
	Login string `json:"login,omitempty"`
}

// timelinePendingDir holds, under the peer directory, the timeline record of
// each sent message whose relay put failed after its commit: its relay seq,
// and so its key, is known only once the outbox replay puts it.
const timelinePendingDir = "timeline-pending"

// timelineState is a party's timeline writes in one round — a serve round or
// one peer send: where they log, and the peers whose page refused, skipped
// for the rest of the round so a refusing page costs one log line per round.
type timelineState struct {
	log     io.Writer
	refused map[string]bool
}

// timelineRound starts a round of timeline writes logging to log.
func (p *party) timelineRound(log io.Writer) {
	p.tl = &timelineState{log: log, refused: map[string]bool{}}
}

func (p *party) timelineLog() io.Writer {
	if p.tl == nil {
		p.timelineRound(os.Stderr)
	}
	return p.tl.log
}

// timelinePage opens the peer's collaboration page; nil when config names none.
func (p *party) timelinePage(name string) (*status.Page, error) {
	tc, ok := p.cfg.Timelines[name]
	if !ok {
		return nil, nil
	}
	if tc.Login == "" {
		tc.Login = p.cfg.Login
	}
	if tc.Page == "" || tc.Slug == "" || tc.Login == "" {
		return nil, fmt.Errorf("%s: timelines.%s: page, slug and a login (its own or the config's) go together", configFile, name)
	}
	return status.NewPage(tc.Page, tc.Slug, tc.Login, nil), nil
}

// writeTimeline puts message m, relay seq seq in direction dir on the
// channel, on the peer's collaboration page. It is the last step after the
// message's birth or commit and never reaches the message path: a failure
// is logged, and the peer's page is left alone for the rest of the round.
// The write is create-only (status.Page.Create), so a message written
// before — a spool replay, another host — is a no-op.
func (p *party) writeTimeline(ctx context.Context, name, channel, dir string, seq int64, m *session.Message) {
	log := p.timelineLog()
	if p.tl.refused[name] {
		return
	}
	page, err := p.timelinePage(name)
	if page == nil && err == nil {
		return
	}
	var rec *timeline.Record
	if err == nil {
		rec, err = timeline.Of(dir, m)
	}
	if err == nil {
		_, err = page.Create(ctx, timeline.Key(channel, dir, seq), timeline.Schema, rec)
	}
	if err != nil {
		p.tl.refused[name] = true
		fmt.Fprintf(log, "timeline %s: %s %s: %v; no more timeline writes for %s this round\n", name, dir, m.ID, err, name)
	}
}

// timelineSpooled writes the timeline record of a spooled message born by a
// spool replay, the cut tail of an earlier round; body is the entry's
// plaintext as the spool holds it.
func (sv *server) timelineSpooled(ctx context.Context, e *store.Entry, body []byte) {
	m, err := session.UnmarshalMessage(body)
	if err != nil {
		return
	}
	r, err := roster.Load(ctx, sv.p.backend)
	if err != nil {
		fmt.Fprintf(sv.p.timelineLog(), "timeline: %v\n", err)
		return
	}
	if pe := r.ByChannel(e.Channel); pe != nil {
		sv.p.writeTimeline(ctx, pe.Name, e.Channel, timeline.In, e.Seq, m)
	}
}

// pendingTimeline is a sent message's timeline write waiting for its seq.
type pendingTimeline struct {
	Peer    string           `json:"peer"`
	Channel string           `json:"channel"`
	Message *session.Message `json:"message"`
}

func (p *party) pendingPath(id string) string {
	return filepath.Join(p.dir, timelinePendingDir, id+".json")
}

// timelinePending keeps a committed message whose put failed for the outbox
// replay that puts it (timelineSent); only for a peer with a timeline.
func (p *party) timelinePending(pe *roster.Peer, m *session.Message) {
	if _, ok := p.cfg.Timelines[pe.Name]; !ok || !deliver.ValidID(m.ID) {
		return
	}
	b, err := json.Marshal(pendingTimeline{Peer: pe.Name, Channel: pe.Channel, Message: m})
	if err == nil {
		err = os.MkdirAll(filepath.Join(p.dir, timelinePendingDir), 0o700)
	}
	if err == nil {
		err = os.WriteFile(p.pendingPath(m.ID), b, 0o600)
	}
	if err != nil {
		fmt.Fprintf(p.timelineLog(), "timeline %s: out %s: not kept for the replay: %v\n", pe.Name, m.ID, err)
	}
}

// timelineSent is the outbox replay's word that the relay took message id
// under seq: a pending timeline record for it is written now, once.
func (p *party) timelineSent(ctx context.Context, id string, seq int64) {
	if !deliver.ValidID(id) {
		return
	}
	path := p.pendingPath(id)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var pt pendingTimeline
	if err == nil {
		err = json.Unmarshal(b, &pt)
	}
	if err == nil && pt.Message == nil {
		err = errors.New("no message")
	}
	if err != nil {
		fmt.Fprintf(p.timelineLog(), "timeline: out %s: %v\n", id, err)
	} else {
		p.writeTimeline(ctx, pt.Peer, pt.Channel, timeline.Out, seq, pt.Message)
	}
	os.Remove(path)
}
