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
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/timeline"
)

// forwardConfig is config.json "forward": {"url", "secret"}, the worker
// every message is POSTed to, both directions (forward.go). The worker maps
// the counterpart's party id to a chat; the host never names one. It is
// host-local config: the secret is this host's.
type forwardConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// timelinePendingDir holds, under the peer directory, the timeline record of
// each sent message whose relay put failed after its commit: its relay seq,
// and so its key, is known only once the outbox replay puts it.
const timelinePendingDir = "timeline-pending"

// timelineState is a party's after-delivery work in one round — a serve
// round or one peer send: where it logs, and the forward URLs whose POST
// failed in the round.
type timelineState struct {
	log         io.Writer
	deadForward map[string]bool
}

// timelineRound starts a round of timeline writes logging to log.
func (p *party) timelineRound(log io.Writer) {
	p.tl = &timelineState{log: log, deadForward: map[string]bool{}}
}

func (p *party) timelineLog() io.Writer {
	if p.tl == nil {
		p.timelineRound(os.Stderr)
	}
	return p.tl.log
}

// writeTimeline is the last step after a message's birth or commit, under
// its relay seq in direction dir on the channel: its forward, either way,
// then the feed — a sent message's local record and the frame to the party's
// reader pages (feedrecord.go). It never reaches the message path.
func (p *party) writeTimeline(ctx context.Context, name, channel, dir string, seq int64, m *session.Message) {
	p.forwardTimeline(ctx, name, dir, m)
	p.feedTimeline(ctx, name, dir, seq, m)
}

// timelineSpooled runs writeTimeline for a spooled message born by a
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

// pendingTimeline is a sent message's writeTimeline waiting for its seq.
type pendingTimeline struct {
	Peer    string           `json:"peer"`
	Channel string           `json:"channel"`
	Message *session.Message `json:"message"`
}

func (p *party) pendingPath(id string) string {
	return filepath.Join(p.dir, timelinePendingDir, id+".json")
}

// timelinePending keeps a committed message whose put failed for the outbox
// replay that puts it (timelineSent).
func (p *party) timelinePending(pe *roster.Peer, m *session.Message) {
	if !deliver.ValidID(m.ID) {
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
// under seq: writeTimeline runs for its pending message now, once.
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
