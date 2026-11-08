package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/timeline"
)

// A channel's messages, received and sent, can also go to the worker named
// by forward: an HTTPS POST to <url>/forward with the bearer secret of the
// counterpart's party id and the peer-timeline@1 record in its envelope,
// {"peer": ..., "record": {"schema": ..., "data": {...}}}, so the worker's
// copy reaches a human with no seat in the path. The worker chooses the chat
// by party id; a 204 is its word that it has none for this peer, logged and
// not retried. Any other 2xx is the delivery. Any other answer, or none,
// keeps the record in
// <dir>/forward-pending/<id>.json, which every round tries once more; after
// forwardRetries retries it is dropped with a log line. The inbox record is
// already written by then, so a dead URL costs only the copy.

const (
	forwardPendingDir = "forward-pending"
	forwardRetries    = 20
	// forwardBodyMax bounds the body as it stands in the POST's JSON, which
	// keeps the whole POST under the handler lane's 64 KiB.
	forwardBodyMax = 60000
)

// forwardPost is the POST body: the counterpart's party id and the timeline
// record, marked when its body was cut.
type forwardPost struct {
	Peer   string        `json:"peer"`
	Record forwardRecord `json:"record"`
}

type forwardRecord struct {
	Schema string      `json:"schema"`
	Data   forwardData `json:"data"`
}

type forwardData struct {
	*timeline.Record
	Truncated bool `json:"truncated,omitempty"`
}

// forwardEntry is one record waiting for the next round: the POST's bytes,
// cut once when the message arrived, and the failures so far. The URL is
// read from config each round, so a corrected URL takes the waiting records.
type forwardEntry struct {
	Peer     string          `json:"peer"`
	ID       string          `json:"id"`
	Post     json.RawMessage `json:"post"`
	Failures int             `json:"failures"`
	Last     string          `json:"last"`
}

// cutBody cuts a text body so its JSON form, without the quotes, is at most
// forwardBodyMax bytes, on a rune boundary. Only a text body can be long.
func cutBody(body json.RawMessage) (json.RawMessage, bool) {
	var s string
	if len(body) <= forwardBodyMax+2 || json.Unmarshal(body, &s) != nil {
		return body, false
	}
	n := sort.Search(len(s)+1, func(i int) bool {
		b, _ := json.Marshal(s[:i])
		return len(b)-2 > forwardBodyMax
	}) - 1
	if n == len(s) {
		return body, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	cut, err := json.Marshal(s[:n])
	if err != nil {
		return body, false
	}
	return cut, true
}

// counterpart is the other party of message m in direction dir: the
// sender's party id for a received message, the recipient's for a sent one,
// without the agent.
func counterpart(dir string, m *session.Message) string {
	addr := m.To
	if dir == timeline.In {
		addr = m.From
	}
	party, _, _ := strings.Cut(addr, "/")
	return party
}

// forwardBytes is the POST body of message m in direction dir.
func forwardBytes(dir string, m *session.Message) ([]byte, error) {
	rec, err := timeline.Of(dir, m)
	if err != nil {
		return nil, err
	}
	var cut bool
	rec.Body, cut = cutBody(rec.Body)
	return json.Marshal(forwardPost{Peer: counterpart(dir, m), Record: forwardRecord{Schema: timeline.Schema, Data: forwardData{Record: rec, Truncated: cut}}})
}

// forwardLine is serve's start line: the forward's URL, or off.
func (p *party) forwardLine() string {
	if p.cfg.Forward == nil {
		return "forward: off"
	}
	return "forward: " + p.cfg.Forward.URL
}

// forwardTimeline POSTs message m in direction dir to the forward, if config
// names one. It never reaches the message path. A forward that failed
// earlier in the round is not tried again: the record waits for the next
// round, its failure count unchanged.
func (p *party) forwardTimeline(ctx context.Context, name, dir string, m *session.Message) {
	if p.cfg.Forward == nil {
		return
	}
	u := p.cfg.Forward.URL
	log := p.timelineLog()
	if !deliver.ValidID(m.ID) {
		fmt.Fprintf(log, "forward %s: invalid message id\n", name)
		return
	}
	post, err := forwardBytes(dir, m)
	if err != nil {
		fmt.Fprintf(log, "forward %s: %s: %v\n", name, m.ID, err)
		return
	}
	e := &forwardEntry{Peer: name, ID: m.ID, Post: post}
	if p.tl.deadForward[u] {
		e.Last = "the URL failed earlier this round"
		fmt.Fprintf(log, "forward %s: %s: waits for the next round\n", name, m.ID)
		p.keepForward(e)
		return
	}
	switch err := p.postForward(ctx, post); {
	case errors.Is(err, errNoTarget):
		fmt.Fprintf(log, "forward %s: %s: no target\n", name, m.ID)
	case err != nil:
		p.tl.deadForward[u] = true
		p.forwardFailed(e, err)
	}
}

// retryForwards tries every waiting record once, in id order. A URL whose
// POST fails is not tried again in the round, so one that never answers
// holds the round for one timeout, not one per record.
func (p *party) retryForwards(ctx context.Context) {
	log := p.timelineLog()
	names, err := filepath.Glob(filepath.Join(p.dir, forwardPendingDir, "*.json"))
	if err != nil {
		fmt.Fprintf(log, "forward: %v\n", err)
		return
	}
	sort.Strings(names)
	for _, n := range names {
		var e forwardEntry
		b, err := os.ReadFile(n)
		if err == nil {
			err = json.Unmarshal(b, &e)
		}
		if err == nil && !deliver.ValidID(e.ID) {
			err = errors.New("invalid message id")
		}
		if err != nil {
			fmt.Fprintf(log, "forward: %s: %v\n", filepath.Base(n), err)
			continue
		}
		if p.cfg.Forward == nil {
			fmt.Fprintf(log, "forward %s: %s: no forward in config; dropped\n", e.Peer, e.ID)
			p.dropForward(&e)
			continue
		}
		u := p.cfg.Forward.URL
		if p.tl.deadForward[u] {
			continue
		}
		switch err := p.postForward(ctx, e.Post); {
		case errors.Is(err, errNoTarget):
			fmt.Fprintf(log, "forward %s: %s: no target\n", e.Peer, e.ID)
		case err != nil:
			p.tl.deadForward[u] = true
			p.forwardFailed(&e, err)
			continue
		default:
			fmt.Fprintf(log, "forward %s: %s: delivered after %d failures\n", e.Peer, e.ID, e.Failures)
		}
		p.dropForward(&e)
	}
}

// forwardFailed counts a failed POST: kept for the next round while retries
// remain, else dropped with its log line.
func (p *party) forwardFailed(e *forwardEntry, cause error) {
	log := p.timelineLog()
	e.Failures++
	e.Last = cause.Error()
	if e.Failures <= forwardRetries {
		fmt.Fprintf(log, "forward %s: %s: %v; retry %d of %d next round\n", e.Peer, e.ID, cause, e.Failures, forwardRetries)
		p.keepForward(e)
		return
	}
	fmt.Fprintf(log, "forward %s: %s: %v; dropped after %d retries\n", e.Peer, e.ID, cause, forwardRetries)
	p.dropForward(e)
}

func (p *party) forwardPath(id string) string {
	return filepath.Join(p.dir, forwardPendingDir, id+".json")
}

func (p *party) keepForward(e *forwardEntry) {
	if err := writeEntry(p.forwardPath(e.ID), e); err != nil {
		fmt.Fprintf(p.timelineLog(), "forward %s: %s: not kept for the next round: %v\n", e.Peer, e.ID, err)
	}
}

func (p *party) dropForward(e *forwardEntry) {
	if err := os.Remove(p.forwardPath(e.ID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(p.timelineLog(), "forward %s: %s: %v\n", e.Peer, e.ID, err)
	}
}

// errNoTarget is the worker's 204: it has no chat for this peer.
var errNoTarget = errors.New("no target")

// postForward is one POST of a record to the forward. An error never
// carries the URL or the secret: the error goes to the journal.
func (p *party) postForward(ctx context.Context, post []byte) error {
	u := strings.TrimSuffix(p.cfg.Forward.URL, "/") + "/forward"
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" {
		return errors.New("the forward URL is not an https URL")
	}
	ctx, cancel := context.WithTimeout(ctx, serviceTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(post))
	if err != nil {
		return errors.New("the forward URL does not form a request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.cfg.Forward.Secret)
	resp, err := serviceClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusNoContent:
		return errNoTarget
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("answered %s", resp.Status)
	}
	return nil
}
