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
	"slices"
	"sort"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/seats"
	"github.com/caoer/peer/internal/session"
)

// A service row's delivery is a callback (UCC design v2 § 5 § Address;
// design §3.5): an HTTPS POST of the record to the row's URL. A 2xx is the
// delivery. Any other answer, or none, puts the message in this host's retry
// queue, <dir>/service/<id>.json, which every round tries once more — per
// entry, the channel's cursor already past it, so a dead URL never stalls the
// messages behind it. After ucc.serviceRetries retries the message becomes a
// local quarantine record, <deliver>/quarantine/<id>.md, naming the URL and
// the last error, and leaves the queue.
//
// There is no signature in this version: the URL is the service's secret,
// and verified: true says peer verified the sender.

const (
	serviceDir            = "service"
	defaultServiceRetries = 20
)

// serviceTimeout bounds one POST; a variable so a test's dead URL fails fast.
var serviceTimeout = 10 * time.Second

// serviceClient follows no redirect: a 3xx is not a delivery.
var serviceClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// servicePost is the POST body: the record's five keys and its body.
type servicePost struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Kind     string `json:"kind"`
	Verified bool   `json:"verified"`
	At       string `json:"at"`
	Body     string `json:"body"`
}

// serviceEntry is one message in the retry queue: the spooled message as
// birth received it, the URL it goes to and the failures so far.
type serviceEntry struct {
	URL      string          `json:"url"`
	Message  json.RawMessage `json:"message"`
	Failures int             `json:"failures"`
	Last     string          `json:"last"`
}

// serviceRow is the message's row when it is a service row.
func (sv *server) serviceRow(m *session.Message) (seats.Row, bool) {
	row, err := sv.seatRow(m.To)
	return row, err == nil && row.Kind == seats.Service
}

// toService delivers m to its service row. A kind the row accepts is posted
// — a doc or file as its descriptor and content line, the content staying
// on this host; any other kind is never posted and becomes a local
// quarantine record. A failed POST is queued, not returned: the cursor moves
// on and the queue retries it.
func (sv *server) toService(row seats.Row, m *session.Message, raw []byte) error {
	if !slices.Contains(row.Accepts, m.Kind) {
		return sv.quarantineLocal(m, fmt.Sprintf("not posted to %s: %s is not a kind the row accepts", row.URL, m.Kind))
	}
	err := postService(row.URL, m)
	if err == nil {
		return sv.posted(row.URL, m)
	}
	return sv.serviceFailed(&serviceEntry{URL: row.URL, Message: raw}, m, err)
}

// posted reports m delivered to u. A doc or file whose content serve did not
// fetch is also born as a local quarantine record: the body posted names
// peer fetch <id> as its retry, and peer fetch reads the descriptor there.
func (sv *server) posted(u string, m *session.Message) error {
	fmt.Fprintf(sv.out, "delivered %s %s → %s\n", m.Kind, m.ID, u)
	if !isAttachment(m.Kind) || contentFetched(m.Body) {
		return nil
	}
	return sv.quarantineLocal(m, fmt.Sprintf("content not fetched; the record was posted to %s", u))
}

// retryServices tries every queued message once, in id order. A URL whose
// POST fails is not tried again in the round: the rest of its queue waits
// for the next round, failure counts unchanged, so a URL that never answers
// holds the round for one timeout, not one per message.
func (sv *server) retryServices() {
	dir := filepath.Join(sv.p.dir, serviceDir)
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		fmt.Fprintf(sv.out, "service queue: %v\n", err)
		return
	}
	sort.Strings(names)
	failed := map[string]bool{}
	for _, n := range names {
		var e serviceEntry
		b, err := os.ReadFile(n)
		if err == nil {
			err = json.Unmarshal(b, &e)
		}
		var m *session.Message
		if err == nil {
			m, err = session.UnmarshalMessage(e.Message)
		}
		if err != nil {
			fmt.Fprintf(sv.out, "service queue %s: %v\n", filepath.Base(n), err)
			continue
		}
		if failed[e.URL] {
			continue
		}
		if err := postService(e.URL, m); err != nil {
			failed[e.URL] = true
			if err := sv.serviceFailed(&e, m, err); err != nil {
				fmt.Fprintf(sv.out, "service queue %s: %v\n", m.ID, err)
			}
			continue
		}
		if err := sv.posted(e.URL, m); err != nil {
			// The entry stays: the next round posts it again and births its record.
			fmt.Fprintf(sv.out, "service queue %s: %v\n", m.ID, err)
			continue
		}
		if err := os.Remove(n); err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(sv.out, "service queue %s: %v\n", m.ID, err)
		}
	}
}

// serviceFailed counts a failed POST: queued for the next round while
// retries remain, else the local quarantine record and out of the queue.
func (sv *server) serviceFailed(e *serviceEntry, m *session.Message, cause error) error {
	e.Failures++
	e.Last = cause.Error()
	path := filepath.Join(sv.p.dir, serviceDir, m.ID+".json")
	if retries := sv.serviceRetries(); e.Failures <= retries {
		fmt.Fprintf(sv.out, "%s %s → %s: %v; retry %d of %d next round\n", m.Kind, m.ID, e.URL, cause, e.Failures, retries)
		return writeServiceEntry(path, e)
	}
	if err := sv.quarantineLocal(m, fmt.Sprintf("not delivered to %s: %s", e.URL, e.Last)); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (sv *server) serviceRetries() int {
	if n := sv.p.cfg.UCC.ServiceRetries; n > 0 {
		return n
	}
	return defaultServiceRetries
}

// quarantineLocal births m in the local delivery directory's quarantine:
// its body first — a doc or file's descriptor where peer fetch reads it —
// then a blank line and the reason.
func (sv *server) quarantineLocal(m *session.Message, reason string) error {
	body := fmt.Appendf(nil, "%s\n\n%s\n", bytes.TrimSuffix(m.Body, []byte("\n")), reason)
	path, _, err := deliver.Write(sv.dir, deliver.Quarantine, m.ID, deliver.Record{From: m.From, To: m.To, Kind: m.Kind, At: m.At, Body: body})
	if err != nil {
		return err
	}
	fmt.Fprintf(sv.out, "quarantined %s %s → %s: %s\n", m.Kind, m.ID, path, reason)
	return nil
}

// postService is one POST of m's record to u.
func postService(u string, m *session.Message) error {
	pu, err := url.Parse(u)
	if err != nil || pu.Scheme != "https" {
		return fmt.Errorf("%q is not an https URL", u)
	}
	b, err := json.Marshal(servicePost{
		From: m.From, To: m.To, Kind: m.Kind, Verified: true,
		At: m.At.UTC().Format(time.RFC3339Nano), Body: string(m.Body),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := serviceClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("answered %s", resp.Status)
	}
	return nil
}

// writeServiceEntry lands e whole: a temp file, synced, renamed over path.
func writeServiceEntry(path string, e *serviceEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
