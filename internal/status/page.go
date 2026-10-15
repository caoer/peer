package status

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RowSchema is the K7 schema id of a roster page record.
const RowSchema = "peer-roster@1"

// StaleBeats is the heartbeat rule: a row not written for more than this
// many beats reads stale — the serve that kept it is gone.
const StaleBeats = 3

// ActiveWindow is how long a peer counts as active after its last message:
// the relay's retention, past which what it sent is gone unread anyway.
const ActiveWindow = 30 * 24 * time.Hour

// RowKey is a peer's roster page key: "peer." and the root public key in
// lowercase hex. The party id itself ("ed25519:" + base64url) carries a colon
// and capitals, which a /d/ key cannot.
func RowKey(root ed25519.PublicKey) string { return "peer." + hex.EncodeToString(root) }

// Row is one peer's roster page record, plaintext on a private page. It
// names the peer and the channel, never the host that wrote it, the login or
// any local id (design §3.6).
type Row struct {
	Name    string `json:"name"`
	Party   string `json:"party"`
	Channel string `json:"channel"`
	Side    string `json:"side"`
	State   string `json:"state"`
	// LastAt and LastKind are the peer's last message, null and "" before one.
	LastAt   *time.Time `json:"lastAt"`
	LastKind string     `json:"lastKind"`
	Unread   int        `json:"unread"`
	// Active: the channel has a session and the peer sent within ActiveWindow.
	Active bool `json:"active"`
	// Beat is the serve interval in seconds; At this write's time.
	Beat int64     `json:"beat"`
	At   time.Time `json:"at"`
}

// Stale reports whether the row outlived its heartbeat: now − at > 3 × beat.
func (r *Row) Stale(now time.Time) bool {
	return now.Sub(r.At) > StaleBeats*time.Duration(r.Beat)*time.Second
}

// Error is a /d/ refusal: the status and the body's code and message.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("/d/ %d %s: %s", e.Status, e.Code, e.Message) }

// Timeout bounds one request when NewPage is given no client.
const Timeout = 30 * time.Second

// Page is the roster page's /d/ store: plaintext rows under RowSchema, CAS
// by ?v= with the owner Bearer. It remembers the version it last read or
// wrote per key — the first write of a key reads it — so a round's write is
// one PUT; a conflict, another host's write in between, is retried once at
// the version the refusal names.
type Page struct {
	base, slug, bearer string
	client             *http.Client

	mu       sync.Mutex
	versions map[string]int64
}

// NewPage opens the page slug on the ccc-pages service at base with the
// owner login "<user>:<token>"; a nil client is one with Timeout.
func NewPage(base, slug, bearer string, client *http.Client) *Page {
	if client == nil {
		client = &http.Client{Timeout: Timeout}
	}
	return &Page{base: strings.TrimRight(base, "/"), slug: slug, bearer: bearer, client: client, versions: map[string]int64{}}
}

type answer struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Version int64  `json:"version"`
	Value   *struct {
		Schema string          `json:"schema"`
		Data   json.RawMessage `json:"data"`
	} `json:"value"`
}

func (p *Page) do(ctx context.Context, method, url string, body []byte) (int, answer, error) {
	var a answer
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, a, err
	}
	req.Header.Set("Authorization", "Bearer "+p.bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := p.client.Do(req)
	if err != nil {
		return 0, a, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return 0, a, err
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return res.StatusCode, a, fmt.Errorf("roster page: %s: status %d, body is not JSON", method, res.StatusCode)
	}
	return res.StatusCode, a, nil
}

func (p *Page) url(key string) string { return p.base + "/d/" + p.slug + "/" + key }

// Put writes the row under key.
func (p *Page) Put(ctx context.Context, key string, row *Row) error {
	body, err := json.Marshal(struct {
		Schema string `json:"schema"`
		Data   *Row   `json:"data"`
	}{RowSchema, row})
	if err != nil {
		return err
	}
	p.mu.Lock()
	v, known := p.versions[key]
	p.mu.Unlock()
	if !known {
		// This process has not written the row yet: learn its version, so
		// the write is one PUT and not a refused one and a retry.
		if _, err := p.Get(ctx, key); err != nil {
			return err
		}
		p.mu.Lock()
		v = p.versions[key]
		p.mu.Unlock()
	}
	for try := 0; ; try++ {
		status, a, err := p.do(ctx, http.MethodPut, p.url(key)+"?v="+strconv.FormatInt(v, 10), body)
		if err != nil {
			return err
		}
		switch {
		case status == http.StatusOK:
			p.mu.Lock()
			p.versions[key] = a.Version
			p.mu.Unlock()
			return nil
		case status == http.StatusConflict && a.Code == "version_conflict" && try == 0:
			v = a.Version
			continue
		}
		return &Error{Status: status, Code: a.Code, Message: a.Error}
	}
}

// Get reads the row under key; an absent row is nil, nil.
func (p *Page) Get(ctx context.Context, key string) (*Row, error) {
	status, a, err := p.do(ctx, http.MethodGet, p.url(key), nil)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusOK:
	case status == http.StatusNotFound && a.Code == "no_such_object":
		p.mu.Lock()
		p.versions[key] = 0
		p.mu.Unlock()
		return nil, nil
	default:
		return nil, &Error{Status: status, Code: a.Code, Message: a.Error}
	}
	if a.Value == nil || a.Value.Schema != RowSchema {
		return nil, fmt.Errorf("roster page: %s is not a %s record", key, RowSchema)
	}
	var r Row
	if err := json.Unmarshal(a.Value.Data, &r); err != nil {
		return nil, fmt.Errorf("roster page: %s: %v", key, err)
	}
	p.mu.Lock()
	p.versions[key] = a.Version
	p.mu.Unlock()
	return &r, nil
}
