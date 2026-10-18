// Package pages is the fleet's store backend: each record is one ccc-pages
// /d/ data record on the party's private state page (UCC design v2 § 5
// commitment 5) — `GET /d/<slug>/<key>` and `PUT /d/<slug>/<key>?v=<n>`
// with the owner Bearer, the bytes base64 once in the envelope's data string
// under Schema, the 256 KiB cap on the envelope. The bytes it carries are
// sealed by store.Sealed; this package never holds a plaintext record.
package pages

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caoer/peer/internal/httpx"
	"github.com/caoer/peer/internal/store"
)

// Schema is the K7 schema id of a peer store record.
const Schema = "peer-store@1"

// MaxEnvelope is /d/'s cap on the UTF-8 bytes of {"schema","data"}.
const MaxEnvelope = 256 * 1024

// Error is a /d/ refusal: the status and the body's code and message.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("pages: %d %s: %s", e.Status, e.Code, e.Message) }

// Backend is one state page's /d/ store.
type Backend struct {
	base, slug, bearer string
	client             *http.Client
}

// Timeout bounds one record's request when New is given no client of its
// own, as the relay client's does: a page that takes the connection and
// never answers would otherwise hang a serve loop with no log line, which
// reads exactly like a quiet channel.
const Timeout = 60 * time.Second

// New opens the store of the page slug on the ccc-pages service at base
// (https://page.sui.pics) with the owner login `<user>:<token>` as the
// Bearer; a nil client is one with Timeout.
func New(base, slug, bearer string, client *http.Client) *Backend {
	if client == nil {
		client = &http.Client{Timeout: Timeout, Transport: httpx.Transport}
	}
	return &Backend{base: strings.TrimRight(base, "/"), slug: slug, bearer: bearer, client: client}
}

type envelope struct {
	Schema string `json:"schema"`
	Data   string `json:"data"`
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

func (b *Backend) url(key string) string { return b.base + "/d/" + b.slug + "/" + key }

func (b *Backend) do(ctx context.Context, method, url string, body []byte) (int, answer, error) {
	var a answer
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, a, err
	}
	req.Header.Set("Authorization", "Bearer "+b.bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := b.client.Do(req)
	if err != nil {
		return 0, a, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return 0, a, err
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return res.StatusCode, a, fmt.Errorf("pages: %s %s: status %d, body is not JSON", method, url, res.StatusCode)
	}
	return res.StatusCode, a, nil
}

// Load reads the record; an absent key is nil, 0, nil.
func (b *Backend) Load(ctx context.Context, key string) ([]byte, int64, error) {
	if !store.ValidKey(key) {
		return nil, 0, fmt.Errorf("pages: %q is not a record key", key)
	}
	status, a, err := b.do(ctx, http.MethodGet, b.url(key), nil)
	if err != nil {
		return nil, 0, err
	}
	switch {
	case status == http.StatusOK:
	case status == http.StatusNotFound && a.Code == "no_such_object":
		return nil, 0, nil
	default:
		return nil, 0, &Error{Status: status, Code: a.Code, Message: a.Error}
	}
	if a.Value == nil || a.Value.Schema != Schema {
		return nil, 0, fmt.Errorf("%w: %s: not a %s record", store.ErrCorrupt, key, Schema)
	}
	var s string
	if err := json.Unmarshal(a.Value.Data, &s); err != nil {
		return nil, 0, fmt.Errorf("%w: %s: data is not a string", store.ErrCorrupt, key)
	}
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %s: data is not base64", store.ErrCorrupt, key)
	}
	return data, a.Version, nil
}

// Store writes the record under CAS; an envelope over MaxEnvelope, here or
// at the page, is ErrTooLarge.
func (b *Backend) Store(ctx context.Context, key string, data []byte, expect int64) (int64, error) {
	if !store.ValidKey(key) {
		return 0, fmt.Errorf("pages: %q is not a record key", key)
	}
	body, err := json.Marshal(envelope{Schema: Schema, Data: base64.StdEncoding.EncodeToString(data)})
	if err != nil {
		return 0, err
	}
	if len(body) > MaxEnvelope {
		return 0, fmt.Errorf("%w: %s: envelope %d bytes, cap %d", store.ErrTooLarge, key, len(body), MaxEnvelope)
	}
	status, a, err := b.do(ctx, http.MethodPut, b.url(key)+"?v="+strconv.FormatInt(expect, 10), body)
	if err != nil {
		return 0, err
	}
	switch {
	case status == http.StatusOK:
		return a.Version, nil
	case status == http.StatusConflict && a.Code == "version_conflict":
		return 0, &store.ConflictError{Key: key, Expected: expect, Found: a.Version}
	case status == http.StatusRequestEntityTooLarge:
		return 0, fmt.Errorf("%w: %s: %s", store.ErrTooLarge, key, a.Error)
	}
	return 0, &Error{Status: status, Code: a.Code, Message: a.Error}
}
