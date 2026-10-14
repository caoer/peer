// Package relay is the client for the peer relay's wire contract
// (session record results/wire-contract.md): create a channel, join it,
// put and pull envelopes, deposit and take one-time prekeys.
//
// The relay is untrusted: every answer is size-capped and validated, and a
// malformed envelope in a pull comes back as a Record with Err set, so the
// caller can skip it and still advance its cursor.
package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/caoer/peer/internal/envelope"
)

// Contract limits.
const (
	MaxPrekeysPerPut = 100
	maxPage          = 100      // envelopes per pull answer
	maxAnswer        = 8 << 20  // a pull page holds ~4 MiB of body text
	maxSmallAnswer   = 64 << 10 // every other answer
	maxLanding       = 256 << 10
	// MaxBlob is the relay's cap on one blob, in ciphertext bytes (64 MiB).
	MaxBlob = 64 << 20
	// blobTimeout bounds one blob put or get: a whole 64 MiB at 1 MB/s.
	blobTimeout = 2 * time.Minute
)

var (
	blobRE    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	channelRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	tokenRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// ValidChannelID reports whether id has the contract's form (32 lowercase hex).
func ValidChannelID(id string) bool { return channelRE.MatchString(id) }

// ValidToken reports whether t has the contract's form (43-char base64url).
func ValidToken(t string) bool { return tokenRE.MatchString(t) }

// Error is a relay error answer {error, code}.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("relay: %d %s: %s", e.Status, e.Code, e.Message)
}

// Is matches on Code, so errors.Is(err, relay.ErrBadToken) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// The contract's error codes.
var (
	ErrBadToken         = &Error{Status: 401, Code: "bad_token"}
	ErrTokenUsed        = &Error{Status: 409, Code: "token_used"}
	ErrNoSuchChannel    = &Error{Status: 404, Code: "no_such_channel"}
	ErrTooLarge         = &Error{Status: 413, Code: "too_large"}
	ErrBadRequest       = &Error{Status: 400, Code: "bad_request"}
	ErrRateLimited      = &Error{Status: 429, Code: "rate_limited"}
	ErrMethodNotAllowed = &Error{Status: 405, Code: "method_not_allowed"}
	ErrNoSuchRoute      = &Error{Status: 404, Code: "no_such_route"}
	ErrNoSuchBlob       = &Error{Status: 404, Code: "no_such_blob"}
)

// ValidBlobID reports whether id has the contract's blob form (32 lowercase hex).
func ValidBlobID(id string) bool { return blobRE.MatchString(id) }

// ErrAnswer means the relay's answer broke the contract.
var ErrAnswer = errors.New("relay: answer breaks the contract")

// Client speaks to one relay base, e.g. https://example.com/peer.
type Client struct {
	base string
	http *http.Client
}

// New returns a client for base (the card's relay URL, ending in /peer).
// A nil hc uses a client with a 60 s timeout.
func New(base string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{base: strings.TrimRight(base, "/"), http: hc}
}

// Channel is a create answer.
type Channel struct {
	ID          string `json:"id"`
	HostToken   string `json:"hostToken"`
	InviteToken string `json:"inviteToken"`
}

// Create opens a channel; login is the ccc-pages owner login "<user>:<token>".
func (c *Client) Create(ctx context.Context, login string) (Channel, error) {
	var ch Channel
	if err := c.do(ctx, http.MethodPost, "/channels", login, struct{}{}, &ch, maxSmallAnswer); err != nil {
		return Channel{}, err
	}
	if !ValidChannelID(ch.ID) || !ValidToken(ch.HostToken) || !ValidToken(ch.InviteToken) {
		return Channel{}, fmt.Errorf("%w: create answer", ErrAnswer)
	}
	return ch, nil
}

// Join redeems the one-time invite token for this side's guest token.
func (c *Client) Join(ctx context.Context, id, inviteToken string) (string, error) {
	if err := checkIDs(id, inviteToken); err != nil {
		return "", err
	}
	var out struct {
		GuestToken string `json:"guestToken"`
	}
	in := struct {
		InviteToken string `json:"inviteToken"`
	}{inviteToken}
	if err := c.do(ctx, http.MethodPost, "/c/"+id+"/join", "", in, &out, maxSmallAnswer); err != nil {
		return "", err
	}
	if !ValidToken(out.GuestToken) {
		return "", fmt.Errorf("%w: join answer", ErrAnswer)
	}
	return out.GuestToken, nil
}

// Receipt is a put answer: the direction the token names and its sequence.
type Receipt struct {
	Dir string `json:"dir"`
	Seq int64  `json:"seq"`
}

// Put stores one envelope on the caller's side. The envelope is checked
// first; one over 1 MiB never leaves the host.
func (c *Client) Put(ctx context.Context, id, token string, e envelope.Envelope) (Receipt, error) {
	if err := checkIDs(id, token); err != nil {
		return Receipt{}, err
	}
	if err := e.Check(); err != nil {
		return Receipt{}, err
	}
	typ, body := e.Wire()
	in := struct {
		Type string `json:"type"`
		Body string `json:"body"`
	}{typ, body}
	var r Receipt
	if err := c.do(ctx, http.MethodPost, "/c/"+id+"/envelopes", token, in, &r, maxSmallAnswer); err != nil {
		return Receipt{}, err
	}
	if (r.Dir != "h2g" && r.Dir != "g2h") || r.Seq < 0 {
		return Receipt{}, fmt.Errorf("%w: put answer %+v", ErrAnswer, r)
	}
	return r, nil
}

// Record is one pulled envelope. Err is set when the relay's bytes for
// this seq are malformed; Env is then zero and the seq still counts.
type Record struct {
	Seq int64
	At  time.Time
	Env envelope.Envelope
	Err error
}

// Pull returns one page of the other side's envelopes with seq > after
// (after -1 for everything), ascending. An empty page means caught up.
func (c *Client) Pull(ctx context.Context, id, token string, after int64) ([]Record, error) {
	if err := checkIDs(id, token); err != nil {
		return nil, err
	}
	if after < -1 {
		return nil, fmt.Errorf("relay: after %d < -1", after)
	}
	var raw []wireRow
	path := "/c/" + id + "/envelopes?after=" + strconv.FormatInt(after, 10)
	if err := c.do(ctx, http.MethodGet, path, token, nil, &raw, maxAnswer); err != nil {
		return nil, err
	}
	if len(raw) > maxPage {
		return nil, fmt.Errorf("%w: %d envelopes in one page", ErrAnswer, len(raw))
	}
	out := make([]Record, 0, len(raw))
	last := after
	for _, r := range raw {
		if r.Seq == nil || *r.Seq <= last {
			return nil, fmt.Errorf("%w: seq missing, not after %d, or not ascending", ErrAnswer, last)
		}
		last = *r.Seq
		out = append(out, r.record())
	}
	return out, nil
}

// PullAll pulls page after page from after until the relay answers [].
func (c *Client) PullAll(ctx context.Context, id, token string, after int64) ([]Record, error) {
	var all []Record
	for {
		page, err := c.Pull(ctx, id, token, after)
		if err != nil {
			return all, err
		}
		if len(page) == 0 {
			return all, nil
		}
		all = append(all, page...)
		after = page[len(page)-1].Seq
	}
}

// Prekey is a one-time prekey: its id and serialized public key
// (0x05 || 32 bytes); JSON carries pub as standard base64.
type Prekey struct {
	ID  uint32 `json:"id"`
	Pub []byte `json:"pub"`
}

// PutPrekeys appends keys to the caller's side and returns how many that
// side now holds. A repeated id is ignored by the relay, so a retry is safe.
func (c *Client) PutPrekeys(ctx context.Context, id, token string, keys []Prekey) (int, error) {
	if err := checkIDs(id, token); err != nil {
		return 0, err
	}
	if len(keys) == 0 || len(keys) > MaxPrekeysPerPut {
		return 0, fmt.Errorf("relay: %d prekeys in one put, want 1..%d", len(keys), MaxPrekeysPerPut)
	}
	for _, k := range keys {
		if err := envelope.CheckKey(k.Pub); err != nil {
			return 0, fmt.Errorf("prekey %d: %w", k.ID, err)
		}
	}
	in := struct {
		Keys []Prekey `json:"keys"`
	}{keys}
	var out struct {
		Count *int `json:"count"`
	}
	if err := c.do(ctx, http.MethodPut, "/c/"+id+"/prekeys", token, in, &out, maxSmallAnswer); err != nil {
		return 0, err
	}
	if out.Count == nil || *out.Count < 0 {
		return 0, fmt.Errorf("%w: prekeys answer", ErrAnswer)
	}
	return *out.Count, nil
}

// TakePrekey takes the other side's oldest one-time prekey; ok is false
// when that side holds none.
func (c *Client) TakePrekey(ctx context.Context, id, token string) (k Prekey, ok bool, err error) {
	if err := checkIDs(id, token); err != nil {
		return Prekey{}, false, err
	}
	var out struct {
		ID  *uint32 `json:"id"`
		Pub *string `json:"pub"`
	}
	if err := c.do(ctx, http.MethodPost, "/c/"+id+"/prekeys/take", token, struct{}{}, &out, maxSmallAnswer); err != nil {
		return Prekey{}, false, err
	}
	if out.ID == nil && out.Pub == nil {
		return Prekey{}, false, nil
	}
	if out.ID == nil || out.Pub == nil {
		return Prekey{}, false, fmt.Errorf("%w: take answer lacks id or pub", ErrAnswer)
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(*out.Pub)
	if err != nil {
		return Prekey{}, false, fmt.Errorf("%w: take pub: %v", ErrAnswer, err)
	}
	if err := envelope.CheckKey(pub); err != nil {
		return Prekey{}, false, fmt.Errorf("%w: take pub: %v", ErrAnswer, err)
	}
	return Prekey{ID: *out.ID, Pub: pub}, true, nil
}

// Blob is a blob put answer: the id the relay gave it and its size.
type Blob struct {
	ID   string `json:"blob"`
	Size int64  `json:"size"`
}

// PutBlob stores data — an attachment's ciphertext, raw bytes — on the
// channel for the other side to get. One over MaxBlob never leaves the host.
func (c *Client) PutBlob(ctx context.Context, id, token string, data []byte) (Blob, error) {
	if err := checkIDs(id, token); err != nil {
		return Blob{}, err
	}
	if len(data) == 0 || len(data) > MaxBlob {
		return Blob{}, fmt.Errorf("relay: a blob is 1..%d bytes, this one %d: %w", MaxBlob, len(data), ErrTooLarge)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/c/"+id+"/blobs", bytes.NewReader(data))
	if err != nil {
		return Blob{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	b, err := c.send(req, maxSmallAnswer)
	if err != nil {
		return Blob{}, err
	}
	var out Blob
	if err := json.Unmarshal(b, &out); err != nil {
		return Blob{}, fmt.Errorf("%w: %v", ErrAnswer, err)
	}
	if !ValidBlobID(out.ID) || out.Size != int64(len(data)) {
		return Blob{}, fmt.Errorf("%w: blob answer %+v for %d bytes", ErrAnswer, out, len(data))
	}
	return out, nil
}

// GetBlob reads a blob the other side put, whole; at most MaxBlob bytes.
func (c *Client) GetBlob(ctx context.Context, id, token, blob string) ([]byte, error) {
	if err := checkIDs(id, token); err != nil {
		return nil, err
	}
	if !ValidBlobID(blob) {
		return nil, fmt.Errorf("relay: bad blob id %q", blob)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/c/"+id+"/blobs/"+blob, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.send(req, MaxBlob)
}

// send does one blob request and returns a 200 answer's bytes, at most
// limit. A blob takes longer than the client's JSON timeout allows, so it
// runs under blobTimeout instead.
func (c *Client) send(req *http.Request, limit int64) ([]byte, error) {
	hc := *c.http
	hc.Timeout = blobTimeout
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, answerError(resp.StatusCode, b)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: answer over %d bytes", ErrAnswer, limit)
	}
	return b, nil
}

// Landing fetches the invite landing text for a channel.
func (c *Client) Landing(ctx context.Context, id string) (string, error) {
	if !ValidChannelID(id) {
		return "", fmt.Errorf("relay: bad channel id %q", id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/i/"+id, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxLanding+1))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", answerError(resp.StatusCode, b)
	}
	if len(b) > maxLanding {
		return "", fmt.Errorf("%w: landing over %d bytes", ErrAnswer, maxLanding)
	}
	return string(b), nil
}

func checkIDs(id, token string) error {
	if !ValidChannelID(id) {
		return fmt.Errorf("relay: bad channel id %q", id)
	}
	if !ValidToken(token) {
		return errors.New("relay: bad token form")
	}
	return nil
}

// do sends one JSON request and decodes a 200 answer into out.
func (c *Client) do(ctx context.Context, method, path, bearer string, in, out any, limit int64) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return answerError(resp.StatusCode, b)
	}
	if int64(len(b)) > limit {
		return fmt.Errorf("%w: answer over %d bytes", ErrAnswer, limit)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%w: %v", ErrAnswer, err)
	}
	return nil
}

func answerError(status int, b []byte) error {
	var e struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if json.Unmarshal(b, &e) != nil || e.Code == "" {
		msg := string(b)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return &Error{Status: status, Message: msg}
	}
	return &Error{Status: status, Code: e.Code, Message: e.Error}
}
