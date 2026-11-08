// Package feedtest is an in-process PeerFeed Object (peer worker
// src/feed.ts) for the host side's tests: the hello check against a source
// secret and reader tokens, the fan-out of a source's records to every
// viewer with its ack, the replay request a viewer's connect sends every
// source with its key, the frames addressed to one viewer, and the signed
// config at /feed/<party id>/config — verified as the worker verifies it,
// the card under the party id and the body under the card's current
// identity key.
package feedtest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.mau.fi/libsignal/ecc"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
)

// Hash is a secret or token as the Object stores it.
func Hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Held is the config the Object holds, as GET answers it.
type Held struct {
	V       int      `json:"v"`
	Party   string   `json:"party"`
	At      string   `json:"at"`
	Source  string   `json:"source"`
	Readers []string `json:"readers"`
}

// Server is one party's fake feed.
type Server struct {
	*httptest.Server
	party   string
	source  string // the source secret's hash; "" until a config is put
	readers map[string]bool
	at      string // the held config's at; "" until one is put

	mu      sync.Mutex
	sources map[*conn]bool
	viewers map[*conn]bool
	// Frames is every frame a source sent, in order, by host.
	frames []Frame
	// closes counts the sockets closed for a bad hello.
	refused int
	nextID  int
	// noAck withholds the ack of every rec, as a frame lost on the way does.
	noAck bool
	puts  int
}

// NoAck makes the Object take records without acking them, or acks again.
func (s *Server) NoAck(off bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noAck = off
}

// Frame is one frame a source sent, as the Object saw it.
type Frame struct {
	Host string
	Body json.RawMessage
}

type conn struct {
	ws   *websocket.Conn
	id   string
	host string
}

// Start serves a feed for party, over TLS as the worker is; Client() is the
// client that trusts it. A secret seeds the config as a PUT would — the
// source secret and the reader tokens admitted — so a test needs no setup;
// "" starts with no config, as a party's feed is before peer feed setup.
func Start(t testing.TB, party, secret string, tokens ...string) *Server {
	t.Helper()
	s := &Server{party: party, readers: map[string]bool{}, sources: map[*conn]bool{}, viewers: map[*conn]bool{}}
	if secret != "" {
		s.source, s.at = Hash(secret), "1970-01-01T00:00:00Z"
		for _, tok := range tokens {
			s.readers[Hash(tok)] = true
		}
	}
	s.Server = httptest.NewTLSServer(s)
	t.Cleanup(s.Close)
	return s
}

// Frames is every frame the sources sent so far.
func (s *Server) Frames() []Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Frame(nil), s.frames...)
}

// Refused is how many hellos were closed 4401.
func (s *Server) Refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

// Sources is how many source sockets are open.
func (s *Server) Sources() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sources)
}

// Puts is how many configs were taken.
func (s *Server) Puts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

// Config is the config held, nil before the first PUT.
func (s *Server) Config() *Held {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held()
}

func (s *Server) held() *Held {
	if s.source == "" {
		return nil
	}
	h := &Held{V: 1, Party: s.party, At: s.at, Source: s.source, Readers: []string{}}
	for r := range s.readers {
		h.Readers = append(h.Readers, r)
	}
	return h
}

// CloseSources closes every source socket with 1001, as a deploy does.
func (s *Server) CloseSources() {
	s.mu.Lock()
	var open []*conn
	for c := range s.sources {
		open = append(open, c)
		delete(s.sources, c)
	}
	s.mu.Unlock()
	for _, c := range open {
		c.ws.Close(websocket.StatusGoingAway, "deploy")
	}
}

// Viewer is a connected reader page: the frames it received come on Frames.
type Viewer struct {
	ws     *websocket.Conn
	Frames chan json.RawMessage
}

// Connect opens a viewer with token and, when key is not "", the reader key
// its page holds; the hello's answer is returned.
func (s *Server) Connect(ctx context.Context, token, key string) (*Viewer, json.RawMessage, error) {
	ws, _, err := websocket.Dial(ctx, s.URL+"/feed/"+s.party, &websocket.DialOptions{HTTPClient: s.Client()})
	if err != nil {
		return nil, nil, err
	}
	hello := map[string]string{"hello": "viewer", "token": token}
	if key != "" {
		hello["key"] = key
	}
	b, _ := json.Marshal(hello)
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		ws.CloseNow()
		return nil, nil, err
	}
	_, answer, err := ws.Read(ctx)
	if err != nil {
		ws.CloseNow()
		return nil, nil, err
	}
	v := &Viewer{ws: ws, Frames: make(chan json.RawMessage, 256)}
	go func() {
		defer close(v.Frames)
		for {
			_, f, err := ws.Read(context.Background())
			if err != nil {
				return
			}
			v.Frames <- f
		}
	}()
	return v, answer, nil
}

// Close ends the viewer.
func (v *Viewer) Close() { v.ws.CloseNow() }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/feed/"+s.party+"/config" {
		s.serveConfig(w, r)
		return
	}
	if r.URL.Path != "/feed/"+s.party || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, `{"error":"no such route","code":"no_such_route"}`, http.StatusNotFound)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ctx := r.Context()
	defer ws.CloseNow()
	_, b, err := ws.Read(ctx)
	if err != nil {
		return
	}
	var hello struct {
		Hello, Secret, Host, Token, Key string
	}
	if json.Unmarshal(b, &hello) != nil {
		ws.Close(1007, "not JSON")
		return
	}
	s.mu.Lock()
	s.nextID++
	c := &conn{ws: ws, id: hexID(s.nextID), host: hello.Host}
	switch {
	case hello.Hello == "source" && s.source != "" && Hash(hello.Secret) == s.source && hello.Host != "":
		s.sources[c] = true
		n := len(s.sources)
		s.mu.Unlock()
		s.send(ws, map[string]any{"ok": true, "sources": n})
		s.serveSource(ctx, c)
	case hello.Hello == "viewer" && s.readers[Hash(hello.Token)]:
		s.viewers[c] = true
		n := len(s.sources)
		var sources []*conn
		for sc := range s.sources {
			sources = append(sources, sc)
		}
		s.mu.Unlock()
		s.send(ws, map[string]any{"ok": true, "sources": n})
		replay := map[string]any{"viewer": c.id, "reader": Hash(hello.Token)}
		if hello.Key != "" {
			replay["key"] = hello.Key
		}
		for _, sc := range sources {
			s.send(sc.ws, map[string]any{"replay": replay})
		}
		s.serveViewer(ctx, c)
	default:
		s.refused++
		s.mu.Unlock()
		ws.Close(4401, "bad_token")
	}
}

// The config routes, as src/feed.ts and src/sign.ts answer them.
const (
	configMax = 16 << 10
	maxSkew   = 5 * time.Minute
)

var hashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": code})
}

// serveConfig is PUT and GET /feed/<party id>/config: the card under the
// party id, the signature under the card's current identity key — over the
// body for a PUT, over X-Peer-At for a GET.
func (s *Server) serveConfig(w http.ResponseWriter, r *http.Request) {
	cardHdr, sig := r.Header.Get("X-Peer-Card"), r.Header.Get("X-Peer-Signature")
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, configMax+1))
		if err != nil || len(body) > configMax {
			fail(w, http.StatusRequestEntityTooLarge, "too_large", "a feed config is one JSON object of hashes")
			return
		}
		var c Held
		if err := json.Unmarshal(body, &c); err != nil {
			fail(w, http.StatusBadRequest, "bad_request", "config is not JSON")
			return
		}
		if c.V != 1 || c.Party != s.party || !hashRE.MatchString(c.Source) || c.Readers == nil || len(c.Readers) > 64 {
			fail(w, http.StatusBadRequest, "bad_request", `config is {"v":1,"party":"<this party id>","at":"<RFC 3339 UTC>","source":"sha256:<hex>","readers":["sha256:<hex>",…]}`)
			return
		}
		for _, h := range c.Readers {
			if !hashRE.MatchString(h) {
				fail(w, http.StatusBadRequest, "bad_request", "a reader is sha256:<hex>")
				return
			}
		}
		if err := s.refuse(cardHdr, sig, body); err != nil {
			fail(w, http.StatusUnauthorized, err.code, err.Error())
			return
		}
		at, err := time.Parse(time.RFC3339Nano, c.At)
		if err != nil || !strings.HasSuffix(c.At, "Z") || at.Sub(time.Now()).Abs() > maxSkew {
			fail(w, http.StatusUnauthorized, "stale", "at must be RFC 3339 UTC within 5 minutes of now")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.at != "" {
			held, _ := time.Parse(time.RFC3339Nano, s.at)
			if !at.After(held) {
				fail(w, http.StatusConflict, "stale", "an equal or newer config is held")
				return
			}
		}
		s.source, s.at, s.readers, s.puts = c.Source, c.At, map[string]bool{}, s.puts+1
		for _, h := range c.Readers {
			s.readers[h] = true
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "at": c.At, "readers": len(s.readers)})
	case http.MethodGet:
		at := r.Header.Get("X-Peer-At")
		if at == "" || sig == "" {
			fail(w, http.StatusUnauthorized, "bad_signature", "reading the config takes X-Peer-At and X-Peer-Signature")
			return
		}
		if err := s.refuse(cardHdr, sig, []byte(at)); err != nil {
			fail(w, http.StatusUnauthorized, err.code, err.Error())
			return
		}
		if t, err := time.Parse(time.RFC3339Nano, at); err != nil || !strings.HasSuffix(at, "Z") || t.Sub(time.Now()).Abs() > maxSkew {
			fail(w, http.StatusUnauthorized, "stale", "X-Peer-At must be RFC 3339 UTC within 5 minutes of now")
			return
		}
		s.mu.Lock()
		h := s.held()
		s.mu.Unlock()
		if h == nil {
			fail(w, http.StatusNotFound, "no_config", "this party has no feed config yet")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(h)
	default:
		fail(w, http.StatusMethodNotAllowed, "method_not_allowed", "PUT or GET")
	}
}

// refusal is why a request's delegation does not hold, with the worker's code.
type refusal struct {
	code string
	err  error
}

func (r *refusal) Error() string { return r.err.Error() }

func (s *Server) refuse(cardHdr, sig string, msg []byte) *refusal {
	err := Verify(s.party, cardHdr, sig, msg)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrCard):
		return &refusal{"bad_card", err}
	}
	return &refusal{"bad_signature", err}
}

// Errors Verify returns, matched by the worker's codes.
var (
	// ErrCard is a missing X-Peer-Card, one that does not decode, or a card
	// the party id did not sign.
	ErrCard = errors.New("X-Peer-Card is not this party's root-signed card")
	// ErrSignature is a signature the card's current identity key did not make.
	ErrSignature = errors.New("X-Peer-Signature is not the card's identity key's signature")
)

// Verify is the check the worker makes on a config request: cardHdr
// (X-Peer-Card: base64url of signature ‖ card bytes) is party's root-signed
// card, and sig (X-Peer-Signature, base64url) is the XEdDSA signature of msg
// by the card's current identity key — the first key with no until. A
// signature by the root key, by another identity key, or under another
// party's card is refused.
func Verify(party, cardHdr, sig string, msg []byte) error {
	root, err := keys.ParsePartyID(party)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCard, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cardHdr)
	if err != nil || len(raw) <= ed25519.SignatureSize {
		return ErrCard
	}
	c, err := card.Verify(&card.Signed{Sig: raw[:ed25519.SignatureSize], Body: raw[ed25519.SignatureSize:]}, root)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCard, err)
	}
	var current *card.Key
	for i := range c.Keys {
		if c.Keys[i].Until == nil {
			current = &c.Keys[i]
			break
		}
	}
	if current == nil {
		return fmt.Errorf("%w: no current key", ErrCard)
	}
	idk, err := current.IdentityKey()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCard, err)
	}
	sb, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(sb) != 64 {
		return ErrSignature
	}
	var s [64]byte
	copy(s[:], sb)
	if !ecc.VerifySignature(idk.PublicKey(), msg, s) {
		return ErrSignature
	}
	return nil
}

func hexID(n int) string { return hex.EncodeToString([]byte{byte(n >> 8), byte(n)}) }

func (s *Server) send(ws *websocket.Conn, v any) {
	b, _ := json.Marshal(v)
	ws.Write(context.Background(), websocket.MessageText, b)
}

// serveSource takes a source's frames: a rec fans out to every viewer and is
// acked; a rec with to, or a replay_done, goes to that viewer alone.
func (s *Server) serveSource(ctx context.Context, c *conn) {
	defer func() {
		s.mu.Lock()
		delete(s.sources, c)
		s.mu.Unlock()
	}()
	for {
		_, b, err := c.ws.Read(ctx)
		if err != nil {
			return
		}
		if string(b) == "ping" {
			c.ws.Write(ctx, websocket.MessageText, []byte("pong"))
			continue
		}
		var f struct {
			Rec        json.RawMessage `json:"rec"`
			N          *int64          `json:"n"`
			To         string          `json:"to"`
			ReplayDone string          `json:"replay_done"`
		}
		if json.Unmarshal(b, &f) != nil {
			continue
		}
		s.mu.Lock()
		s.frames = append(s.frames, Frame{Host: c.host, Body: append(json.RawMessage(nil), b...)})
		ack := !s.noAck
		var to []*conn
		switch {
		case f.ReplayDone != "":
			to = s.viewerByID(f.ReplayDone)
		case f.Rec != nil && f.To != "":
			to = s.viewerByID(f.To)
		case f.Rec != nil:
			for v := range s.viewers {
				to = append(to, v)
			}
		}
		s.mu.Unlock()
		if f.Rec != nil && f.To == "" {
			out, _ := json.Marshal(map[string]json.RawMessage{"rec": f.Rec})
			for _, v := range to {
				v.ws.Write(ctx, websocket.MessageText, out)
			}
			if f.N != nil && ack {
				s.send(c.ws, map[string]int64{"ack": *f.N})
			}
			continue
		}
		for _, v := range to {
			v.ws.Write(ctx, websocket.MessageText, b)
		}
	}
}

func (s *Server) viewerByID(id string) []*conn {
	for v := range s.viewers {
		if v.id == id {
			return []*conn{v}
		}
	}
	return nil
}

// serveViewer holds a viewer's socket open; a viewer only listens.
func (s *Server) serveViewer(ctx context.Context, c *conn) {
	defer func() {
		s.mu.Lock()
		delete(s.viewers, c)
		s.mu.Unlock()
	}()
	for {
		_, b, err := c.ws.Read(ctx)
		if err != nil {
			return
		}
		if string(b) == "ping" {
			c.ws.Write(ctx, websocket.MessageText, []byte("pong"))
		}
	}
}
