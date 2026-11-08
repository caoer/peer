// Package feedtest is an in-process PeerFeed Object (peer worker
// src/feed.ts) for the host side's tests: the hello check against a source
// secret and reader tokens, the fan-out of a source's records to every
// viewer with its ack, the replay request a viewer's connect sends every
// source with its key, and the frames addressed to one viewer. It serves
// GET /feed/<party id> alone; the config routes are the worker's own.
package feedtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/coder/websocket"
)

// Hash is a secret or token as the Object stores it.
func Hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Server is one party's fake feed.
type Server struct {
	*httptest.Server
	party   string
	source  string // the source secret's hash
	readers map[string]bool

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

// Start serves a feed for party admitting the source secret and the reader
// tokens, over TLS as the worker is; Client() is the client that trusts it.
func Start(t testing.TB, party, secret string, tokens ...string) *Server {
	t.Helper()
	s := &Server{party: party, source: Hash(secret), readers: map[string]bool{}, sources: map[*conn]bool{}, viewers: map[*conn]bool{}}
	for _, tok := range tokens {
		s.readers[Hash(tok)] = true
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
	case hello.Hello == "source" && Hash(hello.Secret) == s.source && hello.Host != "":
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
