package relaytest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/coder/websocket"

	"github.com/caoer/peer/internal/relay"
)

// push is the fake's WebSocket push (wire contract § WebSocket push): a
// socket per upgrade, tagged by the dir of the rows it receives.
type push struct {
	socks map[*sock]bool
	// pulls counts the pull GETs per channel and dir pulled ("<id> <dir>").
	pulls map[string]int
	// drop is how many coming pushes are lost, as on a dropped frame.
	drop int
}

type sock struct {
	id, dir string // channel and the dir it receives
	conn    *websocket.Conn
	rows    chan Row
}

// NoPush makes the relay answer an upgrade as the pull, as a relay without
// push does.
func (s *Server) NoPush(off bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noPush = off
}

// CloseSockets closes every open socket with 1001, as a deploy restarting
// the Object does.
func (s *Server) CloseSockets() {
	s.mu.Lock()
	var open []*sock
	for k := range s.push.socks {
		open = append(open, k)
		delete(s.push.socks, k)
	}
	s.mu.Unlock()
	for _, k := range open {
		k.conn.Close(websocket.StatusGoingAway, "deploy")
	}
}

// Sockets is how many sockets are open on channel id receiving dir.
func (s *Server) Sockets(id, dir string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k := range s.push.socks {
		if k.id == id && k.dir == dir {
			n++
		}
	}
	return n
}

// DropPushes loses the next n pushes: the rows are stored, no frame goes out.
func (s *Server) DropPushes(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.push.drop = n
}

// Pulls is how many pull GETs channel id has answered for rows in dir.
func (s *Server) Pulls(id, dir string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.push.pulls[id+" "+dir]
}

// countPull notes one pull answer; s.mu is held.
func (s *Server) countPull(id, dir string) {
	if s.push.pulls == nil {
		s.push.pulls = map[string]int{}
	}
	s.push.pulls[id+" "+dir]++
}

// pushRow sends a stored row to the sockets receiving its dir; s.mu is held.
func (s *Server) pushRow(id, dir string, r Row) {
	if s.push.drop > 0 {
		s.push.drop--
		return
	}
	for k := range s.push.socks {
		if k.id == id && k.dir == dir {
			select {
			case k.rows <- r:
			default: // a socket that cannot keep up loses the frame; the pull has it
			}
		}
	}
}

// upgrade takes a WebSocket upgrade on an envelopes route and reports
// whether it answered; without push it leaves the request to the pull.
func (s *Server) upgrade(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	p := strings.TrimPrefix(r.URL.Path, "/peer/c/")
	id, rest, _ := strings.Cut(p, "/")
	if rest != "envelopes" {
		return false
	}
	s.mu.Lock()
	if s.noPush {
		s.mu.Unlock()
		return false
	}
	ch, found := s.channels[id]
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var dir string
	switch {
	case !found:
		s.mu.Unlock()
		fail(w, relay.ErrNoSuchChannel)
		return true
	case bearer != "" && bearer == ch.host:
		dir = "g2h"
	case bearer != "" && bearer == ch.guest:
		dir = "h2g"
	default:
		s.mu.Unlock()
		fail(w, relay.ErrBadToken)
		return true
	}
	s.mu.Unlock()
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return true
	}
	k := &sock{id: id, dir: dir, conn: conn, rows: make(chan Row, 64)}
	s.mu.Lock()
	if s.push.socks == nil {
		s.push.socks = map[*sock]bool{}
	}
	s.push.socks[k] = true
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(r.Context())
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.push.socks, k)
		s.mu.Unlock()
		conn.CloseNow()
	}()
	pongs := make(chan struct{}, 8)
	go func() {
		defer cancel()
		for {
			_, b, err := conn.Read(ctx)
			if err != nil {
				return
			}
			if string(b) == "ping" {
				pongs <- struct{}{}
			}
		}
	}()
	for {
		var b []byte
		select {
		case <-ctx.Done():
			return true
		case <-pongs:
			b = []byte("pong")
		case row := <-k.rows:
			b, _ = json.Marshal(row)
		}
		if conn.Write(ctx, websocket.MessageText, b) != nil {
			return true
		}
	}
}
