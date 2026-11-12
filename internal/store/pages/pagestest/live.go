package pagestest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/coder/websocket"
)

// The fake's live socket (ccc-pages src/live.ts, `GET /d/<slug>` upgraded,
// the owner's whole store selected): `hello` with every record inline up to
// InlineMax, or after `have=<epoch>.<seq>` of this epoch `welcome`, the
// latest change per key since, `synced`; then a `put` per committed write,
// `prev` its seq - 1. `{"type":"ping"}` is answered `{"type":"pong"}`.

const fakeEpoch = "0123456789abcdef"

var haveRE = regexp.MustCompile(`^([0-9a-f]{16})\.([0-9]{1,15})$`)

// live is the fake's live state; Server.mu guards it.
type live struct {
	off      bool
	seq      int64            // the store's head
	seqs     map[string]int64 // each key's last change
	socks    map[*liveSock]bool
	gets     map[string]int
	upgrades int
	resumes  int
}

type liveSock struct {
	conn   *websocket.Conn
	frames chan []byte
}

// NoLive makes the page answer an upgrade 404, as a page service without
// live sockets would.
func (s *Server) NoLive(off bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live.off = off
}

// Gets is how many GETs key has answered; "" counts every key.
func (s *Server) Gets(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key != "" {
		return s.live.gets[key]
	}
	n := 0
	for _, c := range s.live.gets {
		n += c
	}
	return n
}

// Upgrades is how many live sockets the page accepted, and how many of them
// resumed from a cursor.
func (s *Server) Upgrades() (accepted, resumed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live.upgrades, s.live.resumes
}

// LiveSockets is how many live sockets are open.
func (s *Server) LiveSockets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live.socks)
}

// CloseLive closes every live socket with 1001, as a deploy does.
func (s *Server) CloseLive() {
	s.mu.Lock()
	var open []*websocket.Conn
	for k := range s.live.socks {
		open = append(open, k.conn)
		delete(s.live.socks, k)
	}
	s.mu.Unlock()
	for _, c := range open {
		c.Close(websocket.StatusGoingAway, "deploy")
	}
}

// countGet notes one GET of key; s.mu is held.
func (s *Server) countGet(key string) {
	if s.live.gets == nil {
		s.live.gets = map[string]int{}
	}
	s.live.gets[key]++
}

// changed takes a committed write of key into the log and pushes it; s.mu
// is held.
func (s *Server) changed(key string, r Record) {
	s.live.seq++
	if s.live.seqs == nil {
		s.live.seqs = map[string]int64{}
	}
	s.live.seqs[key] = s.live.seq
	f := s.putFrame(key, r, s.live.seq, s.live.seq-1)
	for k := range s.live.socks {
		select {
		case k.frames <- f:
		default: // a socket that cannot keep up is dropped, as a resync
			delete(s.live.socks, k)
			k.conn.CloseNow()
		}
	}
}

func (s *Server) record(r Record) string {
	if len(r.Data) > s.InlineMax {
		return fmt.Sprintf(`"schema":%q,"ref":true`, r.Schema)
	}
	return fmt.Sprintf(`"schema":%q,"value":%s`, r.Schema, r.Data)
}

func (s *Server) putFrame(key string, r Record, seq, prev int64) []byte {
	return []byte(fmt.Sprintf(`{"type":"put","key":%q,"v":%d,"t":0,"seq":%d,"prev":%d,%s}`, key, r.Version, seq, prev, s.record(r)))
}

// liveUpgrade answers GET /d/<slug> upgraded; the caller checked the Bearer.
func (s *Server) liveUpgrade(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.live.off {
		s.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"no such route","code":"no_such_route"}`))
		return
	}
	// The first frames and the socket's place in the fan-out under one lock:
	// a write lands in exactly one of them.
	var first [][]byte
	resumed := false
	if m := haveRE.FindStringSubmatch(r.URL.Query().Get("have")); m != nil {
		have, _ := strconv.ParseInt(m[2], 10, 64)
		if m[1] == fakeEpoch && have <= s.live.seq {
			resumed = true
			first = append(first, []byte(fmt.Sprintf(`{"type":"welcome","live":1,"epoch":%q,"seq":%d,"floor":0,"reset":false}`, fakeEpoch, s.live.seq)))
			var keys []string
			for k, q := range s.live.seqs {
				if q > have {
					keys = append(keys, k)
				}
			}
			sort.Slice(keys, func(i, j int) bool { return s.live.seqs[keys[i]] < s.live.seqs[keys[j]] })
			prev := have
			for _, k := range keys {
				first = append(first, s.putFrame(k, s.records[k], s.live.seqs[k], prev))
				prev = s.live.seqs[k]
			}
			first = append(first, []byte(fmt.Sprintf(`{"type":"synced","seq":%d}`, s.live.seq)))
		}
	}
	if !resumed {
		var b strings.Builder
		fmt.Fprintf(&b, `{"type":"hello","live":1,"epoch":%q,"seq":%d,"floor":0,"floors":{},"keys":{`, fakeEpoch, s.live.seq)
		n := 0
		for k, rec := range s.records {
			if n++; n > 1 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `%q:{"v":%d,"t":0,%s}`, k, rec.Version, s.record(rec))
		}
		b.WriteString("}}")
		first = append(first, []byte(b.String()))
	}
	k := &liveSock{frames: make(chan []byte, 256)}
	if s.live.socks == nil {
		s.live.socks = map[*liveSock]bool{}
	}
	s.live.socks[k] = true
	s.live.upgrades++
	if resumed {
		s.live.resumes++
	}
	s.mu.Unlock()
	conn, err := websocket.Accept(w, r, nil)
	s.mu.Lock()
	if err != nil {
		delete(s.live.socks, k)
		s.mu.Unlock()
		return
	}
	k.conn = conn
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(r.Context())
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.live.socks, k)
		s.mu.Unlock()
		conn.CloseNow()
	}()
	for _, f := range first {
		if conn.Write(ctx, websocket.MessageText, f) != nil {
			return
		}
	}
	pongs := make(chan struct{}, 8)
	go func() {
		defer cancel()
		for {
			_, b, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var f struct{ Type string }
			if json.Unmarshal(b, &f) == nil && f.Type == "ping" {
				pongs <- struct{}{}
			}
		}
	}()
	for {
		var f []byte
		select {
		case <-ctx.Done():
			return
		case <-pongs:
			f = []byte(`{"type":"pong"}`)
		case f = <-k.frames:
		}
		if conn.Write(ctx, websocket.MessageText, f) != nil {
			return
		}
	}
}
