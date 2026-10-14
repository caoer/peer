// Package relaytest is an in-memory relay serving results/wire-contract.md
// for tests of the CLI: two parties on one httptest server. It is the fake
// package relay's own tests use, exported, plus a view of what the relay
// holds so a test can check it sees ciphertext and the host's card alone.
package relaytest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/relay"
)

// Row is one stored envelope as the relay answers it.
type Row struct {
	Seq  int64  `json:"seq"`
	Type string `json:"type"`
	Body string `json:"body"`
	At   int64  `json:"at"`
}

type channel struct {
	host, guest, invite string
	inviteUsed          bool
	env                 map[string][]Row // by dir
	prekeys             map[string][]relay.Prekey
}

// Server is the fake relay; serve it with httptest.
type Server struct {
	mu       sync.Mutex
	login    string
	channels map[string]*channel
	// PageSize caps a pull answer (the contract's 100).
	PageSize int
}

// New makes a relay whose owner login is login.
func New(login string) *Server {
	return &Server{login: login, channels: map[string]*channel{}, PageSize: 100}
}

// Start serves a new relay for the test and returns it with a client and
// the relay base (…/peer).
func Start(t testing.TB, login string) (*Server, *relay.Client, string) {
	t.Helper()
	s := New(login)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	base := srv.URL + "/peer"
	return s, relay.New(base, srv.Client()), base
}

// Envelopes is what the relay holds on channel id in direction dir ("h2g" or "g2h").
func (s *Server) Envelopes(id, dir string) []Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch := s.channels[id]; ch != nil {
		return append([]Row(nil), ch.env[dir]...)
	}
	return nil
}

// Prekeys is how many one-time prekeys side ("h2g" = host's, "g2h" = guest's) holds on channel id.
func (s *Server) Prekeys(id, side string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch := s.channels[id]; ch != nil {
		return len(ch.prekeys[side])
	}
	return 0
}

func token() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func fail(w http.ResponseWriter, e *relay.Error) {
	w.WriteHeader(e.Status)
	json.NewEncoder(w).Encode(map[string]string{"error": e.Code + " (fake)", "code": e.Code})
}

// ServeHTTP serves the contract from memory.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/peer")
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ok := func(v any) { json.NewEncoder(w).Encode(v) }

	if p == "/channels" {
		if r.Method != http.MethodPost {
			fail(w, relay.ErrMethodNotAllowed)
			return
		}
		if bearer != s.login {
			fail(w, relay.ErrBadToken)
			return
		}
		b := make([]byte, 16)
		rand.Read(b)
		id := hex.EncodeToString(b)
		s.channels[id] = &channel{host: token(), invite: token(),
			env: map[string][]Row{}, prekeys: map[string][]relay.Prekey{}}
		ok(relay.Channel{ID: id, HostToken: s.channels[id].host, InviteToken: s.channels[id].invite})
		return
	}
	if strings.HasPrefix(p, "/i/") {
		if _, found := s.channels[p[3:]]; !found {
			fail(w, relay.ErrNoSuchChannel)
			return
		}
		w.Write([]byte("this is a peer invite; install peer and run peer accept <link>"))
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(p, "/c/"), "/", 2)
	if !strings.HasPrefix(p, "/c/") || len(parts) != 2 {
		fail(w, relay.ErrNoSuchRoute)
		return
	}
	ch, found := s.channels[parts[0]]
	if !found {
		fail(w, relay.ErrNoSuchChannel)
		return
	}
	if parts[1] == "join" {
		var in struct{ InviteToken string }
		json.NewDecoder(r.Body).Decode(&in)
		switch {
		case r.Header.Get("Authorization") != "":
			fail(w, relay.ErrBadRequest) // the contract: no Authorization on join
		case in.InviteToken != ch.invite:
			fail(w, relay.ErrBadToken)
		case ch.inviteUsed:
			fail(w, relay.ErrTokenUsed)
		default:
			ch.inviteUsed = true
			ch.guest = token()
			ok(map[string]string{"guestToken": ch.guest})
		}
		return
	}
	var own, other string
	switch {
	case bearer != "" && bearer == ch.host:
		own, other = "h2g", "g2h"
	case bearer != "" && bearer == ch.guest:
		own, other = "g2h", "h2g"
	default:
		fail(w, relay.ErrBadToken)
		return
	}
	switch {
	case parts[1] == "envelopes" && r.Method == http.MethodPost:
		var in struct{ Type, Body string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, relay.ErrBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(in.Body)
		if err != nil || (in.Type != "card" && in.Type != "prekey" && in.Type != "msg") {
			fail(w, relay.ErrBadRequest)
			return
		}
		if len(raw) > envelope.MaxBody {
			fail(w, relay.ErrTooLarge)
			return
		}
		seq := int64(len(ch.env[own]))
		ch.env[own] = append(ch.env[own], Row{seq, in.Type, in.Body, time.Now().UnixMilli()})
		ok(relay.Receipt{Dir: own, Seq: seq})
	case parts[1] == "envelopes" && r.Method == http.MethodGet:
		after := int64(-1)
		if q := r.URL.Query().Get("after"); q != "" {
			n, err := strconv.ParseInt(q, 10, 64)
			if err != nil {
				fail(w, relay.ErrBadRequest)
				return
			}
			after = n
		}
		page := []Row{}
		for _, e := range ch.env[other] {
			if e.Seq > after && len(page) < s.PageSize {
				page = append(page, e)
			}
		}
		ok(page)
	case parts[1] == "prekeys" && r.Method == http.MethodPut:
		var in struct{ Keys []relay.Prekey }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, relay.ErrBadRequest)
			return
		}
		if len(in.Keys) > relay.MaxPrekeysPerPut || len(ch.prekeys[own])+len(in.Keys) > 200 {
			fail(w, relay.ErrTooLarge)
			return
		}
	next:
		for _, k := range in.Keys {
			for _, have := range ch.prekeys[own] {
				if have.ID == k.ID {
					continue next
				}
			}
			ch.prekeys[own] = append(ch.prekeys[own], k)
		}
		ok(map[string]int{"count": len(ch.prekeys[own])})
	case parts[1] == "prekeys/take" && r.Method == http.MethodPost:
		if len(ch.prekeys[other]) == 0 {
			ok(struct{}{})
			return
		}
		k := ch.prekeys[other][0]
		ch.prekeys[other] = ch.prekeys[other][1:]
		ok(k)
	default:
		fail(w, relay.ErrNoSuchRoute)
	}
}
