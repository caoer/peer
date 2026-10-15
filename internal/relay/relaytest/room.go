package relaytest

// The fake room: results/wire-contract-v2.md § Room routes from memory, on
// the same Server as the channels, so a test runs parties over channels and
// rooms against one relay.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/caoer/peer/internal/relay"
)

// RoomRow is one stored room record as the relay answers it.
type RoomRow struct {
	Seq  int64  `json:"seq"`
	Idx  int    `json:"idx"`
	Type string `json:"type"`
	Body string `json:"body"`
	At   int64  `json:"at"`
}

const (
	socketsPerIdx = 16
	pageBytes     = 4 << 20 // ~4 MiB of body text per pull answer
)

var errTooManySockets = &relay.Error{Status: 429, Code: "too_many_sockets"}

type room struct {
	add        string
	membership int64
	members    []*roomMember        // by idx
	tokens     map[string]roomToken // by token
	rows       []RoomRow
}

type roomMember struct {
	role    string
	from    int64
	revoked bool
}

type roomToken struct {
	idx   int
	admin bool
}

type roomSock struct {
	id   string
	idx  int
	conn *websocket.Conn
	rows chan RoomRow
}

// rooms is the Server's room state; s.mu guards it.
type rooms struct {
	byID  map[string]*room
	socks map[*roomSock]bool
}

// RoomRecords is every record the relay holds for room id, in seq order.
func (s *Server) RoomRecords(id string) []RoomRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rm := s.rooms.byID[id]; rm != nil {
		return append([]RoomRow(nil), rm.rows...)
	}
	return nil
}

// RoomMembership is room id's membership version, -1 when there is no such room.
func (s *Server) RoomMembership(id string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rm := s.rooms.byID[id]; rm != nil {
		return rm.membership
	}
	return -1
}

// RoomSockets is how many sockets are open on room id for idx.
func (s *Server) RoomSockets(id string, idx int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roomSockets(id, idx)
}

func (s *Server) roomSockets(id string, idx int) int {
	n := 0
	for k := range s.rooms.socks {
		if k.id == id && k.idx == idx {
			n++
		}
	}
	return n
}

// RoomPulls is how many pull GETs room id has answered for idx's tokens.
func (s *Server) RoomPulls(id string, idx int) int {
	return s.Pulls(id, roomPullKey(idx))
}

func roomPullKey(idx int) string { return "idx " + strconv.Itoa(idx) }

// serveRoom answers the room routes and reports whether p was one.
func (s *Server) serveRoom(w http.ResponseWriter, r *http.Request) bool {
	p := strings.TrimPrefix(r.URL.Path, "/peer")
	if p != "/rooms" && !strings.HasPrefix(p, "/r/") && !strings.HasPrefix(p, "/f/") {
		return false
	}
	if s.roomUpgrade(w, r, p) {
		return true
	}
	s.mu.Lock()
	closing := s.roomRoute(w, r, p)
	s.mu.Unlock()
	for _, k := range closing {
		go k.conn.Close(4401, "revoked")
	}
	return true
}

// roomRoute serves one non-upgrade room request under s.mu and returns the
// sockets a revoke closes, for the caller to close after unlocking.
func (s *Server) roomRoute(w http.ResponseWriter, r *http.Request, p string) []*roomSock {
	ok := func(v any) { json.NewEncoder(w).Encode(v) }
	if s.rooms.byID == nil {
		s.rooms.byID = map[string]*room{}
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	if p == "/rooms" {
		if r.Method != http.MethodPost {
			fail(w, relay.ErrMethodNotAllowed)
			return nil
		}
		if bearer != s.login {
			fail(w, relay.ErrBadToken)
			return nil
		}
		var in struct{ Add *string }
		if r.ContentLength != 0 && json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, relay.ErrBadRequest)
			return nil
		}
		add := relay.AddAdmins
		if in.Add != nil {
			add = *in.Add
		}
		if add != relay.AddAdmins && add != relay.AddMembers {
			fail(w, relay.ErrBadRequest)
			return nil
		}
		b := make([]byte, 16)
		rand.Read(b)
		id := hex.EncodeToString(b)
		t := token()
		s.rooms.byID[id] = &room{add: add, members: []*roomMember{{role: relay.RoleWrite}},
			tokens: map[string]roomToken{t: {idx: 0, admin: true}}}
		ok(map[string]any{"id": id, "adminToken": t, "membership": 0})
		return nil
	}
	if strings.HasPrefix(p, "/f/") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			fail(w, relay.ErrMethodNotAllowed)
			return nil
		}
		// The real relay answers the landing text for any id of the room form,
		// room or no room: the route is for a human's browser, not a member.
		if !relay.ValidRoomID(p[3:]) {
			fail(w, relay.ErrNoSuchRoom)
			return nil
		}
		if r.Method == http.MethodGet {
			w.Write([]byte("this is a peer feed; install peer and run peer room follow <link>"))
		}
		return nil
	}

	// The real Worker checks the route and the method, then that a bearer is
	// there, then the request's body and query, and reaches the room Object
	// last: a bad request answers 400, 405 or 413 before any 401 or 404, and
	// an unknown room with no bearer answers bad_token.
	id, rest, _ := strings.Cut(strings.TrimPrefix(p, "/r/"), "/")
	if !relay.ValidRoomID(id) {
		fail(w, relay.ErrNoSuchRoom)
		return nil
	}
	var route string
	switch {
	case rest == "members" && r.Method == http.MethodPost:
		route = "mint"
	case rest == "members" && r.Method == http.MethodGet:
		route = "list"
	case strings.HasPrefix(rest, "members/") && r.Method == http.MethodDelete:
		route = "revoke"
	case rest == "admin" && r.Method == http.MethodPost:
		route = "grant"
	case rest == "records" && r.Method == http.MethodPost:
		route = "put"
	case rest == "records" && r.Method == http.MethodGet:
		route = "pull"
	case rest == "members" || strings.HasPrefix(rest, "members/") || rest == "admin" || rest == "records":
		fail(w, relay.ErrMethodNotAllowed)
		return nil
	default:
		fail(w, relay.ErrNoSuchRoute)
		return nil
	}
	if bearer == "" {
		fail(w, relay.ErrBadToken)
		return nil
	}
	var (
		mintRole  string
		revokeIdx = -1 // self
		grantIdx  int
		put       struct {
			Type       string
			Body       string
			Membership *int64
			Bump       bool
		}
		after = int64(-1)
	)
	switch route {
	case "mint":
		var in struct{ Role string }
		if json.NewDecoder(r.Body).Decode(&in) != nil || (in.Role != relay.RoleWrite && in.Role != relay.RoleRead) {
			fail(w, relay.ErrBadRequest)
			return nil
		}
		mintRole = in.Role
	case "revoke":
		if k := strings.TrimPrefix(rest, "members/"); k != "self" {
			n, err := strconv.Atoi(k)
			if err != nil || !relay.ValidIdx(n) {
				fail(w, relay.ErrNoSuchMember)
				return nil
			}
			revokeIdx = n
		}
	case "grant":
		var in struct{ Idx *int }
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Idx == nil || !relay.ValidIdx(*in.Idx) {
			fail(w, relay.ErrBadRequest)
			return nil
		}
		grantIdx = *in.Idx
	case "put":
		if json.NewDecoder(r.Body).Decode(&put) != nil || put.Type != "sealed" || put.Membership == nil || *put.Membership < 0 {
			fail(w, relay.ErrBadRequest)
			return nil
		}
		raw, err := base64.StdEncoding.DecodeString(put.Body)
		switch {
		case err != nil || len(raw) == 0:
			fail(w, relay.ErrBadRequest)
			return nil
		case len(raw) > relay.MaxSealed:
			fail(w, relay.ErrTooLarge)
			return nil
		}
	case "pull":
		if q, set := r.URL.Query()["after"]; set {
			n, err := strconv.ParseInt(q[0], 10, 64)
			if err != nil || n < -1 {
				fail(w, relay.ErrBadRequest)
				return nil
			}
			after = n
		}
	}

	rm := s.rooms.byID[id]
	if rm == nil {
		fail(w, relay.ErrNoSuchRoom)
		return nil
	}
	tok, found := rm.tokens[bearer]
	if !found {
		fail(w, relay.ErrBadToken)
		return nil
	}
	me := rm.members[tok.idx]
	if me.revoked {
		fail(w, relay.ErrRevoked)
		return nil
	}

	switch route {
	case "mint":
		if !tok.admin && !(rm.add == relay.AddMembers && me.role == relay.RoleWrite) {
			fail(w, relay.ErrNotAdmin)
			return nil
		}
		idx := len(rm.members)
		if !relay.ValidIdx(idx) {
			fail(w, relay.ErrTooLarge)
			return nil
		}
		t := token()
		from := int64(len(rm.rows))
		rm.members = append(rm.members, &roomMember{role: mintRole, from: from})
		rm.tokens[t] = roomToken{idx: idx}
		rm.membership++
		ok(map[string]any{"idx": idx, "token": t, "from": from, "membership": rm.membership})
	case "list":
		if !tok.admin {
			fail(w, relay.ErrNotAdmin)
			return nil
		}
		ms := make([]relay.Member, len(rm.members))
		for i, m := range rm.members {
			ms[i] = relay.Member{Idx: i, Role: m.role, From: m.from, Revoked: m.revoked}
		}
		for _, t := range rm.tokens {
			if t.admin {
				ms[t.idx].Admin = true
			}
		}
		ok(map[string]any{"membership": rm.membership, "members": ms})
	case "revoke":
		idx := tok.idx
		if revokeIdx >= 0 {
			if !tok.admin {
				fail(w, relay.ErrNotAdmin)
				return nil
			}
			if revokeIdx >= len(rm.members) {
				fail(w, relay.ErrNoSuchMember)
				return nil
			}
			idx = revokeIdx
		}
		var closing []*roomSock
		if m := rm.members[idx]; !m.revoked {
			m.revoked = true
			rm.membership++
			for k := range s.rooms.socks {
				if k.id == id && k.idx == idx {
					closing = append(closing, k)
					delete(s.rooms.socks, k)
				}
			}
		}
		ok(map[string]any{"membership": rm.membership})
		return closing
	case "grant":
		if !tok.admin {
			fail(w, relay.ErrNotAdmin)
			return nil
		}
		k := grantIdx
		switch {
		case k >= len(rm.members) || rm.members[k].revoked:
			fail(w, relay.ErrNoSuchMember)
			return nil
		case rm.members[k].role != relay.RoleWrite:
			fail(w, relay.ErrReadOnly)
			return nil
		}
		t := token()
		rm.tokens[t] = roomToken{idx: k, admin: true}
		rm.membership++
		ok(map[string]any{"token": t, "membership": rm.membership})
	case "put":
		switch {
		case me.role != relay.RoleWrite:
			fail(w, relay.ErrReadOnly)
			return nil
		case put.Bump && !tok.admin:
			fail(w, relay.ErrReadOnly)
			return nil
		case *put.Membership < rm.membership:
			fail(w, relay.ErrStaleMembership)
			return nil
		case *put.Membership > rm.membership:
			fail(w, relay.ErrBadRequest)
			return nil
		}
		row := RoomRow{Seq: int64(len(rm.rows)), Idx: tok.idx, Type: "sealed", Body: put.Body, At: time.Now().UnixMilli()}
		rm.rows = append(rm.rows, row)
		if put.Bump {
			rm.membership++
		}
		ok(map[string]any{"seq": row.Seq, "membership": rm.membership})
		if s.push.drop > 0 {
			s.push.drop--
			return nil
		}
		for k := range s.rooms.socks {
			if k.id == id && k.idx != row.Idx {
				select {
				case k.rows <- row:
				default: // a socket that cannot keep up loses the frame; the pull has it
				}
			}
		}
	case "pull":
		page, size := []RoomRow{}, 0
		for _, row := range rm.rows {
			if row.Idx == tok.idx || row.Seq < me.from || row.Seq <= after {
				continue
			}
			if len(page) == s.PageSize || (len(page) > 0 && size+len(row.Body) > pageBytes) {
				break
			}
			page = append(page, row)
			size += len(row.Body)
		}
		s.countPull(id, roomPullKey(tok.idx))
		ok(map[string]any{"membership": rm.membership, "records": page})
	}
	return nil
}

// roomUpgrade takes a WebSocket upgrade on a room's records route and
// reports whether it answered; without push it leaves it to the pull.
func (s *Server) roomUpgrade(w http.ResponseWriter, r *http.Request, p string) bool {
	if r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	id, rest, _ := strings.Cut(strings.TrimPrefix(p, "/r/"), "/")
	if !strings.HasPrefix(p, "/r/") || rest != "records" {
		return false
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	if s.noPush {
		s.mu.Unlock()
		return false
	}
	rm := s.rooms.byID[id]
	var tok roomToken
	var found bool
	if rm != nil {
		tok, found = rm.tokens[bearer]
	}
	var refuse *relay.Error
	switch {
	case rm == nil:
		refuse = relay.ErrNoSuchRoom
	case bearer == "" || !found:
		refuse = relay.ErrBadToken
	case rm.members[tok.idx].revoked:
		refuse = relay.ErrRevoked
	case s.roomSockets(id, tok.idx) >= socketsPerIdx:
		refuse = errTooManySockets
	}
	s.mu.Unlock()
	if refuse != nil {
		fail(w, refuse)
		return true
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return true
	}
	k := &roomSock{id: id, idx: tok.idx, conn: conn, rows: make(chan RoomRow, 64)}
	s.mu.Lock()
	if s.rooms.socks == nil {
		s.rooms.socks = map[*roomSock]bool{}
	}
	s.rooms.socks[k] = true
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(r.Context())
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.rooms.socks, k)
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
