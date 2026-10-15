package relay

// The room client: every room route of results/wire-contract-v2.md § Room
// routes. As with channels, the relay is untrusted: answers are size-capped
// and validated, and a malformed record in a pull or a push frame comes back
// as a RoomRecord with Err set and its seq kept, so the cursor still moves.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
)

// Room contract limits.
const (
	// MaxSealed is the relay's cap on one record's decoded body bytes.
	MaxSealed = 1 << 20
	// FeedIdx is the stanza idx of a feed's link; no member holds it.
	FeedIdx = 65535
	// closeNoSuchRoom is the room socket's close for a room that is gone.
	closeNoSuchRoom websocket.StatusCode = 4404
)

// The add settings a room is created with (who may mint a member).
const (
	AddAdmins  = "admins"
	AddMembers = "members"
)

// The member roles.
const (
	RoleWrite = "write"
	RoleRead  = "read"
)

// The room codes, beside v1's.
var (
	ErrStaleMembership = &Error{Status: 409, Code: "stale_membership"}
	ErrNoSuchRoom      = &Error{Status: 404, Code: "no_such_room"}
	ErrNoSuchMember    = &Error{Status: 404, Code: "no_such_member"}
	ErrNotAdmin        = &Error{Status: 403, Code: "not_admin"}
	ErrReadOnly        = &Error{Status: 403, Code: "read_only"}
	ErrRevoked         = &Error{Status: 401, Code: "revoked"}
)

// ValidRoomID reports whether id has the contract's room form (32 lowercase hex).
func ValidRoomID(id string) bool { return channelRE.MatchString(id) }

// ValidIdx reports whether k can be a member's idx (a uint16 short of FeedIdx).
func ValidIdx(k int) bool { return k >= 0 && k < FeedIdx }

// Room is a create answer: the room, the creator's admin-flagged token
// (idx 0, role write, from 0) and the membership version.
type Room struct {
	ID         string `json:"id"`
	AdminToken string `json:"adminToken"`
	Membership int64  `json:"membership"`
}

// CreateRoom opens a room; login is the ccc-pages owner login and add is
// AddAdmins or AddMembers ("" is AddAdmins). The relay keeps add.
func (c *Client) CreateRoom(ctx context.Context, login, add string) (Room, error) {
	if add == "" {
		add = AddAdmins
	}
	if add != AddAdmins && add != AddMembers {
		return Room{}, fmt.Errorf("relay: add %q, want %q or %q", add, AddAdmins, AddMembers)
	}
	var out struct {
		ID         string `json:"id"`
		AdminToken string `json:"adminToken"`
		Membership *int64 `json:"membership"`
	}
	in := struct {
		Add string `json:"add"`
	}{add}
	if err := c.do(ctx, http.MethodPost, "/rooms", login, in, &out, maxSmallAnswer); err != nil {
		return Room{}, err
	}
	if !ValidRoomID(out.ID) || !ValidToken(out.AdminToken) || !version(out.Membership) {
		return Room{}, fmt.Errorf("%w: room create answer", ErrAnswer)
	}
	return Room{ID: out.ID, AdminToken: out.AdminToken, Membership: *out.Membership}, nil
}

// Minted is a member mint answer: the new idx, its token, its from (the log
// head: it reads no record below it) and the bumped membership version.
type Minted struct {
	Idx        int
	Token      string
	From       int64
	Membership int64
}

// AddMember mints a member with role RoleWrite or RoleRead. token is an
// admin token, or under AddMembers any write token; otherwise ErrNotAdmin.
func (c *Client) AddMember(ctx context.Context, id, token, role string) (Minted, error) {
	if err := checkRoom(id, token); err != nil {
		return Minted{}, err
	}
	if role != RoleWrite && role != RoleRead {
		return Minted{}, fmt.Errorf("relay: role %q, want %q or %q", role, RoleWrite, RoleRead)
	}
	var out struct {
		Idx        *int   `json:"idx"`
		Token      string `json:"token"`
		From       *int64 `json:"from"`
		Membership *int64 `json:"membership"`
	}
	in := struct {
		Role string `json:"role"`
	}{role}
	if err := c.do(ctx, http.MethodPost, "/r/"+id+"/members", token, in, &out, maxSmallAnswer); err != nil {
		return Minted{}, err
	}
	if out.Idx == nil || !ValidIdx(*out.Idx) || !ValidToken(out.Token) || !version(out.From) || !version(out.Membership) {
		return Minted{}, fmt.Errorf("%w: member mint answer", ErrAnswer)
	}
	return Minted{Idx: *out.Idx, Token: out.Token, From: *out.From, Membership: *out.Membership}, nil
}

// RemoveMember revokes every token on idx (an admin token's act); the
// relay closes that idx's sockets with 4401. It returns the bumped
// membership version.
func (c *Client) RemoveMember(ctx context.Context, id, token string, idx int) (int64, error) {
	if err := checkRoom(id, token); err != nil {
		return 0, err
	}
	if !ValidIdx(idx) {
		return 0, fmt.Errorf("relay: bad idx %d", idx)
	}
	return c.membership(ctx, http.MethodDelete, "/r/"+id+"/members/"+strconv.Itoa(idx), token, nil)
}

// LeaveRoom revokes the caller's own idx — a read member's leave.
func (c *Client) LeaveRoom(ctx context.Context, id, token string) (int64, error) {
	if err := checkRoom(id, token); err != nil {
		return 0, err
	}
	return c.membership(ctx, http.MethodDelete, "/r/"+id+"/members/self", token, nil)
}

// Member is one row of a members answer.
type Member struct {
	Idx     int    `json:"idx"`
	Role    string `json:"role"`
	From    int64  `json:"from"`
	Admin   bool   `json:"admin"`
	Revoked bool   `json:"revoked"`
}

// Members is a members answer.
type Members struct {
	Membership int64
	Members    []Member
}

// ListMembers reads the room's members (an admin token's act) — how an
// admin's host sees a reader gone.
func (c *Client) ListMembers(ctx context.Context, id, token string) (Members, error) {
	if err := checkRoom(id, token); err != nil {
		return Members{}, err
	}
	var out struct {
		Membership *int64 `json:"membership"`
		Members    []struct {
			Idx     *int   `json:"idx"`
			Role    string `json:"role"`
			From    *int64 `json:"from"`
			Admin   bool   `json:"admin"`
			Revoked bool   `json:"revoked"`
		} `json:"members"`
	}
	if err := c.do(ctx, http.MethodGet, "/r/"+id+"/members", token, nil, &out, maxAnswer); err != nil {
		return Members{}, err
	}
	if !version(out.Membership) || out.Members == nil {
		return Members{}, fmt.Errorf("%w: members answer", ErrAnswer)
	}
	ms := Members{Membership: *out.Membership, Members: make([]Member, 0, len(out.Members))}
	seen := map[int]bool{}
	for _, m := range out.Members {
		if m.Idx == nil || !ValidIdx(*m.Idx) || seen[*m.Idx] || (m.Role != RoleWrite && m.Role != RoleRead) || !version(m.From) {
			return Members{}, fmt.Errorf("%w: members row", ErrAnswer)
		}
		seen[*m.Idx] = true
		ms.Members = append(ms.Members, Member{Idx: *m.Idx, Role: m.Role, From: *m.From, Admin: m.Admin, Revoked: m.Revoked})
	}
	return ms, nil
}

// GrantAdmin mints an admin-flagged token for the live write idx k (an
// admin token's act) and returns it with the bumped membership version.
func (c *Client) GrantAdmin(ctx context.Context, id, token string, idx int) (string, int64, error) {
	if err := checkRoom(id, token); err != nil {
		return "", 0, err
	}
	if !ValidIdx(idx) {
		return "", 0, fmt.Errorf("relay: bad idx %d", idx)
	}
	var out struct {
		Token      string `json:"token"`
		Membership *int64 `json:"membership"`
	}
	in := struct {
		Idx int `json:"idx"`
	}{idx}
	if err := c.do(ctx, http.MethodPost, "/r/"+id+"/admin", token, in, &out, maxSmallAnswer); err != nil {
		return "", 0, err
	}
	if !ValidToken(out.Token) || !version(out.Membership) {
		return "", 0, fmt.Errorf("%w: admin answer", ErrAnswer)
	}
	return out.Token, *out.Membership, nil
}

// RoomReceipt is a record put answer.
type RoomReceipt struct {
	Seq        int64
	Membership int64
}

// PutRecord stores one sealed record, put at the membership version the
// sender sealed it under: below the relay's current one it is refused with
// ErrStaleMembership before anything is stored. bump (admin tokens only)
// appends the record and bumps the version in one transaction — the
// removal record travels so. A body over MaxSealed never leaves the host.
func (c *Client) PutRecord(ctx context.Context, id, token string, sealed []byte, membership int64, bump bool) (RoomReceipt, error) {
	if err := checkRoom(id, token); err != nil {
		return RoomReceipt{}, err
	}
	if len(sealed) == 0 || len(sealed) > MaxSealed {
		return RoomReceipt{}, fmt.Errorf("relay: a sealed record is 1..%d bytes, this one %d: %w", MaxSealed, len(sealed), ErrTooLarge)
	}
	if membership < 0 {
		return RoomReceipt{}, fmt.Errorf("relay: membership %d < 0", membership)
	}
	in := struct {
		Type       string `json:"type"`
		Body       string `json:"body"`
		Membership int64  `json:"membership"`
		Bump       bool   `json:"bump,omitempty"`
	}{"sealed", base64.StdEncoding.EncodeToString(sealed), membership, bump}
	var out struct {
		Seq        *int64 `json:"seq"`
		Membership *int64 `json:"membership"`
	}
	if err := c.do(ctx, http.MethodPost, "/r/"+id+"/records", token, in, &out, maxSmallAnswer); err != nil {
		return RoomReceipt{}, err
	}
	want := membership // a put lands at the version it names; above it is refused
	if bump {
		want++
	}
	if !version(out.Seq) || out.Membership == nil || *out.Membership != want {
		return RoomReceipt{}, fmt.Errorf("%w: record put answer", ErrAnswer)
	}
	return RoomReceipt{Seq: *out.Seq, Membership: *out.Membership}, nil
}

// RoomRecord is one pulled or pushed room record: the relay's seq, the
// writer's idx, when the relay stored it and the sealed bytes. Err is set
// when the relay's bytes for this seq are malformed; Body is then nil and
// the seq still counts.
type RoomRecord struct {
	Seq  int64
	Idx  int
	At   time.Time
	Body []byte
	Err  error
}

// RoomPage is a pull answer: the relay's membership version and the
// records, ascending.
type RoomPage struct {
	Membership int64
	Records    []RoomRecord
}

// PullRoom returns one page of the other members' records with seq > after
// (after -1 for everything the caller may read), ascending. The relay
// floors the page at the caller's from. An empty page means caught up.
func (c *Client) PullRoom(ctx context.Context, id, token string, after int64) (RoomPage, error) {
	if err := checkRoom(id, token); err != nil {
		return RoomPage{}, err
	}
	if after < -1 {
		return RoomPage{}, fmt.Errorf("relay: after %d < -1", after)
	}
	var out struct {
		Membership *int64    `json:"membership"`
		Records    []roomRow `json:"records"`
	}
	path := "/r/" + id + "/records?after=" + strconv.FormatInt(after, 10)
	if err := c.do(ctx, http.MethodGet, path, token, nil, &out, maxAnswer); err != nil {
		return RoomPage{}, err
	}
	if !version(out.Membership) || out.Records == nil {
		return RoomPage{}, fmt.Errorf("%w: room pull answer", ErrAnswer)
	}
	if len(out.Records) > maxPage {
		return RoomPage{}, fmt.Errorf("%w: %d records in one page", ErrAnswer, len(out.Records))
	}
	page := RoomPage{Membership: *out.Membership, Records: make([]RoomRecord, 0, len(out.Records))}
	last := after
	for _, r := range out.Records {
		if r.Seq == nil || *r.Seq <= last {
			return RoomPage{}, fmt.Errorf("%w: seq missing, not after %d, or not ascending", ErrAnswer, last)
		}
		last = *r.Seq
		page.Records = append(page.Records, r.record())
	}
	return page, nil
}

// PullRoomAll pulls page after page from after until the relay answers
// none; the membership is the last page's.
func (c *Client) PullRoomAll(ctx context.Context, id, token string, after int64) (RoomPage, error) {
	var all RoomPage
	for {
		page, err := c.PullRoom(ctx, id, token, after)
		if err != nil {
			return all, err
		}
		all.Membership = page.Membership
		if len(page.Records) == 0 {
			return all, nil
		}
		all.Records = append(all.Records, page.Records...)
		after = page.Records[len(page.Records)-1].Seq
	}
}

// FeedLanding fetches a feed's landing text (no token).
func (c *Client) FeedLanding(ctx context.Context, id string) (string, error) {
	if !ValidRoomID(id) {
		return "", fmt.Errorf("relay: bad room id %q", id)
	}
	return c.landing(ctx, "/f/"+id)
}

// RoomSocket is one member's WebSocket on a room's records route: every
// record another idx puts while it is open arrives as a frame. It pings
// every PingEvery until it is closed.
type RoomSocket struct{ s *Socket }

// SubscribeRoom opens the push socket on room id with a member token. A
// refusal before the upgrade is an *Error (revoked, bad_token,
// no_such_room, rate_limited, too_many_sockets); an answer that is not an
// upgrade is ErrNoPush.
func (c *Client) SubscribeRoom(ctx context.Context, id, token string) (*RoomSocket, error) {
	if err := checkRoom(id, token); err != nil {
		return nil, err
	}
	s, err := c.dial(ctx, "/r/"+id+"/records", token)
	if err != nil {
		return nil, err
	}
	return &RoomSocket{s}, nil
}

// Next returns the next pushed record, validated as a pulled one is. A
// close the relay sends for good — 4401 when the idx is revoked, 4404 — is
// ErrRevoked or ErrNoSuchRoom; any other close or failure is returned as
// it is and the caller reconnects. A frame without a seq is ErrAnswer.
func (r *RoomSocket) Next(ctx context.Context) (RoomRecord, error) {
	b, err := r.s.next(ctx)
	switch websocket.CloseStatus(err) {
	case closeBadToken:
		return RoomRecord{}, ErrRevoked
	case closeNoSuchRoom:
		return RoomRecord{}, ErrNoSuchRoom
	}
	if err != nil {
		return RoomRecord{}, err
	}
	var row roomRow
	if err := json.Unmarshal(b, &row); err != nil {
		return RoomRecord{}, fmt.Errorf("%w: frame: %v", ErrAnswer, err)
	}
	if !version(row.Seq) {
		return RoomRecord{}, fmt.Errorf("%w: frame without a seq", ErrAnswer)
	}
	return row.record(), nil
}

// Close closes the socket from this side, without waiting on the relay.
func (r *RoomSocket) Close() error { return r.s.Close() }

// roomRow is one record as the relay answers it, in a pull page or a frame.
type roomRow struct {
	Seq  *int64 `json:"seq"`
	Idx  *int   `json:"idx"`
	Type string `json:"type"`
	Body string `json:"body"`
	At   *int64 `json:"at"`
}

// record is the row as a RoomRecord; its seq is present and checked by the
// caller.
func (r roomRow) record() RoomRecord {
	rec := RoomRecord{Seq: *r.Seq, Idx: -1}
	if r.Idx != nil {
		rec.Idx = *r.Idx
	}
	if r.At != nil {
		rec.At = time.UnixMilli(*r.At)
	}
	body, err := base64.StdEncoding.Strict().DecodeString(r.Body)
	switch {
	case r.Idx == nil || !ValidIdx(*r.Idx):
		rec.Err = fmt.Errorf("%w: record %d: idx missing or out of range", ErrAnswer, rec.Seq)
	case r.Type != "sealed":
		rec.Err = fmt.Errorf("%w: record %d: type %q", ErrAnswer, rec.Seq, r.Type)
	case err != nil:
		rec.Err = fmt.Errorf("%w: record %d: body: %v", ErrAnswer, rec.Seq, err)
	case len(body) == 0 || len(body) > MaxSealed:
		rec.Err = fmt.Errorf("%w: record %d: body of %d bytes", ErrAnswer, rec.Seq, len(body))
	case r.At == nil:
		rec.Err = fmt.Errorf("%w: record %d: no at", ErrAnswer, rec.Seq)
	default:
		rec.Body = body
	}
	return rec
}

// membership does one request whose answer is {membership}.
func (c *Client) membership(ctx context.Context, method, path, token string, in any) (int64, error) {
	var out struct {
		Membership *int64 `json:"membership"`
	}
	if err := c.do(ctx, method, path, token, in, &out, maxSmallAnswer); err != nil {
		return 0, err
	}
	if !version(out.Membership) {
		return 0, fmt.Errorf("%w: membership answer", ErrAnswer)
	}
	return *out.Membership, nil
}

// version reports whether a counter the relay answered is present and >= 0.
func version(n *int64) bool { return n != nil && *n >= 0 }

func checkRoom(id, token string) error {
	if !ValidRoomID(id) {
		return fmt.Errorf("relay: bad room id %q", id)
	}
	if !ValidToken(token) {
		return fmt.Errorf("relay: bad token form")
	}
	return nil
}
