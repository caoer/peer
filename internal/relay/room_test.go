package relay_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
)

const roomLogin = "zt:owner-secret"

func sealed(b byte) []byte { return bytes.Repeat([]byte{b}, 200) }

// room starts a fake relay and creates a room with add.
func room(t *testing.T, add string) (*relaytest.Server, *relay.Client, relay.Room) {
	t.Helper()
	srv, c, _ := relaytest.Start(t, roomLogin)
	rm, err := c.CreateRoom(context.Background(), roomLogin, add)
	if err != nil {
		t.Fatal(err)
	}
	return srv, c, rm
}

func mint(t *testing.T, c *relay.Client, id, token, role string) relay.Minted {
	t.Helper()
	m, err := c.AddMember(context.Background(), id, token, role)
	if err != nil {
		t.Fatalf("mint %s: %v", role, err)
	}
	return m
}

// Every room route round-trips through the client and the fake.
func TestRoomRoutesRoundTrip(t *testing.T) {
	ctx := context.Background()
	srv, c, rm := room(t, "")
	if rm.Membership != 0 {
		t.Fatalf("create: %+v", rm)
	}
	if text, err := c.FeedLanding(ctx, rm.ID); err != nil || !strings.Contains(text, "peer") {
		t.Fatalf("feed landing: %q %v", text, err)
	}
	a := rm.AdminToken
	b := mint(t, c, rm.ID, a, relay.RoleWrite)
	r := mint(t, c, rm.ID, a, relay.RoleRead)
	if b.Idx != 1 || b.From != 0 || b.Membership != 1 || r.Idx != 2 || r.Membership != 2 {
		t.Fatalf("mints: %+v %+v", b, r)
	}

	got, err := c.PutRecord(ctx, rm.ID, a, sealed(1), 2, false)
	if err != nil || got.Seq != 0 || got.Membership != 2 {
		t.Fatalf("A put: %+v %v", got, err)
	}
	if got, err = c.PutRecord(ctx, rm.ID, b.Token, sealed(2), 2, false); err != nil || got.Seq != 1 {
		t.Fatalf("B put: %+v %v", got, err)
	}
	page, err := c.PullRoom(ctx, rm.ID, b.Token, -1)
	if err != nil || page.Membership != 2 || len(page.Records) != 1 {
		t.Fatalf("B pull: %+v %v", page, err)
	}
	if rec := page.Records[0]; rec.Seq != 0 || rec.Idx != 0 || rec.Err != nil || !bytes.Equal(rec.Body, sealed(1)) || rec.At.IsZero() {
		t.Fatalf("B's record: %+v", rec)
	}
	if page, err = c.PullRoom(ctx, rm.ID, r.Token, -1); err != nil || len(page.Records) != 2 || page.Records[1].Idx != 1 {
		t.Fatalf("reader pull: %+v %v", page, err)
	}
	if page, err = c.PullRoom(ctx, rm.ID, r.Token, 1); err != nil || len(page.Records) != 0 {
		t.Fatalf("caught-up pull: %+v %v", page, err)
	}

	bAdmin, v, err := c.GrantAdmin(ctx, rm.ID, a, b.Idx)
	if err != nil || v != 3 || bAdmin == b.Token {
		t.Fatalf("grant: %v %v", v, err)
	}
	ms, err := c.ListMembers(ctx, rm.ID, bAdmin)
	if err != nil || ms.Membership != 3 || len(ms.Members) != 3 {
		t.Fatalf("members: %+v %v", ms, err)
	}
	want := []relay.Member{{0, "write", 0, true, false}, {1, "write", 0, true, false}, {2, "read", 0, false, false}}
	for i, m := range ms.Members {
		if m != want[i] {
			t.Fatalf("member %d: %+v, want %+v", i, m, want[i])
		}
	}

	if v, err = c.LeaveRoom(ctx, rm.ID, r.Token); err != nil || v != 4 {
		t.Fatalf("reader leave: %v %v", v, err)
	}
	if v, err = c.RemoveMember(ctx, rm.ID, bAdmin, 0); err != nil || v != 5 {
		t.Fatalf("B removes A: %v %v", v, err)
	}
	if ms, err = c.ListMembers(ctx, rm.ID, bAdmin); err != nil || !ms.Members[0].Revoked || !ms.Members[2].Revoked || ms.Members[1].Revoked {
		t.Fatalf("members after: %+v %v", ms, err)
	}
	if srv.RoomMembership(rm.ID) != 5 || len(srv.RoomRecords(rm.ID)) != 2 {
		t.Fatalf("relay holds %d at %d", len(srv.RoomRecords(rm.ID)), srv.RoomMembership(rm.ID))
	}
}

// Each code the contract names for the room routes, through the client.
func TestRoomCodes(t *testing.T) {
	ctx := context.Background()
	_, c, rm := room(t, relay.AddAdmins)
	a := rm.AdminToken
	b := mint(t, c, rm.ID, a, relay.RoleWrite)
	r := mint(t, c, rm.ID, a, relay.RoleRead)
	m := int64(2)
	other := strings.Repeat("ab", 16)

	cases := []struct {
		name string
		err  error
		want *relay.Error
	}{
		{"create wrong login", second(c.CreateRoom(ctx, "zt:wrong", "")), relay.ErrBadToken},
		{"no such room", second(c.PullRoom(ctx, other, a, -1)), relay.ErrNoSuchRoom},
		{"stranger's token", second(c.PullRoom(ctx, rm.ID, strings.Repeat("B", 43), -1)), relay.ErrBadToken},
		{"writer mints under admins", second(c.AddMember(ctx, rm.ID, b.Token, relay.RoleRead)), relay.ErrNotAdmin},
		{"writer lists", second(c.ListMembers(ctx, rm.ID, b.Token)), relay.ErrNotAdmin},
		{"writer revokes", second(c.RemoveMember(ctx, rm.ID, b.Token, 2)), relay.ErrNotAdmin},
		{"writer grants", third(c.GrantAdmin(ctx, rm.ID, b.Token, 1)), relay.ErrNotAdmin},
		{"reader puts", second(c.PutRecord(ctx, rm.ID, r.Token, sealed(1), m, false)), relay.ErrReadOnly},
		{"writer bumps", second(c.PutRecord(ctx, rm.ID, b.Token, sealed(1), m, true)), relay.ErrReadOnly},
		{"put above current", second(c.PutRecord(ctx, rm.ID, a, sealed(1), m+1, false)), relay.ErrBadRequest},
		{"grant to a reader", third(c.GrantAdmin(ctx, rm.ID, a, r.Idx)), relay.ErrReadOnly},
		{"grant to no one", third(c.GrantAdmin(ctx, rm.ID, a, 9)), relay.ErrNoSuchMember},
		{"revoke no one", second(c.RemoveMember(ctx, rm.ID, a, 9)), relay.ErrNoSuchMember},
	}
	for _, tc := range cases {
		var e *relay.Error
		if !errors.Is(tc.err, tc.want) || !errors.As(tc.err, &e) || e.Status != tc.want.Status {
			t.Errorf("%s: %v, want %d %s", tc.name, tc.err, tc.want.Status, tc.want.Code)
		}
	}

	// A revoke is idempotent; the revoked token is refused on every route.
	if v, err := c.RemoveMember(ctx, rm.ID, a, b.Idx); err != nil || v != 3 {
		t.Fatalf("revoke: %v %v", v, err)
	}
	if v, err := c.RemoveMember(ctx, rm.ID, a, b.Idx); err != nil || v != 3 {
		t.Fatalf("revoke again: %v %v", v, err)
	}
	if _, _, err := c.GrantAdmin(ctx, rm.ID, a, b.Idx); !errors.Is(err, relay.ErrNoSuchMember) {
		t.Errorf("grant to the revoked: %v", err)
	}
	for name, err := range map[string]error{
		"pull":  second(c.PullRoom(ctx, rm.ID, b.Token, -1)),
		"put":   second(c.PutRecord(ctx, rm.ID, b.Token, sealed(1), 3, false)),
		"leave": second(c.LeaveRoom(ctx, rm.ID, b.Token)),
		"mint":  second(c.AddMember(ctx, rm.ID, b.Token, relay.RoleRead)),
	} {
		if !errors.Is(err, relay.ErrRevoked) {
			t.Errorf("revoked %s: %v", name, err)
		}
	}

	// Under add: members any write member mints; a reader does not.
	_, c2, rm2 := room(t, relay.AddMembers)
	w := mint(t, c2, rm2.ID, rm2.AdminToken, relay.RoleWrite)
	rd := mint(t, c2, rm2.ID, w.Token, relay.RoleRead)
	if _, err := c2.AddMember(ctx, rm2.ID, rd.Token, relay.RoleRead); !errors.Is(err, relay.ErrNotAdmin) {
		t.Errorf("reader mints under members: %v", err)
	}
	if _, err := c2.ListMembers(ctx, rm2.ID, w.Token); !errors.Is(err, relay.ErrNotAdmin) {
		t.Errorf("non-admin lists under members: %v", err)
	}

	// Refused on the host, before the relay.
	for name, err := range map[string]error{
		"bad add":       second(c.CreateRoom(ctx, roomLogin, "everyone")),
		"bad role":      second(c.AddMember(ctx, rm.ID, a, "owner")),
		"empty record":  second(c.PutRecord(ctx, rm.ID, a, nil, 3, false)),
		"over 1 MiB":    second(c.PutRecord(ctx, rm.ID, a, make([]byte, relay.MaxSealed+1), 3, false)),
		"negative m":    second(c.PutRecord(ctx, rm.ID, a, sealed(1), -1, false)),
		"bad room id":   second(c.PullRoom(ctx, "NOT-HEX", a, -1)),
		"bad token":     second(c.PullRoom(ctx, rm.ID, "short", -1)),
		"after -2":      second(c.PullRoom(ctx, rm.ID, a, -2)),
		"feed idx":      second(c.RemoveMember(ctx, rm.ID, a, relay.FeedIdx)),
		"bad feed room": second(c.FeedLanding(ctx, "x")),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := c.PutRecord(ctx, rm.ID, a, make([]byte, relay.MaxSealed+1), 3, false); !errors.Is(err, relay.ErrTooLarge) {
		t.Errorf("over 1 MiB: %v", err)
	}
}

// A put sealed under a membership version the relay has moved past is
// refused 409 before anything is stored; at the version a pull reports, it lands.
func TestRoomStaleMembership(t *testing.T) {
	ctx := context.Background()
	srv, c, rm := room(t, "")
	b := mint(t, c, rm.ID, rm.AdminToken, relay.RoleWrite)
	if _, err := c.PutRecord(ctx, rm.ID, b.Token, sealed(1), b.Membership, false); err != nil {
		t.Fatal(err)
	}
	mint(t, c, rm.ID, rm.AdminToken, relay.RoleWrite)

	_, err := c.PutRecord(ctx, rm.ID, b.Token, sealed(2), b.Membership, false)
	var e *relay.Error
	if !errors.Is(err, relay.ErrStaleMembership) || !errors.As(err, &e) || e.Status != 409 {
		t.Fatalf("stale put: %v", err)
	}
	if n := len(srv.RoomRecords(rm.ID)); n != 1 {
		t.Fatalf("relay stored the stale put: %d records", n)
	}
	page, err := c.PullRoom(ctx, rm.ID, b.Token, -1)
	if err != nil || page.Membership != 2 {
		t.Fatalf("pull: %+v %v", page, err)
	}
	if got, err := c.PutRecord(ctx, rm.ID, b.Token, sealed(2), page.Membership, false); err != nil || got.Seq != 1 || got.Membership != 2 {
		t.Fatalf("re-sealed put: %+v %v", got, err)
	}
}

// bump appends the removal record and moves the version in one step: a put
// at the old version after it is 409, before the revoke.
func TestRoomBump(t *testing.T) {
	ctx := context.Background()
	srv, c, rm := room(t, "")
	b := mint(t, c, rm.ID, rm.AdminToken, relay.RoleWrite)
	got, err := c.PutRecord(ctx, rm.ID, rm.AdminToken, sealed(9), b.Membership, true)
	if err != nil || got.Seq != 0 || got.Membership != b.Membership+1 {
		t.Fatalf("bump put: %+v %v", got, err)
	}
	if srv.RoomMembership(rm.ID) != 2 || len(srv.RoomRecords(rm.ID)) != 1 {
		t.Fatal("bump did not land with its record")
	}
	if _, err := c.PutRecord(ctx, rm.ID, b.Token, sealed(1), b.Membership, false); !errors.Is(err, relay.ErrStaleMembership) {
		t.Fatalf("put at the old version: %v", err)
	}
	if page, err := c.PullRoom(ctx, rm.ID, b.Token, -1); err != nil || len(page.Records) != 1 || !bytes.Equal(page.Records[0].Body, sealed(9)) {
		t.Fatalf("the leaver still reads the removal record: %+v %v", page, err)
	}
	if v, err := c.RemoveMember(ctx, rm.ID, rm.AdminToken, b.Idx); err != nil || v != 3 {
		t.Fatalf("revoke: %v %v", v, err)
	}
}

// A newcomer reads nothing below its from, and pages up from there.
func TestRoomFromFloor(t *testing.T) {
	ctx := context.Background()
	srv, c, rm := room(t, "")
	srv.PageSize = 2
	a := rm.AdminToken
	for i := 0; i < 3; i++ {
		if _, err := c.PutRecord(ctx, rm.ID, a, sealed(byte(i)), 0, false); err != nil {
			t.Fatal(err)
		}
	}
	n := mint(t, c, rm.ID, a, relay.RoleWrite)
	if n.From != 3 {
		t.Fatalf("from %d, want the log head 3", n.From)
	}
	if page, err := c.PullRoom(ctx, rm.ID, n.Token, -1); err != nil || len(page.Records) != 0 {
		t.Fatalf("newcomer reads below from: %+v %v", page, err)
	}
	for i := 3; i < 8; i++ {
		if _, err := c.PutRecord(ctx, rm.ID, a, sealed(byte(i)), n.Membership, false); err != nil {
			t.Fatal(err)
		}
	}
	all, err := c.PullRoomAll(ctx, rm.ID, n.Token, -1)
	if err != nil || len(all.Records) != 5 || all.Membership != 1 {
		t.Fatalf("pull all: %d %v", len(all.Records), err)
	}
	for i, rec := range all.Records {
		if rec.Seq != int64(i+3) || rec.Body[0] != byte(i+3) {
			t.Fatalf("record %d: %+v", i, rec)
		}
	}
	if rest, err := c.PullRoomAll(ctx, rm.ID, n.Token, 5); err != nil || len(rest.Records) != 2 {
		t.Fatalf("from 5: %d %v", len(rest.Records), err)
	}
}

// Push carries another idx's records; a revoke closes the socket 4401 and a
// revoked token is refused before the upgrade.
func TestRoomPush(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv, c, rm := room(t, "")
	b := mint(t, c, rm.ID, rm.AdminToken, relay.RoleWrite)
	sock, err := c.SubscribeRoom(ctx, rm.ID, b.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	for srv.RoomSockets(rm.ID, b.Idx) != 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := c.PutRecord(ctx, rm.ID, b.Token, sealed(1), 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutRecord(ctx, rm.ID, rm.AdminToken, sealed(2), 1, false); err != nil {
		t.Fatal(err)
	}
	rec, err := sock.Next(ctx)
	if err != nil || rec.Seq != 1 || rec.Idx != 0 || !bytes.Equal(rec.Body, sealed(2)) {
		t.Fatalf("pushed: %+v %v", rec, err)
	}
	if _, err := c.RemoveMember(ctx, rm.ID, rm.AdminToken, b.Idx); err != nil {
		t.Fatal(err)
	}
	if _, err := sock.Next(ctx); !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("after revoke: %v", err)
	}
	if _, err := c.SubscribeRoom(ctx, rm.ID, b.Token); !errors.Is(err, relay.ErrRevoked) {
		t.Fatalf("revoked upgrade: %v", err)
	}
	if _, err := c.SubscribeRoom(ctx, strings.Repeat("cd", 16), rm.AdminToken); !errors.Is(err, relay.ErrNoSuchRoom) {
		t.Fatalf("no room upgrade: %v", err)
	}
}

// A hostile relay: malformed records come back with Err set and their seq
// kept; a broken answer is ErrAnswer; nothing panics.
func TestRoomHostileRelay(t *testing.T) {
	ctx := context.Background()
	good := base64.StdEncoding.EncodeToString(sealed(1))
	tok := strings.Repeat("A", 43)
	id := strings.Repeat("0", 32)
	serve := func(body string) *relay.Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return relay.New(srv.URL+"/peer", srv.Client())
	}

	c := serve(`{"membership":4,"records":[
		{"seq":0,"idx":1,"type":"sealed","body":"` + good + `","at":1},
		{"seq":1,"idx":1,"type":"msg","body":"` + good + `","at":1},
		{"seq":2,"idx":1,"type":"sealed","body":"!!notbase64","at":1},
		{"seq":3,"idx":1,"type":"sealed","body":"","at":1},
		{"seq":4,"type":"sealed","body":"` + good + `","at":1},
		{"seq":5,"idx":65535,"type":"sealed","body":"` + good + `","at":1},
		{"seq":6,"idx":1,"type":"sealed","body":"` + good + `"}]}`)
	page, err := c.PullRoom(ctx, id, tok, -1)
	if err != nil || len(page.Records) != 7 || page.Membership != 4 {
		t.Fatalf("%+v %v", page, err)
	}
	if page.Records[0].Err != nil {
		t.Fatalf("good record refused: %v", page.Records[0].Err)
	}
	for i, rec := range page.Records[1:] {
		if rec.Err == nil || rec.Body != nil || rec.Seq != int64(i+1) {
			t.Fatalf("seq %d accepted: %+v", i+1, rec)
		}
	}

	row := `{"seq":0,"idx":1,"type":"sealed","body":"` + good + `","at":1}`
	pulls := map[string]string{
		"not json":       `<html>`,
		"array":          `[` + row + `]`,
		"no membership":  `{"records":[]}`,
		"no records":     `{"membership":1}`,
		"seq missing":    `{"membership":1,"records":[{"idx":1,"type":"sealed","body":"` + good + `","at":1}]}`,
		"seq descending": `{"membership":1,"records":[{"seq":3},{"seq":2}]}`,
		"over 100":       `{"membership":1,"records":[` + strings.Repeat(`{"seq":0},`, 100) + `{"seq":0}]}`,
	}
	for name, body := range pulls {
		if _, err := serve(body).PullRoom(ctx, id, tok, -1); !errors.Is(err, relay.ErrAnswer) {
			t.Errorf("pull %s: %v", name, err)
		}
	}

	answers := map[string]func(*relay.Client) error{
		`{"id":"x","adminToken":"` + tok + `","membership":0}`: func(c *relay.Client) error { return second(c.CreateRoom(ctx, roomLogin, "")) },
		`{"id":"` + id + `","adminToken":"` + tok + `"}`:       func(c *relay.Client) error { return second(c.CreateRoom(ctx, roomLogin, "")) },
		`{"idx":65535,"token":"` + tok + `","from":0,"membership":1}`: func(c *relay.Client) error {
			return second(c.AddMember(ctx, id, tok, relay.RoleWrite))
		},
		`{"idx":1,"token":"` + tok + `","membership":1}`: func(c *relay.Client) error { return second(c.AddMember(ctx, id, tok, relay.RoleWrite)) },
		`{"membership":-1}`:                func(c *relay.Client) error { return second(c.RemoveMember(ctx, id, tok, 1)) },
		`{"token":"short","membership":2}`: func(c *relay.Client) error { return third(c.GrantAdmin(ctx, id, tok, 1)) },
		`{"membership":1,"members":[{"idx":0,"role":"write","from":0},{"idx":0,"role":"write","from":0}]}`: func(c *relay.Client) error {
			return second(c.ListMembers(ctx, id, tok))
		},
		`{"membership":1,"members":[{"idx":0,"role":"owner","from":0}]}`: func(c *relay.Client) error { return second(c.ListMembers(ctx, id, tok)) },
		`{"seq":0,"membership":2}`:                                       func(c *relay.Client) error { return second(c.PutRecord(ctx, id, tok, sealed(1), 1, false)) },
		`{"seq":0,"membership":1}`:                                       func(c *relay.Client) error { return second(c.PutRecord(ctx, id, tok, sealed(1), 1, true)) },
		`{"membership":1}`:                                               func(c *relay.Client) error { return second(c.PutRecord(ctx, id, tok, sealed(1), 1, false)) },
	}
	for body, call := range answers {
		if err := call(serve(body)); !errors.Is(err, relay.ErrAnswer) {
			t.Errorf("answer %s: %v", body, err)
		}
	}
}

func second[T any](_ T, err error) error        { return err }
func third[T, U any](_ T, _ U, err error) error { return err }
