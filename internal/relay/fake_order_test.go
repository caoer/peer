package relay_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// The real relay checks the route and method, then that a bearer is there,
// then the request, and reaches the room last; the fake answers the same
// code for the same request, so a test against it says what production says.
func TestFakeChecksTheRequestBeforeTheRoom(t *testing.T) {
	ctx := context.Background()
	_, c, base := relaytest.Start(t, roomLogin)
	rm, err := c.CreateRoom(ctx, roomLogin, "")
	if err != nil {
		t.Fatal(err)
	}
	b := mint(t, c, rm.ID, rm.AdminToken, relay.RoleWrite)
	if _, err := c.RemoveMember(ctx, rm.ID, rm.AdminToken, b.Idx); err != nil {
		t.Fatal(err)
	}
	unknown := strings.Repeat("ab", 16)
	cases := []struct {
		name, method, path, token, body string
		status                          int
		code                            string
	}{
		{"revoked token, bad body", "POST", "/r/" + rm.ID + "/records", b.Token, `{"type":"sealed","body":"!!","membership":0}`, 400, "bad_request"},
		{"membership below zero", "POST", "/r/" + rm.ID + "/records", rm.AdminToken, `{"type":"sealed","body":"AAAA","membership":-1}`, 400, "bad_request"},
		{"wrong method", "DELETE", "/r/" + rm.ID + "/records", rm.AdminToken, "", 405, "method_not_allowed"},
		{"unknown room, no bearer", "GET", "/r/" + unknown + "/records", "", "", 401, "bad_token"},
		{"unknown room, a bearer", "GET", "/r/" + unknown + "/records", rm.AdminToken, "", 404, "no_such_room"},
		{"grant past the last idx", "POST", "/r/" + rm.ID + "/admin", rm.AdminToken, `{"idx":70000}`, 400, "bad_request"},
		{"after empty", "GET", "/r/" + rm.ID + "/records?after=", rm.AdminToken, "", 400, "bad_request"},
		{"feed landing, room id form, no room", "GET", "/f/" + unknown, "", "", 200, ""},
		{"feed landing, not a room id", "GET", "/f/nope", "", "", 404, "no_such_room"},
		{"revoked token on a good request", "GET", "/r/" + rm.ID + "/records?after=-1", b.Token, "", 401, "revoked"},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(tc.method, base+tc.path, strings.NewReader(tc.body))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(res.Body)
		res.Body.Close()
		var ans struct{ Code string }
		json.Unmarshal(out, &ans)
		if res.StatusCode != tc.status || ans.Code != tc.code {
			t.Errorf("%s: %d %q, want %d %q", tc.name, res.StatusCode, ans.Code, tc.status, tc.code)
		}
	}
}
