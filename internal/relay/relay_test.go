package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caoer/peer/internal/envelope"
)

const login = "zt:owner-secret"

// fakeRelay serves results/wire-contract.md from memory.
type fakeRelay struct {
	mu       sync.Mutex
	channels map[string]*channel
	pageSize int
	// raw, when set, replaces the envelopes answer (hostile relay).
	raw string
}

type row struct {
	Seq  int64  `json:"seq"`
	Type string `json:"type"`
	Body string `json:"body"`
	At   int64  `json:"at"`
}

type channel struct {
	host, guest, invite string
	inviteUsed          bool
	env                 map[string][]row // by dir
	prekeys             map[string][]Prekey
}

func token() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newFake() *fakeRelay {
	return &fakeRelay{channels: map[string]*channel{}, pageSize: 100}
}

func fail(w http.ResponseWriter, e *Error) {
	w.WriteHeader(e.Status)
	json.NewEncoder(w).Encode(map[string]string{"error": e.Code + " (fake)", "code": e.Code})
}

func (f *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/peer")
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ok := func(v any) { json.NewEncoder(w).Encode(v) }

	if p == "/channels" {
		if r.Method != http.MethodPost {
			fail(w, ErrMethodNotAllowed)
			return
		}
		if bearer != login {
			fail(w, ErrBadToken)
			return
		}
		b := make([]byte, 16)
		rand.Read(b)
		id := hex.EncodeToString(b)
		f.channels[id] = &channel{host: token(), invite: token(),
			env: map[string][]row{}, prekeys: map[string][]Prekey{}}
		ok(Channel{ID: id, HostToken: f.channels[id].host, InviteToken: f.channels[id].invite})
		return
	}
	if strings.HasPrefix(p, "/i/") {
		if _, found := f.channels[p[3:]]; !found {
			fail(w, ErrNoSuchChannel)
			return
		}
		w.Write([]byte("this is a peer invite; install peer and run peer accept <link>"))
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(p, "/c/"), "/", 2)
	if !strings.HasPrefix(p, "/c/") || len(parts) != 2 {
		fail(w, ErrNoSuchRoute)
		return
	}
	ch, found := f.channels[parts[0]]
	if !found {
		fail(w, ErrNoSuchChannel)
		return
	}
	if parts[1] == "join" {
		var in struct{ InviteToken string }
		json.NewDecoder(r.Body).Decode(&in)
		switch {
		case r.Header.Get("Authorization") != "":
			fail(w, ErrBadRequest) // the contract: no Authorization on join
		case in.InviteToken != ch.invite:
			fail(w, ErrBadToken)
		case ch.inviteUsed:
			fail(w, ErrTokenUsed)
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
		fail(w, ErrBadToken)
		return
	}
	switch {
	case parts[1] == "envelopes" && r.Method == http.MethodPost:
		var in struct{ Type, Body string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, ErrBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(in.Body)
		if err != nil || (in.Type != "card" && in.Type != "prekey" && in.Type != "msg") {
			fail(w, ErrBadRequest)
			return
		}
		if len(raw) > envelope.MaxBody {
			fail(w, ErrTooLarge)
			return
		}
		seq := int64(len(ch.env[own]))
		ch.env[own] = append(ch.env[own], row{seq, in.Type, in.Body, time.Now().UnixMilli()})
		ok(Receipt{Dir: own, Seq: seq})
	case parts[1] == "envelopes" && r.Method == http.MethodGet:
		if f.raw != "" {
			w.Write([]byte(f.raw))
			return
		}
		after := int64(-1)
		if s := r.URL.Query().Get("after"); s != "" {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				fail(w, ErrBadRequest)
				return
			}
			after = n
		}
		page := []row{}
		for _, e := range ch.env[other] {
			if e.Seq > after && len(page) < f.pageSize {
				page = append(page, e)
			}
		}
		ok(page)
	case parts[1] == "prekeys" && r.Method == http.MethodPut:
		var in struct{ Keys []Prekey }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, ErrBadRequest)
			return
		}
		if len(in.Keys) > 100 {
			fail(w, ErrTooLarge)
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
		fail(w, ErrNoSuchRoute)
	}
}

func start(t *testing.T) (*fakeRelay, *Client) {
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, New(srv.URL+"/peer", srv.Client())
}

func msgEnv(b byte) envelope.Envelope {
	// a structurally valid SignalMessage: ratchet key + ciphertext + MAC
	body := []byte{0x33, 0x0a, 33, 0x05}
	for i := 1; i <= 32; i++ {
		body = append(body, byte(i))
	}
	body = append(body, 0x22, 1, b)
	body = append(body, make([]byte, 8)...)
	return envelope.Envelope{Type: envelope.Msg, Body: body}
}

func pub(b byte) []byte {
	k := bytes.Repeat([]byte{b}, 33)
	k[0] = 0x05
	return k
}

// Every route, both directions.
func TestRoutesRoundTrip(t *testing.T) {
	ctx := context.Background()
	_, c := start(t)

	ch, err := c.Create(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	card, err := envelope.PackCard([]byte(`{"v":1}`), make([]byte, envelope.SigSize))
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Put(ctx, ch.ID, ch.HostToken, card)
	if err != nil || r.Dir != "h2g" || r.Seq != 0 {
		t.Fatalf("host card: %+v %v", r, err)
	}
	if n, err := c.PutPrekeys(ctx, ch.ID, ch.HostToken, []Prekey{{1, pub(1)}, {2, pub(2)}}); err != nil || n != 2 {
		t.Fatalf("host prekeys: %d %v", n, err)
	}
	if n, err := c.PutPrekeys(ctx, ch.ID, ch.HostToken, []Prekey{{2, pub(2)}}); err != nil || n != 2 {
		t.Fatalf("repeated id: %d %v", n, err)
	}
	landing, err := c.Landing(ctx, ch.ID)
	if err != nil || !strings.Contains(landing, "peer accept") {
		t.Fatalf("landing: %q %v", landing, err)
	}

	guest, err := c.Join(ctx, ch.ID, ch.InviteToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Join(ctx, ch.ID, ch.InviteToken); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second join: %v", err)
	}
	recs, err := c.Pull(ctx, ch.ID, guest, -1)
	if err != nil || len(recs) != 1 || recs[0].Err != nil || recs[0].Seq != 0 ||
		recs[0].Env.Type != envelope.Card || !bytes.Equal(recs[0].Env.Body, card.Body) || recs[0].At.IsZero() {
		t.Fatalf("guest pull: %+v %v", recs, err)
	}
	k, ok, err := c.TakePrekey(ctx, ch.ID, guest)
	if err != nil || !ok || k.ID != 1 || !bytes.Equal(k.Pub, pub(1)) {
		t.Fatalf("take: %+v %v %v", k, ok, err)
	}
	r, err = c.Put(ctx, ch.ID, guest, msgEnv(1))
	if err != nil || r.Dir != "g2h" || r.Seq != 0 {
		t.Fatalf("guest put: %+v %v", r, err)
	}
	if _, err := c.PutPrekeys(ctx, ch.ID, guest, []Prekey{{9, pub(9)}}); err != nil {
		t.Fatal(err)
	}

	recs, err = c.Pull(ctx, ch.ID, ch.HostToken, -1)
	if err != nil || len(recs) != 1 || recs[0].Env.Type != envelope.Msg || !bytes.Equal(recs[0].Env.Body, msgEnv(1).Body) {
		t.Fatalf("host pull: %+v %v", recs, err)
	}
	if recs, err := c.Pull(ctx, ch.ID, ch.HostToken, 0); err != nil || len(recs) != 0 {
		t.Fatalf("caught-up pull: %+v %v", recs, err)
	}
	if k, ok, err := c.TakePrekey(ctx, ch.ID, ch.HostToken); err != nil || !ok || k.ID != 9 {
		t.Fatalf("host take: %+v %v %v", k, ok, err)
	}
	if _, ok, err := c.TakePrekey(ctx, ch.ID, ch.HostToken); err != nil || ok {
		t.Fatalf("empty take: %v %v", ok, err)
	}
}

func TestPullAllPages(t *testing.T) {
	ctx := context.Background()
	f, c := start(t)
	f.pageSize = 3
	ch, _ := c.Create(ctx, login)
	guest, _ := c.Join(ctx, ch.ID, ch.InviteToken)
	for i := 0; i < 8; i++ {
		if _, err := c.Put(ctx, ch.ID, ch.HostToken, msgEnv(byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	all, err := c.PullAll(ctx, ch.ID, guest, -1)
	if err != nil || len(all) != 8 {
		t.Fatalf("%d records, %v", len(all), err)
	}
	for i, r := range all {
		if r.Seq != int64(i) || r.Err != nil || r.Env.Body[38] != byte(i) {
			t.Fatalf("record %d: %+v", i, r)
		}
	}
	if rest, err := c.PullAll(ctx, ch.ID, guest, 5); err != nil || len(rest) != 2 {
		t.Fatalf("from 5: %d %v", len(rest), err)
	}
}

func TestErrorCodes(t *testing.T) {
	ctx := context.Background()
	_, c := start(t)
	if _, err := c.Create(ctx, "zt:wrong"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("create wrong login: %v", err)
	}
	ch, _ := c.Create(ctx, login)
	if _, err := c.Join(ctx, ch.ID, token()); !errors.Is(err, ErrBadToken) {
		t.Fatalf("join wrong invite: %v", err)
	}
	if _, err := c.Pull(ctx, ch.ID, token(), -1); !errors.Is(err, ErrBadToken) {
		t.Fatalf("pull wrong token: %v", err)
	}
	other := strings.Repeat("ab", 16)
	if _, err := c.Pull(ctx, other, ch.HostToken, -1); !errors.Is(err, ErrNoSuchChannel) {
		t.Fatalf("no channel: %v", err)
	}
	var e *Error
	_, err := c.Pull(ctx, other, ch.HostToken, -1)
	if !errors.As(err, &e) || e.Status != 404 || errors.Is(err, ErrNoSuchRoute) {
		t.Fatalf("error detail: %#v", err)
	}
	// Client-side refusals never reach the relay.
	if _, err := c.Put(ctx, ch.ID, ch.HostToken, envelope.Envelope{Type: envelope.Card, Body: make([]byte, envelope.MaxBody+1)}); !errors.Is(err, envelope.ErrTooLarge) {
		t.Fatalf("oversized put: %v", err)
	}
	if _, err := c.Put(ctx, "NOT-HEX", ch.HostToken, msgEnv(1)); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, err := c.Put(ctx, ch.ID, "short", msgEnv(1)); err == nil {
		t.Fatal("bad token form accepted")
	}
	keys := make([]Prekey, 101)
	for i := range keys {
		keys[i] = Prekey{uint32(i), pub(1)}
	}
	if _, err := c.PutPrekeys(ctx, ch.ID, ch.HostToken, keys); err == nil {
		t.Fatal("101 prekeys accepted")
	}
	if _, err := c.PutPrekeys(ctx, ch.ID, ch.HostToken, []Prekey{{1, []byte{5, 1}}}); err == nil {
		t.Fatal("short prekey accepted")
	}
	if _, err := c.Pull(ctx, ch.ID, ch.HostToken, -2); err == nil {
		t.Fatal("after -2 accepted")
	}
}

// A hostile or broken relay: malformed records come back with Err set and
// their seq kept; a broken answer is an error; nothing panics.
func TestHostileRelay(t *testing.T) {
	ctx := context.Background()
	f, c := start(t)
	ch, _ := c.Create(ctx, login)
	good := base64.StdEncoding.EncodeToString(msgEnv(1).Body)
	emptyRatchet := base64.StdEncoding.EncodeToString(append([]byte{0x33, 0x0a, 0, 0x22, 1, 1}, make([]byte, 8)...))

	f.raw = `[{"seq":0,"type":"msg","body":"` + good + `","at":1},
	         {"seq":1,"type":"blob","body":"` + good + `","at":1},
	         {"seq":2,"type":"msg","body":"!!notbase64","at":1},
	         {"seq":3,"type":"msg","body":"` + emptyRatchet + `","at":1},
	         {"seq":4,"type":"msg","body":"","at":1},
	         {"seq":5,"type":"msg","body":"` + good + `"}]`
	recs, err := c.Pull(ctx, ch.ID, ch.HostToken, -1)
	if err != nil || len(recs) != 6 {
		t.Fatalf("%d records, %v", len(recs), err)
	}
	if recs[0].Err != nil {
		t.Fatalf("good record refused: %v", recs[0].Err)
	}
	for _, r := range recs[1:] {
		if r.Err == nil || r.Env.Body != nil {
			t.Fatalf("seq %d accepted: %+v", r.Seq, r)
		}
	}

	broken := map[string]string{
		"not json":        `<html>`,
		"object":          `{"seq":0}`,
		"seq missing":     `[{"type":"msg","body":"` + good + `","at":1}]`,
		"seq not after":   `[{"seq":-1,"type":"msg","body":"` + good + `","at":1}]`,
		"seq descending":  `[{"seq":3,"type":"msg","body":"` + good + `","at":1},{"seq":2,"type":"msg","body":"` + good + `","at":1}]`,
		"over 100 rows":   "[" + strings.Repeat(`{"seq":0},`, 100) + `{"seq":0}]`,
		"seq not integer": `[{"seq":"zero","type":"msg","body":"` + good + `","at":1}]`,
	}
	for name, raw := range broken {
		f.raw = raw
		if _, err := c.Pull(ctx, ch.ID, ch.HostToken, -1); !errors.Is(err, ErrAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestHostileAnswers(t *testing.T) {
	ctx := context.Background()
	answers := map[string]string{
		"create bad id":      `{"id":"x","hostToken":"` + token() + `","inviteToken":"` + token() + `"}`,
		"take id only":       `{"id":1}`,
		"take bad base64":    `{"id":1,"pub":"%%%"}`,
		"take short key":     `{"id":1,"pub":"BQE="}`,
		"take zero key":      `{"id":1,"pub":"` + base64.StdEncoding.EncodeToString(append([]byte{5}, make([]byte, 32)...)) + `"}`,
		"put bad dir":        `{"dir":"x2y","seq":0}`,
		"prekeys no count":   `{}`,
		"error without code": "",
	}
	for name, body := range answers {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if body == "" {
				w.WriteHeader(502)
				w.Write([]byte("bad gateway"))
				return
			}
			w.Write([]byte(body))
		}))
		c := New(srv.URL+"/peer", srv.Client())
		id, tok := strings.Repeat("0", 32), token()
		var err error
		switch {
		case strings.HasPrefix(name, "create"):
			_, err = c.Create(ctx, login)
		case strings.HasPrefix(name, "take"):
			_, _, err = c.TakePrekey(ctx, id, tok)
		case strings.HasPrefix(name, "put"):
			_, err = c.Put(ctx, id, tok, msgEnv(1))
		case strings.HasPrefix(name, "prekeys"):
			_, err = c.PutPrekeys(ctx, id, tok, []Prekey{{1, pub(1)}})
		default:
			_, err = c.Pull(ctx, id, tok, -1)
			var e *Error
			if !errors.As(err, &e) || e.Status != 502 || e.Code != "" {
				t.Errorf("%s: %#v", name, err)
			}
			err = nil
			srv.Close()
			continue
		}
		if !errors.Is(err, ErrAnswer) {
			t.Errorf("%s: %v", name, err)
		}
		srv.Close()
	}
}
