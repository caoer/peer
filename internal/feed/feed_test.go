package feed

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caoer/peer/internal/feed/feedtest"
)

const (
	party  = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	secret = "source-secret-0123456789abcdefghijklmnopqrstuv"
	token  = "reader-token-0123456789abcdefghijklmnopqrstuvw"
)

func quick(t *testing.T) {
	t.Helper()
	min, max := backoffMin, backoffMax
	backoffMin, backoffMax = 20*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { backoffMin, backoffMax = min, max })
}

// next is the viewer's next frame, or the test fails after a while.
func next(t *testing.T, v *feedtest.Viewer) map[string]json.RawMessage {
	t.Helper()
	select {
	case f, ok := <-v.Frames:
		if !ok {
			t.Fatal("the viewer's socket closed")
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(f, &m); err != nil {
			t.Fatalf("%v: %s", err, f)
		}
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no frame reached the viewer")
	}
	return nil
}

// A source's record reaches every viewer once, is acked, and Flush returns.
func TestSendFansOutAndAcks(t *testing.T) {
	quick(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := feedtest.Start(t, party, secret, token)
	v, answer, err := s.Connect(ctx, token, "")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if !strings.Contains(string(answer), `"ok":true`) {
		t.Fatalf("viewer hello answered %s", answer)
	}
	c := Dial(ctx, s.URL, party, secret, "host-a", Options{HTTPClient: s.Client()})
	defer c.Close()
	c.Send(json.RawMessage(`{"id":"m1","dir":"out","body":"hi"}`), 1)
	c.Send(json.RawMessage(`{"id":"m2","dir":"in","body":"there"}`), 2)
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"m1", "m2"} {
		f := next(t, v)
		if !strings.Contains(string(f["rec"]), `"id":"`+id+`"`) || f["n"] != nil {
			t.Fatalf("viewer got %v", f)
		}
	}
	if fr := s.Frames(); len(fr) != 2 || fr[0].Host != "host-a" || !strings.Contains(string(fr[0].Body), `"n":1`) {
		t.Fatalf("frames %v", fr)
	}
}

// A hello the Object refuses ends the client: no reconnects, Flush says so.
func TestBadSecretStops(t *testing.T) {
	quick(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := feedtest.Start(t, party, secret, token)
	var log strings.Builder
	c := Dial(ctx, s.URL, party, "wrong", "host-a", Options{HTTPClient: s.Client(), Log: &log})
	defer c.Close()
	c.Send(json.RawMessage(`{"id":"m1"}`), 1)
	if err := c.Flush(ctx); !errors.Is(err, ErrRefused) {
		t.Fatalf("Flush: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if s.Refused() != 1 || !strings.Contains(log.String(), "not this feed's") {
		t.Fatalf("%d refusals; log:\n%s", s.Refused(), log.String())
	}
}

// A record the Object did not ack is sent again on the next socket, and one
// sent while the socket is down goes out when it is up.
func TestPendingResentAfterReconnect(t *testing.T) {
	quick(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := feedtest.Start(t, party, secret, token)
	c := Dial(ctx, s.URL, party, secret, "host-a", Options{HTTPClient: s.Client()})
	defer c.Close()
	s.NoAck(true)
	c.Send(json.RawMessage(`{"id":"m1"}`), 1)
	deadline := time.Now().Add(5 * time.Second)
	for len(s.Frames()) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Pending() != 1 {
		t.Fatalf("pending %d before the close", c.Pending())
	}
	s.CloseSources()
	c.Send(json.RawMessage(`{"id":"m2"}`), 2)
	s.NoAck(false)
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range s.Frames() {
		var m struct {
			Rec struct{ ID string }
		}
		json.Unmarshal(f.Body, &m)
		ids = append(ids, m.Rec.ID)
	}
	if got := strings.Join(ids, " "); got != "m1 m1 m2" && got != "m1 m2 m1" {
		t.Fatalf("frames %v", ids)
	}
}

// A viewer's connect reaches the source as a replay request: its key goes to
// the Key callback, the Replay callback's records go to that viewer alone,
// then replay_done with the readers; a viewer without a key asks for no key.
func TestReplayToOneViewer(t *testing.T) {
	quick(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := feedtest.Start(t, party, secret, token, "other-token-0123456789abcdefghijklmnopqrst")
	var mu sync.Mutex
	var keys []string
	c := Dial(ctx, s.URL, party, secret, "host-a", Options{
		HTTPClient: s.Client(),
		Key: func(key, reader string) {
			mu.Lock()
			defer mu.Unlock()
			keys = append(keys, key+" "+reader)
		},
		Replay: func(ctx context.Context, r Replay, send func(json.RawMessage) error) ([]string, error) {
			for _, rec := range []string{`{"id":"r1"}`, `{"id":"r2"}`} {
				if err := send(json.RawMessage(rec)); err != nil {
					return nil, err
				}
			}
			return []string{"x25519:k1"}, nil
		},
	})
	defer c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for s.Sources() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	other, _, err := s.Connect(ctx, "other-token-0123456789abcdefghijklmnopqrst", "")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// The other viewer's replay: two records and a done, none of them to v.
	for range 3 {
		next(t, other)
	}
	v, _, err := s.Connect(ctx, token, "x25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	var got []string
	for range 3 {
		f := next(t, v)
		switch {
		case f["rec"] != nil:
			got = append(got, string(f["rec"]))
		case f["replay_done"] != nil:
			got = append(got, "done "+string(f["readers"]))
		default:
			t.Fatalf("frame %v", f)
		}
	}
	if want := `{"id":"r1"} {"id":"r2"} done ["x25519:k1"]`; strings.Join(got, " ") != want {
		t.Fatalf("viewer got %v", got)
	}
	select {
	case f := <-other.Frames:
		t.Fatalf("the other viewer got %s", f)
	case <-time.After(200 * time.Millisecond):
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keys) != 1 || keys[0] != "x25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB "+feedtest.Hash(token) {
		t.Fatalf("keys %v", keys)
	}
}

// Without a Replay callback the client answers a viewer with replay_done and
// no readers at all.
func TestReplayWithoutCallback(t *testing.T) {
	quick(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := feedtest.Start(t, party, secret, token)
	c := Dial(ctx, s.URL, party, secret, "host-a", Options{HTTPClient: s.Client()})
	defer c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for s.Sources() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	v, _, err := s.Connect(ctx, token, "")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if f := next(t, v); string(f["readers"]) != "[]" || f["replay_done"] == nil {
		t.Fatalf("frame %v", f)
	}
}
