package pages

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A record's request is bounded when New is given no client of its own. It
// took http.DefaultClient, which has no timeout, so a state page that
// accepted the connection and never answered hung the serve loop with no log
// line — indistinguishable from a quiet channel.
func TestNewBoundsItsRequests(t *testing.T) {
	b := New("https://page.sui.pics", "state-0123456789abcdef", "zt:token", nil)
	if b.client == http.DefaultClient {
		t.Fatal("a nil client took http.DefaultClient, which never gives up")
	}
	if b.client.Timeout <= 0 {
		t.Fatalf("the client New made has timeout %v", b.client.Timeout)
	}
	own := &http.Client{Timeout: time.Second}
	if got := New("https://page.sui.pics", "state-0123456789abcdef", "zt:token", own); got.client != own {
		t.Fatal("New replaced the client it was given")
	}
}

// And the bound is what ends the request: a page that never answers comes
// back as an error, not as a serve loop that stopped.
func TestLoadGivesUpOnAPageThatNeverAnswers(t *testing.T) {
	block := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-block
	}))
	t.Cleanup(func() {
		close(block)
		ts.Close()
	})
	b := New(ts.URL, "state-0123456789abcdef", "zt:token", &http.Client{Timeout: 150 * time.Millisecond})
	start := time.Now()
	if _, _, err := b.Load(context.Background(), "keys"); err == nil {
		t.Fatal("Load answered from a page that never answered")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("Load waited %v", d)
	}
}
