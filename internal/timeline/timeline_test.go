package timeline

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/session"
)

// The key is a /d/ key, zero-padded so a direction's keys list in seq order.
func TestKey(t *testing.T) {
	keyRE := regexp.MustCompile(`^[a-z0-9._-]{1,128}$`)
	ch := "c864c3eec62af5cea97ec8114096b8b6"
	if k := Key(ch, In, 7); k != "tl."+ch+".in.00000007" || !keyRE.MatchString(k) {
		t.Fatalf("key %q", k)
	}
	if Key(ch, Out, 9) >= Key(ch, Out, 10) {
		t.Fatal("keys out of seq order")
	}
	if p := Prefix(ch); Key(ch, Out, 1)[:len(p)] != p {
		t.Fatalf("prefix %q", p)
	}
}

// An envelope is marked e2e and its body is the envelope string; a plain
// body and an attachment or card are not marked, and the field is absent.
func TestOfMarksEncrypted(t *testing.T) {
	env := `{"e2e":1,"suite":"peer-e2e-v1","to":[],"body":"AA=="}`
	at := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	r, err := Of(In, &session.Message{ID: "m", From: "a", To: "b", Kind: "text", At: at, Body: []byte(env)})
	if err != nil {
		t.Fatal(err)
	}
	var body string
	if err := json.Unmarshal(r.Body, &body); err != nil || body != env || !r.E2E {
		t.Fatalf("encrypted record: %+v, %v", r, err)
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.HasSuffix(string(b), `,"e2e":true}`) {
		t.Fatalf("%s, %v", b, err)
	}
	r, err = Of(In, &session.Message{ID: "m", From: "a", To: "b", Kind: "text", At: at, Body: []byte(`{"e2e":2}`)})
	if err != nil || r.E2E {
		t.Fatalf("plain record: %+v, %v", r, err)
	}
	if b, _ := json.Marshal(r); strings.Contains(string(b), `"e2e":true`) || !strings.HasSuffix(string(b), `}"}`) {
		t.Fatalf("plain record: %s", b)
	}
	r, err = Of(In, &session.Message{ID: "m", From: "a", To: "b", Kind: session.KindCard, At: at, Body: []byte(env)})
	if err != nil || r.E2E {
		t.Fatalf("card: %+v, %v", r, err)
	}
}
