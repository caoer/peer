package timeline

import (
	"regexp"
	"testing"
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
