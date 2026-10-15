package invite

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The feed link round-trips; the parser refuses anything that is not one —
// a v1 invite link, a short or long fragment, a bad key, token or room id —
// and the invite parser refuses a feed link.
func TestParseFeed(t *testing.T) {
	key := bytes.Repeat([]byte{7}, LinkKeySize)
	f := Feed{Relay: "https://page.example.com/peer/", Room: chID, Token: tok, Key: key, Owner: root}
	s := f.String()
	if !strings.HasPrefix(s, "https://page.example.com/peer/f/"+chID+"#v1."+tok+".") {
		t.Fatalf("form: %s", s)
	}
	got, err := ParseFeed(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.Relay != "https://page.example.com/peer" || got.Room != chID || got.Token != tok || !bytes.Equal(got.Key, key) || !bytes.Equal(got.Owner, root) {
		t.Fatalf("parsed %+v", got)
	}
	if _, err := Parse(s, now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("invite.Parse of a feed link: %v", err)
	}

	inv, err := New("https://page.example.com/peer", chID, tok, root, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	frag := "https://page.example.com/peer/f/" + chID + "#"
	for name, bad := range map[string]string{
		"invite link":    inv.String(),
		"three fields":   frag + "v1." + tok + "." + b64(key),
		"five fields":    frag + "v1." + tok + "." + b64(key) + "." + b64(root) + ".x",
		"version":        frag + "v2." + tok + "." + b64(key) + "." + b64(root),
		"short key":      frag + "v1." + tok + "." + b64(key[:31]) + "." + b64(root),
		"padded key":     frag + "v1." + tok + "." + base64.URLEncoding.EncodeToString(key) + "." + b64(root),
		"short owner":    frag + "v1." + tok + "." + b64(key) + "." + b64(root[:31]),
		"bad token":      frag + "v1.short." + b64(key) + "." + b64(root),
		"bad room":       "https://page.example.com/peer/f/XYZ#v1." + tok + "." + b64(key) + "." + b64(root),
		"query":          "https://page.example.com/peer/f/" + chID + "?a=b#v1." + tok + "." + b64(key) + "." + b64(root),
		"scheme":         "ftp://page.example.com/peer/f/" + chID + "#v1." + tok + "." + b64(key) + "." + b64(root),
		"no fragment":    "https://page.example.com/peer/f/" + chID,
		"not a url":      "%%",
		"empty":          "",
		"base64 std key": frag + "v1." + tok + "." + base64.StdEncoding.EncodeToString(key) + "." + b64(root),
	} {
		if _, err := ParseFeed(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %q parsed (%v)", name, bad, err)
		}
	}
}
