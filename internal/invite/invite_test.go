package invite

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	now     = time.Date(2026, 10, 14, 20, 0, 0, 0, time.UTC)
	chID    = "0123456789abcdef0123456789abcdef"
	tok     = strings.Repeat("Ab_-", 10) + "xyz" // 43 chars
	secret  = bytes.Repeat([]byte{0x5a, 0xa5}, SecretSize/2)
	root, _ = func() (ed25519.PublicKey, error) {
		pub, _, err := ed25519.GenerateKey(nil)
		return pub, err
	}()
)

func TestRoundTrip(t *testing.T) {
	for _, base := range []string{"https://page.example.com/peer", "https://relay.example.org/x/peer/", "http://127.0.0.1:8080/peer"} {
		l, err := New(base, chID, tok, root, secret, now)
		if err != nil {
			t.Fatal(err)
		}
		if got := l.Expires.Sub(now); got != Validity {
			t.Fatalf("validity %v", got)
		}
		s := l.String()
		if !strings.Contains(s, "/peer/i/"+chID+"#v1."+tok+".") || !strings.HasSuffix(s, "."+base64.RawURLEncoding.EncodeToString(secret)) {
			t.Fatalf("form: %s", s)
		}
		p, err := Parse(s, now)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if p.Relay != strings.TrimRight(base, "/") || p.Channel != chID || p.Token != tok ||
			!bytes.Equal(p.Root, root) || !p.Expires.Equal(l.Expires) || !bytes.Equal(p.Secret, secret) {
			t.Fatalf("round trip: %+v", p)
		}
		if p.String() != s {
			t.Fatalf("re-render: %s != %s", p.String(), s)
		}
	}
}

func TestNewSecret(t *testing.T) {
	a, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSecret()
	if len(a) != SecretSize || len(b) != SecretSize || bytes.Equal(a, b) {
		t.Fatalf("secrets %x %x", a, b)
	}
	if len(base64.RawURLEncoding.EncodeToString(a)) != 22 {
		t.Fatalf("secret text is %d chars, want 22", len(base64.RawURLEncoding.EncodeToString(a)))
	}
}

func TestExpiry(t *testing.T) {
	l, _ := New("https://h/peer", chID, tok, root, secret, now)
	s := l.String()
	if _, err := Parse(s, now.Add(Validity-time.Second)); err != nil {
		t.Fatalf("one second before expiry: %v", err)
	}
	for _, at := range []time.Time{now.Add(Validity), now.Add(Validity + time.Hour)} {
		if _, err := Parse(s, at); !errors.Is(err, ErrExpired) {
			t.Fatalf("at %v: %v", at, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	rp := base64.RawURLEncoding.EncodeToString(root)
	sec := base64.RawURLEncoding.EncodeToString(secret)
	good := "https://h/peer/i/" + chID + "#v1." + tok + "." + rp + ".1800000000." + sec
	if _, err := Parse(good, now); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	cases := map[string]string{
		"empty":            "",
		"no fragment":      "https://h/peer/i/" + chID,
		"version v2":       strings.Replace(good, "#v1.", "#v2.", 1),
		"three parts":      "https://h/peer/i/" + chID + "#v1." + tok + "." + rp,
		"four parts":       "https://h/peer/i/" + chID + "#v1." + tok + "." + rp + ".1800000000",
		"six parts":        good + ".9",
		"ftp scheme":       strings.Replace(good, "https://", "ftp://", 1),
		"no host":          strings.Replace(good, "https://h", "https://", 1),
		"user info":        strings.Replace(good, "https://h", "https://u:p@h", 1),
		"query":            strings.Replace(good, chID+"#", chID+"?x=1#", 1),
		"no /i/":           strings.Replace(good, "/i/", "/x/", 1),
		"uppercase id":     strings.Replace(good, chID, strings.ToUpper(chID), 1),
		"short id":         strings.Replace(good, chID, chID[:31], 1),
		"extra path":       strings.Replace(good, chID+"#", chID+"/x#", 1),
		"short token":      strings.Replace(good, tok, tok[:42], 1),
		"token std b64":    strings.Replace(good, tok, strings.Repeat("A+/=", 10)+"AAA", 1),
		"root padded":      strings.Replace(good, rp, rp+"=", 1),
		"root std b64":     strings.Replace(good, rp, base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32)), 1),
		"root 31 bytes":    strings.Replace(good, rp, base64.RawURLEncoding.EncodeToString(root[:31]), 1),
		"root empty":       strings.Replace(good, rp, "", 1),
		"exp text":         strings.Replace(good, "1800000000", "soon", 1),
		"exp plus sign":    strings.Replace(good, "1800000000", "+1800000000", 1),
		"exp leading zero": strings.Replace(good, "1800000000", "01800000000", 1),
		"exp zero":         strings.Replace(good, "1800000000", "0", 1),
		"exp negative":     strings.Replace(good, "1800000000", "-5", 1),
		"exp overflow":     strings.Replace(good, "1800000000", "99999999999999999999", 1),
		"secret empty":     strings.TrimSuffix(good, sec),
		"secret padded":    good + "==",
		"secret 15 bytes":  strings.TrimSuffix(good, sec) + base64.RawURLEncoding.EncodeToString(secret[:15]),
		"secret 17 bytes":  strings.TrimSuffix(good, sec) + base64.RawURLEncoding.EncodeToString(append(secret, 1)),
		"secret 21 chars":  good[:len(good)-1],
		"secret std b64":   strings.TrimSuffix(good, sec) + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 16)),
		"secret non-canon": good[:len(good)-1] + "B", // trailing bits set: a strict decode refuses
		"not a url":        "%%%",
	}
	for name, s := range cases {
		if _, err := Parse(s, now); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := New("https://h/peer", chID, tok, root[:31], secret, now); err == nil {
		t.Error("New with short root accepted")
	}
	if _, err := New("https://h/peer", chID, tok, root, secret[:15], now); err == nil {
		t.Error("New with short secret accepted")
	}
	if _, err := New("https://h/peer", chID, tok, root, nil, now); err == nil {
		t.Error("New without a secret accepted")
	}
	if _, err := New("h/peer", chID, tok, root, secret, now); err == nil {
		t.Error("New with schemeless relay accepted")
	}
}

func FuzzParse(f *testing.F) {
	l, _ := New("https://h/peer", chID, tok, root, secret, now)
	f.Add(l.String())
	f.Add("https://h/peer/i/x#v1....")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s, now)
		if err != nil {
			return
		}
		if q, err := Parse(p.String(), now); err != nil || q.String() != p.String() {
			t.Fatalf("accepted %q but its rendering %q does not round-trip: %v", s, p.String(), err)
		}
	})
}
