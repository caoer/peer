package sealed

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const testRoom = "0123456789abcdef0123456789abcdef"

var testAt = time.Date(2026, 10, 15, 11, 46, 0, 123456789, time.UTC)

func signer(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sealKey(t testing.TB) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// members makes n recipients at idx 0..n-1 with their seal keys.
func members(t testing.TB, n int) ([]Recipient, []*ecdh.PrivateKey) {
	t.Helper()
	to := make([]Recipient, n)
	privs := make([]*ecdh.PrivateKey, n)
	for i := range to {
		privs[i] = sealKey(t)
		to[i] = Recipient{Idx: uint16(i), Key: privs[i].PublicKey()}
	}
	return to, privs
}

type fixture struct {
	rec   []byte
	to    []Recipient
	privs []*ecdh.PrivateKey
	pub   ed25519.PublicKey
	msg   []byte
}

// good seals one message from idx 0 to n members.
func good(t testing.TB, n int) fixture {
	t.Helper()
	to, privs := members(t, n)
	pub, priv := signer(t)
	msg := []byte(`{"v":1,"id":"m1","from":"ed25519:a","kind":"text","at":"2026-10-15T11:46:00Z","body":"hi","group":"` + testRoom + `"}`)
	h := Header{Room: testRoom, Idx: 0, Ctr: 1, At: testAt}
	rec, err := Seal(h, msg, to, priv)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{rec: rec, to: to, privs: privs, pub: pub, msg: msg}
}

// split returns a record's four parts.
func split(t testing.TB, rec []byte) (hdr, stanzas, body, sig []byte) {
	t.Helper()
	rest := rec
	var segs [3][]byte
	for i := range segs {
		n := binary.BigEndian.Uint32(rest)
		segs[i], rest = rest[4:4+n], rest[4+n:]
	}
	if len(rest) != 64 {
		t.Fatalf("split: %d trailing bytes", len(rest))
	}
	return segs[0], segs[1], segs[2], rest
}

// rebuild frames the parts without re-signing.
func rebuild(hdr, stanzas, body, sig []byte) []byte {
	var out []byte
	for _, seg := range [][]byte{hdr, stanzas, body} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(seg)))
		out = append(out, seg...)
	}
	return append(out, sig...)
}

func parseVerify(t testing.TB, rec []byte, pub ed25519.PublicKey) *Record {
	t.Helper()
	r, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(pub); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{1, 3, 100} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			f := good(t, n)
			r := parseVerify(t, f.rec, f.pub)
			if r.Header.Room != testRoom || r.Header.Idx != 0 || r.Header.Ctr != 1 {
				t.Fatalf("header %+v", r.Header)
			}
			if !r.Header.At.Equal(testAt.Truncate(time.Millisecond)) {
				t.Fatalf("at %v, want %v to the millisecond", r.Header.At, testAt)
			}
			idxs := r.Recipients()
			if len(idxs) != n || idxs[0] != 0 || idxs[n-1] != uint16(n-1) {
				t.Fatalf("recipients %v", idxs)
			}
			for i, priv := range f.privs {
				got, err := r.Open(uint16(i), priv)
				if err != nil {
					t.Fatalf("idx %d: %v", i, err)
				}
				if !bytes.Equal(got, f.msg) {
					t.Fatalf("idx %d: opened %q", i, got)
				}
			}
			want := 12 + len(encodedHeader(t, r.Header)) + 2 + n*(stanzaHead+StanzaSize) + len(f.msg) + 16 + 64
			if len(f.rec) != want {
				t.Fatalf("record is %d bytes, layout says %d", len(f.rec), want)
			}
		})
	}
}

func encodedHeader(t testing.TB, h Header) []byte {
	t.Helper()
	b, err := encodeHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The header bytes are the contract's shape, key for key: a second
// implementation signs and hashes exactly these.
func TestHeaderWire(t *testing.T) {
	f := good(t, 1)
	hdr, _, _, _ := split(t, f.rec)
	shape := regexp.MustCompile(`^\{"v":1,"room":"[0-9a-f]{32}","idx":0,"ctr":1,"kh":"[A-Za-z0-9+/]{43}=","at":"2026-10-15T11:46:00\.123Z"\}$`)
	if !shape.Match(hdr) {
		t.Fatalf("header %s", hdr)
	}
}

// Seal puts recipients in idx order whatever order they came in.
func TestSealOrdersStanzas(t *testing.T) {
	to, privs := members(t, 3)
	_, priv := signer(t)
	rec, err := Seal(Header{Room: testRoom, Idx: 2, Ctr: 9, At: testAt}, []byte("x"), []Recipient{to[2], to[0], to[1]}, priv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Recipients(); !slices.Equal(got, []uint16{0, 1, 2}) {
		t.Fatalf("recipients %v", got)
	}
	r.verified = true
	if _, err := r.Open(1, privs[1]); err != nil {
		t.Fatal(err)
	}
}

func TestNonRecipientFailsEveryStanza(t *testing.T) {
	f := good(t, 3)
	r := parseVerify(t, f.rec, f.pub)
	outsider := sealKey(t)
	for _, idx := range r.Recipients() {
		if _, err := r.Open(idx, outsider); !errors.Is(err, ErrStanza) {
			t.Fatalf("idx %d under the outsider's key: %v, want ErrStanza", idx, err)
		}
	}
	if _, err := r.Open(7, outsider); !errors.Is(err, ErrNoStanza) {
		t.Fatalf("idx 7: %v, want ErrNoStanza", err)
	}
	// A member cannot open another member's stanza either: the info binds idx.
	if _, err := r.Open(1, f.privs[2]); !errors.Is(err, ErrStanza) {
		t.Fatalf("idx 1 under idx 2's key: %v, want ErrStanza", err)
	}
	if _, err := r.Open(1); !errors.Is(err, ErrStanza) {
		t.Fatalf("no keys: %v, want ErrStanza", err)
	}
}

// twoKeys builds a record whose stanzas carry k1 to A (idx 1) and k2 to B
// (idx 2) under one header, the body sealed under bodyKey — the attack rule 1
// exists to refuse.
func twoKeys(t testing.TB, writer uint16, kh, bodyKey, k1, k2 []byte, a, b *ecdh.PublicKey, priv ed25519.PrivateKey, msg []byte) []byte {
	t.Helper()
	h := Header{Room: testRoom, Idx: writer, Ctr: 1, At: testAt}
	copy(h.KH[:], kh)
	hdr := encodedHeader(t, h)
	hh := sha256.Sum256(hdr)
	stA, err := wrap(testRoom, 1, hh, a, k1)
	if err != nil {
		t.Fatal(err)
	}
	stB, err := wrap(testRoom, 2, hh, b, k2)
	if err != nil {
		t.Fatal(err)
	}
	stanzas := binary.BigEndian.AppendUint16(nil, 2)
	for i, st := range [][]byte{stA, stB} {
		stanzas = binary.BigEndian.AppendUint16(stanzas, uint16(i+1))
		stanzas = binary.BigEndian.AppendUint16(stanzas, StanzaSize)
		stanzas = append(stanzas, st...)
	}
	body, err := sealBody(bodyKey, hdr, msg)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := assemble(hdr, stanzas, body, priv)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestKeyCommitment(t *testing.T) {
	a, b := sealKey(t), sealKey(t)
	pub, priv := signer(t)
	k1, k2 := make([]byte, 32), make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	kh1, kh2 := KeyCommit(k1), KeyCommit(k2)
	msg := []byte(`{"body":"one message"}`)
	const writer = 7

	cases := []struct {
		name          string
		kh, bodyKey   []byte
		opens, refuse uint16
		opener        *ecdh.PrivateKey
		refuser       *ecdh.PrivateKey
	}{
		{"K1 to A, K2 to B, kh=H(K1): A opens, B refuses", kh1[:], k1, 1, 2, a, b},
		{"mirror — kh=H(K2): B opens, A refuses", kh2[:], k2, 2, 1, b, a},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := twoKeys(t, writer, c.kh, c.bodyKey, k1, k2, a.PublicKey(), b.PublicKey(), priv, msg)
			r := parseVerify(t, rec, pub)
			got, err := r.Open(c.opens, c.opener)
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("idx %d: %q %v", c.opens, got, err)
			}
			_, err = r.Open(c.refuse, c.refuser)
			if !errors.Is(err, ErrKeyCommit) {
				t.Fatalf("idx %d: %v, want ErrKeyCommit", c.refuse, err)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("writer idx %d", writer)) {
				t.Fatalf("refusal does not name the writer: %v", err)
			}
		})
	}
}

func TestWrongSignerRefuses(t *testing.T) {
	f := good(t, 2)
	other, _ := signer(t)
	r, err := Parse(f.rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open(0, f.privs[0]); !errors.Is(err, ErrUnverified) {
		t.Fatalf("open before verify: %v, want ErrUnverified", err)
	}
	if err := r.Verify(other); !errors.Is(err, ErrSignature) {
		t.Fatalf("other signer: %v, want ErrSignature", err)
	}
	if err := r.Verify(f.pub[:31]); !errors.Is(err, ErrSignature) {
		t.Fatalf("31-byte key: %v, want ErrSignature", err)
	}
	if _, err := r.Open(0, f.privs[0]); !errors.Is(err, ErrUnverified) {
		t.Fatalf("open after a failed verify: %v, want ErrUnverified", err)
	}
	if err := r.Verify(f.pub); err != nil {
		t.Fatal(err)
	}
	// Any byte of the signed span flipped fails the right signer; the header's
	// flipped byte is the ctr digit (1 → 0), so the header still parses.
	hdr, stanzas, body, sig := split(t, f.rec)
	flip := func(b []byte, i int) []byte {
		c := slices.Clone(b)
		c[i] ^= 1
		return c
	}
	for name, rec := range map[string][]byte{
		"header":    rebuild(flip(hdr, bytes.Index(hdr, []byte(`"ctr":1`))+6), stanzas, body, sig),
		"stanzas":   rebuild(hdr, flip(stanzas, 10), body, sig),
		"body":      rebuild(hdr, stanzas, flip(body, 0), sig),
		"signature": rebuild(hdr, stanzas, body, flip(sig, 5)),
	} {
		r, err := Parse(rec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := r.Verify(f.pub); !errors.Is(err, ErrSignature) {
			t.Fatalf("%s flipped: %v, want ErrSignature", name, err)
		}
	}
}

// A body byte flipped under a forged-but-accepted signature path: Open's own
// checks still refuse (the fuzz target relies on this never panicking).
func TestTamperedBodyRefuses(t *testing.T) {
	f := good(t, 1)
	hdr, stanzas, body, sig := split(t, f.rec)
	body = slices.Clone(body)
	body[0] ^= 1
	r, err := Parse(rebuild(hdr, stanzas, body, sig))
	if err != nil {
		t.Fatal(err)
	}
	r.verified = true
	if _, err := r.Open(0, f.privs[0]); !errors.Is(err, ErrBody) {
		t.Fatalf("%v, want ErrBody", err)
	}
}

// A record sealed to a key the member has since rotated opens under the
// retired key, passed after the current one (rule 3).
func TestRetiredKeyOpens(t *testing.T) {
	f := good(t, 2)
	r := parseVerify(t, f.rec, f.pub)
	current := sealKey(t)
	if _, err := r.Open(1, current); !errors.Is(err, ErrStanza) {
		t.Fatalf("current key alone: %v, want ErrStanza", err)
	}
	got, err := r.Open(1, current, f.privs[1])
	if err != nil || !bytes.Equal(got, f.msg) {
		t.Fatalf("current then retired: %q %v", got, err)
	}
	if got, err := r.Open(1, nil, f.privs[1]); err != nil || !bytes.Equal(got, f.msg) {
		t.Fatalf("nil then retired: %q %v", got, err)
	}
}

func TestSealRefuses(t *testing.T) {
	to, _ := members(t, 2)
	_, priv := signer(t)
	h := Header{Room: testRoom, Idx: 0, Ctr: 1, At: testAt}
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		h      Header
		msg    []byte
		to     []Recipient
		signer ed25519.PrivateKey
		want   error
	}{
		{"no recipients", h, []byte("x"), nil, priv, ErrMalformed},
		{"duplicate idx", h, []byte("x"), []Recipient{to[0], to[0]}, priv, ErrMalformed},
		{"nil seal key", h, []byte("x"), []Recipient{{Idx: 0}}, priv, ErrMalformed},
		{"P-256 seal key", h, []byte("x"), []Recipient{{Idx: 0, Key: p256.PublicKey()}}, priv, ErrMalformed},
		{"room 31 hex", Header{Room: testRoom[:31], At: testAt}, []byte("x"), to, priv, ErrMalformed},
		{"room uppercase", Header{Room: strings.ToUpper(testRoom), At: testAt}, []byte("x"), to, priv, ErrMalformed},
		{"32-byte signer", h, []byte("x"), to, priv[:32], ErrMalformed},
		{"message over 1 MiB", h, make([]byte, MaxRecord+1), to, priv, ErrTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Seal(c.h, c.msg, c.to, c.signer); !errors.Is(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
		})
	}
	// Just under the cap seals and parses.
	big := make([]byte, MaxRecord-2000)
	rec, err := Seal(h, big, to[:1], priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(rec); err != nil {
		t.Fatal(err)
	}
}

// malformed is the table FuzzParse also seeds: every entry refuses at Parse
// with ErrMalformed or ErrTooLarge and no panic.
func malformed(t testing.TB) map[string][]byte {
	t.Helper()
	f := good(t, 2)
	hdr, stanzas, body, sig := split(t, f.rec)
	kh := base64.StdEncoding.EncodeToString(make([]byte, 32))
	hdrWith := func(s string) []byte { return rebuild([]byte(s), stanzas, body, sig) }
	stanzasWith := func(s []byte) []byte { return rebuild(hdr, s, body, sig) }
	js := func(room, idx, ctr, kh, at string) string {
		return fmt.Sprintf(`{"v":1,"room":"%s","idx":%s,"ctr":%s,"kh":"%s","at":"%s"}`, room, idx, ctr, kh, at)
	}
	ok := js(testRoom, "0", "1", kh, "2026-10-15T11:46:00.000Z")
	st := func(mut func(s []byte)) []byte { s := slices.Clone(stanzas); mut(s); return stanzasWith(s) }
	const stLen = stanzaHead + StanzaSize

	return map[string][]byte{
		"empty":                        nil,
		"three bytes":                  {0, 0, 0},
		"header length past the end":   append([]byte{0xff, 0xff, 0xff, 0xff}, f.rec[4:]...),
		"cut after header":             f.rec[:4+len(hdr)],
		"cut inside stanzas":           f.rec[:4+len(hdr)+4+5],
		"cut inside body":              f.rec[:len(f.rec)-64-3],
		"63-byte signature":            f.rec[:len(f.rec)-1],
		"65-byte signature":            append(slices.Clone(f.rec), 0),
		"header not JSON":              hdrWith("nope"),
		"header empty":                 hdrWith(""),
		"header v 2":                   hdrWith(strings.Replace(ok, `"v":1`, `"v":2`, 1)),
		"header no v":                  hdrWith(strings.Replace(ok, `"v":1,`, ``, 1)),
		"header unknown key":           hdrWith(strings.Replace(ok, `"v":1`, `"v":1,"x":1`, 1)),
		"header duplicate key":         hdrWith(strings.Replace(ok, `"idx":0,"ctr":1`, `"idx":0,"idx":5,"ctr":1,"ctr":9`, 1)),
		"header key in caps":           hdrWith(strings.Replace(ok, `"idx":0`, `"IDX":0`, 1)),
		"header no kh":                 hdrWith(strings.Replace(ok, `"kh":"`+kh+`",`, ``, 1)),
		"header no idx":                hdrWith(strings.Replace(ok, `"idx":0,`, ``, 1)),
		"header idx null":              hdrWith(js(testRoom, "null", "1", kh, "2026-10-15T11:46:00.000Z")),
		"header no ctr":                hdrWith(strings.Replace(ok, `"ctr":1,`, ``, 1)),
		"header room 31 hex":           hdrWith(js(testRoom[:31], "0", "1", kh, "2026-10-15T11:46:00.000Z")),
		"header room uppercase":        hdrWith(js(strings.ToUpper(testRoom), "0", "1", kh, "2026-10-15T11:46:00.000Z")),
		"header room not hex":          hdrWith(js(strings.Replace(testRoom, "a", "g", 1), "0", "1", kh, "2026-10-15T11:46:00.000Z")),
		"header idx 65536":             hdrWith(js(testRoom, "65536", "1", kh, "2026-10-15T11:46:00.000Z")),
		"header idx negative":          hdrWith(js(testRoom, "-1", "1", kh, "2026-10-15T11:46:00.000Z")),
		"header idx string":            hdrWith(js(testRoom, `"0"`, "1", kh, "2026-10-15T11:46:00.000Z")),
		"header ctr float":             hdrWith(js(testRoom, "0", "1.5", kh, "2026-10-15T11:46:00.000Z")),
		"header ctr negative":          hdrWith(js(testRoom, "0", "-1", kh, "2026-10-15T11:46:00.000Z")),
		"header kh 31 bytes":           hdrWith(js(testRoom, "0", "1", base64.StdEncoding.EncodeToString(make([]byte, 31)), "2026-10-15T11:46:00.000Z")),
		"header kh url alphabet":       hdrWith(js(testRoom, "0", "1", strings.Repeat("-_", 21)+"A=", "2026-10-15T11:46:00.000Z")),
		"header kh no padding":         hdrWith(js(testRoom, "0", "1", kh[:43], "2026-10-15T11:46:00.000Z")),
		"header kh not base64":         hdrWith(js(testRoom, "0", "1", "@@@@", "2026-10-15T11:46:00.000Z")),
		"header at not a time":         hdrWith(js(testRoom, "0", "1", kh, "yesterday")),
		"header at epoch ms":           hdrWith(js(testRoom, "0", "1", kh, "1760528760123")),
		"header bytes after the JSON":  hdrWith(ok + "{}"),
		"header array":                 hdrWith("[" + ok + "]"),
		"stanzas empty":                stanzasWith(nil),
		"stanzas 1 byte":               stanzasWith([]byte{0}),
		"stanzas count 3, bytes for 2": st(func(s []byte) { s[1] = 3 }),
		"stanzas count 1, bytes for 2": st(func(s []byte) { s[1] = 1 }),
		"stanzas count 0, bytes for 2": st(func(s []byte) { s[1] = 0 }),
		"stanza len 79":                st(func(s []byte) { s[5] = 79 }),
		"stanza len 81":                st(func(s []byte) { s[5] = 81 }),
		"stanzas descending":           stanzasWith(slices.Concat(stanzas[:2], stanzas[2+stLen:2+2*stLen], stanzas[2:2+stLen])),
		"stanzas duplicate idx":        st(func(s []byte) { copy(s[2+stLen:2+stLen+2], s[2:4]) }),
		"stanzas trailing byte":        stanzasWith(append(slices.Clone(stanzas), 0)),
		"body 15 bytes":                rebuild(hdr, stanzas, make([]byte, 15), sig),
		"body empty":                   rebuild(hdr, stanzas, nil, sig),
		"over 1 MiB":                   make([]byte, MaxRecord+1),
	}
}

func TestMalformedRefused(t *testing.T) {
	for name, b := range malformed(t) {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(b)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("%v wraps no sentinel", err)
			}
		})
	}
	// Zero stanzas is a shape, not a fault: every member skips it.
	f := good(t, 1)
	hdr, _, body, sig := split(t, f.rec)
	r, err := Parse(rebuild(hdr, []byte{0, 0}, body, sig))
	if err != nil {
		t.Fatal(err)
	}
	r.verified = true
	if _, err := r.Open(0, f.privs[0]); !errors.Is(err, ErrNoStanza) {
		t.Fatalf("%v, want ErrNoStanza", err)
	}
}

func TestCheckCtr(t *testing.T) {
	cases := []struct {
		last, got uint64
		want      error
	}{
		{0, 1, nil}, {5, 6, nil},
		{0, 2, ErrCtrGap}, {5, 9, ErrCtrGap},
		{5, 5, ErrCtrBack}, {5, 3, ErrCtrBack}, {0, 0, ErrCtrBack},
	}
	for _, c := range cases {
		err := CheckCtr(c.last, c.got)
		if !errors.Is(err, c.want) {
			t.Errorf("CheckCtr(%d, %d) = %v, want %v", c.last, c.got, err, c.want)
		}
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("%d after %d", c.got, c.last)) {
			t.Errorf("CheckCtr(%d, %d) = %v: does not name both counters", c.last, c.got, err)
		}
	}
	if err := CheckCtr(5, 9); !strings.Contains(err.Error(), "3 missing") {
		t.Errorf("gap report %v does not count the missing records", err)
	}
}

func TestKeyCommit(t *testing.T) {
	k := make([]byte, 32)
	rand.Read(k)
	want := sha256.Sum256(append([]byte("peer room key commit v1"), k...))
	if KeyCommit(k) != want {
		t.Fatal("kh is not SHA-256 of the prefix and the key")
	}
	if KeyCommit(k) == KeyCommit(append(slices.Clone(k[:31]), k[31]^1)) {
		t.Fatal("two keys, one kh")
	}
}

// FuzzParse: Parse never panics, and whatever it accepts Verify and Open
// take without panicking under keys that are right or wrong.
func FuzzParse(f *testing.F) {
	g1, g3 := good(f, 1), good(f, 3)
	f.Add(g1.rec)
	f.Add(g3.rec)
	hdr, _, _, _ := split(f, g3.rec)
	f.Add(hdr)
	for _, b := range malformed(f) {
		f.Add(b)
	}
	pub := g1.pub
	key, other := g1.privs[0], sealKey(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		parseHeader(b)
		r, err := Parse(b)
		if err != nil {
			return
		}
		idxs := r.Recipients()
		if _, err := r.Open(0, key); !errors.Is(err, ErrUnverified) {
			t.Fatalf("unverified record opened: %v", err)
		}
		if r.Verify(pub) == nil && !bytes.Equal(b, g1.rec) {
			t.Fatal("a mutated record verified under the fixture's key")
		}
		r.verified = true
		for _, idx := range append(idxs, 0, 65535) {
			r.Open(idx, key, other, nil)
		}
	})
}
