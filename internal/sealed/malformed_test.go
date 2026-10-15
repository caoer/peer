package sealed

import (
	"encoding/binary"
	"slices"
	"testing"
)

func TestMalformedBytesNeverPanic(t *testing.T) {
	f := good(t, 3)
	try := func(name string, b []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s: panic %v", name, r)
			}
		}()
		r, err := Parse(b)
		if err != nil {
			return
		}
		r.verified = true
		for _, i := range []uint16{0, 1, 2, 3, 65535} {
			r.Open(i, f.privs...)
		}
	}
	for n := 0; n < len(f.rec); n++ {
		try("trunc", f.rec[:n])
		if _, err := Parse(f.rec[:n]); err == nil {
			t.Fatalf("truncation at %d parsed", n)
		}
	}
	hdr, stz, body, sig := split(t, f.rec)
	for _, c := range []uint16{4, 0xffff} {
		s := slices.Clone(stz)
		binary.BigEndian.PutUint16(s, c)
		try("count", rebuild(hdr, s, body, sig))
	}
	for _, l := range []uint16{0, 79, 81, 0xffff} {
		s := slices.Clone(stz)
		binary.BigEndian.PutUint16(s[4:], l)
		if _, err := Parse(rebuild(hdr, s, body, sig)); err == nil {
			t.Fatalf("len %d parsed", l)
		}
		try("len", rebuild(hdr, s, body, sig))
	}
	// every uint32 prefix set to huge values
	off := 0
	for i := 0; i < 3; i++ {
		for _, v := range []uint32{0, 0x7fffffff, 0xffffffff, uint32(len(f.rec))} {
			b := slices.Clone(f.rec)
			binary.BigEndian.PutUint32(b[off:], v)
			try("prefix", b)
		}
		off += 4 + int(binary.BigEndian.Uint32(f.rec[off:]))
	}
	// stanza transplant: idx 1's stanza relabelled as idx 0 must not open for 0's key
	s := slices.Clone(stz)
	r, _ := Parse(rebuild(hdr, s, body, sig))
	r.verified = true
	if _, err := r.Open(0, f.privs[1]); err == nil {
		t.Fatal("member 1's key opened idx 0's stanza")
	}
}

// A stanza binds SHA-256(header) through the HPKE info, so record A's
// stanzas moved under record B's header open nothing.
func TestStanzaTransplantRefuses(t *testing.T) {
	a := good(t, 2)
	_, stzA, _, _ := split(t, a.rec)
	_, signer2 := signer(t)
	rec, err := Seal(Header{Room: testRoom, Idx: 0, Ctr: 2, At: testAt}, []byte("x"), a.to, signer2)
	if err != nil {
		t.Fatal(err)
	}
	hdr2, _, body2, sig2 := split(t, rec)
	r, err := Parse(rebuild(hdr2, stzA, body2, sig2))
	if err != nil {
		t.Fatal(err)
	}
	r.verified = true
	if _, err := r.Open(0, a.privs[0]); err == nil {
		t.Fatal("a stanza from record A opened under record B's header")
	}
}
