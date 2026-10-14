package attach

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func sealed(t *testing.T, plain []byte) ([]byte, Descriptor) {
	t.Helper()
	ct, d, err := Seal("report.pdf", plain)
	if err != nil {
		t.Fatal(err)
	}
	d.Blob = "0123456789abcdef0123456789abcdef"
	return ct, d
}

// A sealed file opens byte-identical under its descriptor, through the
// message body and back; the ciphertext is not the file.
func TestSealOpen(t *testing.T) {
	plain := make([]byte, 5_000_000)
	rand.Read(plain)
	ct, d := sealed(t, plain)
	if len(ct) != len(plain)+Overhead || bytes.Contains(ct, plain[:64]) {
		t.Fatalf("ciphertext %d bytes for %d", len(ct), len(plain))
	}
	body, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(append(body, "\n\nblob not fetched: a status line\n"...))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(back, ct)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v", err)
	}
	// An empty file is a file too.
	ct, d = sealed(t, nil)
	if got, err := Open(d, ct); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v", err)
	}
}

// A changed byte fails the tag; a descriptor lying about the file fails the
// sha256; neither returns anything of the file.
func TestOpenRefuses(t *testing.T) {
	plain := []byte("the method you should follow")
	ct, d := sealed(t, plain)
	bad := append([]byte(nil), ct...)
	bad[3] ^= 1
	if got, err := Open(d, bad); !errors.Is(err, ErrOpen) || got != nil {
		t.Fatalf("tampered: %q %v", got, err)
	}
	if _, err := Open(d, ct[:len(ct)-1]); !errors.Is(err, ErrOpen) {
		t.Fatalf("short: %v", err)
	}
	lying := d
	lying.SHA256 = "00" + d.SHA256[2:]
	if got, err := Open(lying, ct); !errors.Is(err, ErrMismatch) || got != nil {
		t.Fatalf("lying sha256: %q %v", got, err)
	}
	other, _ := sealed(t, plain)
	if _, err := Open(d, other); !errors.Is(err, ErrOpen) {
		t.Fatalf("another key's blob: %v", err)
	}
}

func TestDescriptorShape(t *testing.T) {
	_, d := sealed(t, []byte("x"))
	for name, mut := range map[string]func(*Descriptor){
		"blob":   func(d *Descriptor) { d.Blob = "../etc" },
		"key":    func(d *Descriptor) { d.Key = d.Key[:16] },
		"name":   func(d *Descriptor) { d.Name = "../../.bashrc" },
		"size":   func(d *Descriptor) { d.Size = -1 },
		"sha256": func(d *Descriptor) { d.SHA256 = "ABC" },
	} {
		bad := d
		mut(&bad)
		if err := bad.Check(); !errors.Is(err, ErrDescriptor) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, n := range []string{"", ".", "..", "a/b", `a\b`, "a\x00b", "a\nb", strings.Repeat("a", 256)} {
		if ValidName(n) {
			t.Errorf("ValidName(%q)", n)
		}
	}
	for _, n := range []string{"a.txt", ".env", "报告 v2.pdf", "x"} {
		if !ValidName(n) {
			t.Errorf("!ValidName(%q)", n)
		}
	}
	if _, err := Parse([]byte("body of doc")); !errors.Is(err, ErrDescriptor) {
		t.Fatalf("a body that is not a descriptor: %v", err)
	}
}
