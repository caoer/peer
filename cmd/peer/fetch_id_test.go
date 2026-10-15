package main

import (
	"strings"
	"testing"
)

// A message id may begin with '-' (base64url): peer fetch takes it as the id,
// never as an undefined flag.
func TestFetchTakesAnIDBeginningWithDash(t *testing.T) {
	const id = "-Fy3nmoz1Z_F3Ci1rVEbwA"
	dir := newDir(t, config{})
	for _, args := range [][]string{
		{"fetch", "--dir", dir, id},
		{"fetch", "--dir", dir, "--", id},
	} {
		code, _, errb := cmd(t, args...)
		if code != 1 || strings.Contains(errb, "flag provided but not defined") || strings.Contains(errb, "is not a message id") {
			t.Fatalf("peer %s: exit %d, stderr %q, want the id taken and a refusal past the flags", strings.Join(args, " "), code, errb)
		}
	}
	if code, _, errb := cmd(t, "fetch", "--dir", dir, "-nodir", id); code != 2 || !strings.Contains(errb, "flag provided but not defined: -nodir") {
		t.Fatalf("an undefined flag before the id: exit %d, stderr %q", code, errb)
	}
	if code, _, _ := cmd(t, "fetch", "--help"); code != 2 {
		t.Fatalf("peer fetch --help: exit %d, want the usage", code)
	}
}
