package main

import (
	"strings"
	"testing"

	"github.com/caoer/peer/internal/relay/relaytest"
)

// The confirm hint invite prints runs as printed: flags after the command,
// the invite's own --dir, the name last. The earlier form put the name
// before --code, and an outside agent who pasted it got a usage error.
func TestInviteHintRunsAsPrinted(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	hostDir := newDir(t, config{Relay: base})
	guestDir := newDir(t, config{})

	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, rest, _ := strings.Cut(out, "\n")
	_, hint, ok := strings.Cut(rest, "run: ")
	if !ok {
		t.Fatalf("invite printed no confirm hint:\n%s", out)
	}
	hint, _, _ = strings.Cut(hint, ";")
	if want := "peer confirm --dir " + hostDir + " --code <code> ancan"; hint != want {
		t.Fatalf("hint %q, want %q", hint, want)
	}

	out = mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	m := codeRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("accept printed no code line:\n%s", out)
	}
	args := strings.Fields(strings.Replace(hint, "<code>", m[1], 1))[1:] // after "peer"
	if out := mustOK(t, args...); !strings.Contains(out, "confirmed ancan (") {
		t.Fatalf("the printed hint ran but did not confirm: %q", out)
	}
}
