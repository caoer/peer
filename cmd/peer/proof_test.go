package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/session"
)

// A proof that is present but wrong in shape or value is refused the same
// way as an absent one (finding2_test.go).
func TestConfirmRefusesWrongProof(t *testing.T) {
	_, rc, base := relaytest.Start(t, login)
	hostDir := newDir(t, config{})
	garbage := make([]byte, session.ProofSize)
	rand.Read(garbage)
	shapes := map[string]string{
		"random 32 bytes": session.EncodeProof(garbage),
		"31 bytes":        session.EncodeProof(garbage[:31]),
		"33 bytes":        session.EncodeProof(append(append([]byte(nil), garbage...), 1)),
		"padded":          session.EncodeProof(garbage) + "=",
		"not base64":      "!" + session.EncodeProof(garbage)[1:],
	}
	for name, proof := range shapes {
		t.Run(name, func(t *testing.T) {
			_, l := inviteLink(t, hostDir, base, "ancan")
			joinWithTokenOnly(t, rc, l, func(m *session.Message) { m.Proof = proof })
			mustRefuse(t, "proof", "confirm", "--dir", hostDir, "--code", "00000000", "ancan")
		})
	}
}

// readerFunc is an io.Reader from a function.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// Without --code, confirm asks the code on stdin only after the proof has
// verified, with the peer's id in the prompt; a joiner without the secret
// never reaches the prompt.
func TestConfirmAsksCodeAfterProof(t *testing.T) {
	_, rc, base := relaytest.Start(t, login)
	hostDir, guestDir := newDir(t, config{}), newDir(t, config{})
	guestRoot := rootOf(t, guestDir)
	defer func(r io.Reader) { stdin = r }(stdin)

	// A joiner without the secret: the prompt is never reached.
	_, l := inviteLink(t, hostDir, base, "ancan")
	joinWithTokenOnly(t, rc, l, nil)
	stdin = readerFunc(func([]byte) (int, error) {
		t.Fatal("the code was asked before the proof verified")
		return 0, nil
	})
	code, _, errb := cmd(t, "confirm", "--dir", hostDir, "ancan")
	if code != 1 || !strings.Contains(errb, "proof") || strings.Contains(errb, "code from") {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}

	// The genuine guest: the prompt names the peer, the typed code confirms.
	link, _ := inviteLink(t, hostDir, base, "ancan")
	out := mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	m := codeRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("accept printed no code line:\n%s", out)
	}
	stdin = bytes.NewBufferString(m[1] + "\n")
	code, out, errb = cmd(t, "confirm", "--dir", hostDir, "ancan")
	want := "code from ancan (" + keys.PartyID(guestRoot.Public()) + "), as read back over the chat the link went on: "
	if code != 0 || !strings.Contains(errb, want) || !strings.Contains(out, "confirmed ancan ("+keys.PartyID(guestRoot.Public())+")") {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, errb, out)
	}
}
