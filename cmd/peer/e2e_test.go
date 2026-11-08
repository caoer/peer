package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/e2e"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// peerProc runs the CLI in its own OS process and logs the transcript.
func peerProc(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	c := exec.Command(os.Args[0], args...)
	c.Env = append(os.Environ(), "PEER_CLI_CHILD=1")
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	t.Logf("$ peer %s\n[exit %d]\n%s%s", strings.Join(args, " "), code, out.String(), errb.String())
	return code, out.String(), errb.String()
}

func procOK(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errb := peerProc(t, args...)
	if code != 0 {
		t.Fatalf("peer %s: exit %d: %s", strings.Join(args, " "), code, errb)
	}
	return out
}

// keygen is a throwaway pair from the CLI.
func keygen(t *testing.T) (pub, secret string) {
	t.Helper()
	lines := strings.Fields(procOK(t, "e2e", "keygen"))
	if len(lines) != 2 || !strings.HasPrefix(lines[0], e2e.PublicPrefix) || !strings.HasPrefix(lines[1], e2e.SecretPrefix) {
		t.Fatalf("keygen printed %v", lines)
	}
	return lines[0], lines[1]
}

// publishKey is dir publishing a new key, the reader's serve pinning it.
func publishKey(t *testing.T, dir, readerDir string) (pub, secret string) {
	t.Helper()
	pub, secret = keygen(t)
	procOK(t, "e2e", "publish", "--dir", dir, pub)
	procOK(t, "serve", "--dir", readerDir, "--once")
	return pub, secret
}

func envelopeKeys(t *testing.T, env []byte) []string {
	t.Helper()
	var e struct {
		To []struct {
			Key string `json:"key"`
		} `json:"to"`
	}
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatalf("%v\n%s", err, env)
	}
	var out []string
	for _, s := range e.To {
		out = append(out, s.Key)
	}
	return out
}

// The U2 check, each step its own OS process on the fake relay: a keyless
// peer refused by name; A publishes, B's status lists the key; B's encrypted
// send is an inbox record marked e2e with the envelope for a body; A
// decrypts it to hi.
func TestE2ETwoProcess(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	a, b := p.hostDir, p.guestDir

	code, _, errb := peerProc(t, "send", "--dir", b, "--encrypt", "--text", "too early", "zt")
	if code != 1 || !strings.Contains(errb, "zt has published no e2e key") {
		t.Fatalf("send to a keyless peer: exit %d: %s", code, errb)
	}

	pub, secret := publishKey(t, a, b)
	var rows []statusJSON
	if err := json.Unmarshal([]byte(procOK(t, "status", "--dir", b, "--json")), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].Readers) != 1 || rows[0].Readers[0] != pub {
		t.Fatalf("status: %+v", rows)
	}
	if out := procOK(t, "status", "--dir", b); !strings.Contains(out, "READERS") || !strings.Contains(out, tail(pub)) {
		t.Fatalf("status table:\n%s", out)
	}

	out := procOK(t, "send", "--dir", b, "--encrypt", "--text", "hi", "zt")
	id := sentRE.FindStringSubmatch(out)[1]
	procOK(t, "serve", "--dir", a, "--once")

	path := filepath.Join(deliverDirOf(a), "inbox", id+".md")
	rec, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, v, body := frontMatter(t, rec)
	if strings.Join(keys, " ") != "from to kind verified at e2e" || v["e2e"] != e2e.Suite || !strings.HasPrefix(body, `{"e2e":`) {
		t.Fatalf("record:\n%s", rec)
	}

	if out := procOK(t, "e2e", "decrypt", "--key", secret, path); out != "hi" {
		t.Fatalf("decrypt printed %q", out)
	}
	_, other := keygen(t)
	if code, _, errb := peerProc(t, "e2e", "decrypt", "--key", other, path); code != 1 || !strings.Contains(errb, "encrypted to other keys") {
		t.Fatalf("decrypt with another key: exit %d: %s", code, errb)
	}
}

// What --encrypt refuses, before anything is sent, and what --to-key adds.
func TestE2ESendRefusalsAndToKey(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	f := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub2, secret2, err := e2e.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"doc", "file"} {
		if code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--encrypt", "--kind", kind, "--file", f, "zt"); code != 1 || !strings.Contains(errb, "does not take a "+kind) {
			t.Fatalf("%s: exit %d: %s", kind, code, errb)
		}
	}
	if code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--to-key", pub2, "--text", "x", "zt"); code != 2 || !strings.Contains(errb, "goes with --encrypt") {
		t.Fatalf("--to-key alone: exit %d: %s", code, errb)
	}
	if code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--encrypt", "--to-key", "x25519:short", "--text", "x", "zt"); code != 1 || !strings.Contains(errb, "x25519:short") {
		t.Fatalf("a bad --to-key: exit %d: %s", code, errb)
	}

	// No key published: --to-key alone carries it.
	id, _ := sendOK(t, p.guestDir, "--encrypt", "--to-key", pub2, "--text", "by hand", "zt")
	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	_, _, body := frontMatter(t, records(t, deliverDirOf(p.hostDir), deliver.Inbox)[id])
	if plain, err := e2e.Open([]byte(body), secret2); err != nil || string(plain) != "by hand" {
		t.Fatalf("open: %q, %v", plain, err)
	}

	// Published too: both keys open it, a key named twice is one stanza.
	pub1, secret1 := publishKey(t, p.hostDir, p.guestDir)
	id, _ = sendOK(t, p.guestDir, "--encrypt", "--to-key", pub2, "--to-key", pub1, "--text", "both", "zt")
	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	_, _, body = frontMatter(t, records(t, deliverDirOf(p.hostDir), deliver.Inbox)[id])
	if s := envelopeKeys(t, []byte(body)); len(s) != 2 {
		t.Fatalf("stanzas %v", s)
	}
	for _, secret := range []string{secret1, secret2} {
		if plain, err := e2e.Open([]byte(body), secret); err != nil || string(plain) != "both" {
			t.Fatalf("open: %q, %v", plain, err)
		}
	}

	// Sealed past what a record holds: refused with the size and the limit,
	// and nothing waits in the outbox.
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), envelope.MaxBody-1000), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--encrypt", "--file", big, "zt")
	if code != 1 || !strings.Contains(errb, "at most 1048576 bytes") {
		t.Fatalf("oversize: exit %d: %s", code, errb)
	}
	if es, _ := os.ReadDir(filepath.Join(p.guestDir, outboxDir)); len(es) != 0 {
		t.Errorf("outbox holds %d entries", len(es))
	}
}

func TestE2EKeygenHelp(t *testing.T) {
	code, _, errb := cmd(t, "e2e", "keygen", "--help")
	if code != 0 || !strings.Contains(errb, "stays with the human") || !strings.Contains(errb, "never on a\nserving host") {
		t.Fatalf("exit %d:\n%s", code, errb)
	}
}

// publish edits only details.readers, and a second publish replaces the key.
func TestE2EPublishKeepsConfig(t *testing.T) {
	dir := newDir(t, hostCfg())
	path := filepath.Join(dir, configFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = append([]byte(`{"future":{"url":"https://x/?a=1&b=2"},`), b[1:]...)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	pub1, _, _ := e2e.GenerateKey()
	pub2, _, _ := e2e.GenerateKey()
	mustOK(t, "e2e", "publish", "--dir", dir, pub1)
	mustOK(t, "e2e", "publish", "--dir", dir, pub2)
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("a=1&b=2")) {
		t.Errorf("an unknown key changed:\n%s", b)
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	d, err := e2e.ParseDetails(cfg.Details)
	if err != nil || d == nil || len(d.Keys) != 1 || d.Keys[0] != pub2 {
		t.Fatalf("details %s: %v", cfg.Details, err)
	}
	if !bytes.Contains(cfg.Details, []byte(`"advisor"`)) || len(cfg.Agents) != 1 {
		t.Errorf("config lost its details or agents:\n%s", b)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode().Perm())
	}

	if code, _, errb := cmd(t, "e2e", "publish", "--dir", dir, "x25519:short"); code != 1 || errb == "" {
		t.Fatalf("a bad key: exit %d: %s", code, errb)
	}
	if err := os.Remove(filepath.Join(dir, rootFile)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if code, _, errb := cmd(t, "e2e", "publish", "--dir", dir, pub1); code != 1 || !strings.Contains(errb, rootFile) {
		t.Fatalf("no root: exit %d: %s", code, errb)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("config changed without a root to sign the card")
	}
}

// A body with no frontmatter decrypts as it stands.
func TestE2EDecryptBareEnvelope(t *testing.T) {
	pub, secret, err := e2e.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.Seal([]byte("---\nbare\n"), []string{pub})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "env.json")
	if err := os.WriteFile(f, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if out := mustOK(t, "e2e", "decrypt", "--key", secret, f); out != "---\nbare\n" {
		t.Fatalf("decrypt printed %q", out)
	}
}

// A room send seals to every other member's published keys and refuses
// naming each member without one; the --to subset is all that needs a key.
func TestE2ERoom(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	a, b, c := newDir(t, config{}), newDir(t, config{}), newDir(t, config{})
	ab := handshakeNamed(t, a, b, base, "bob", "alice")
	ac := handshakeNamed(t, a, c, base, "carol", "alice")
	pubB, secretB, _ := e2e.GenerateKey()
	mustOK(t, "e2e", "publish", "--dir", b, pubB)
	mustOK(t, "serve", "--dir", a, "--once")
	id := createRoom(t, a, base, "r1")
	addToRoom(t, a, b, "r1", "bob")
	addToRoom(t, a, c, "r1", "carol")
	for _, d := range []string{b, c, a} {
		mustOK(t, "serve", "--dir", d, "--once")
	}

	code, _, errb := cmd(t, "send", "--dir", a, "--encrypt", "--text", "x", "r1")
	if code != 1 || !strings.Contains(errb, ac.guestParty) || strings.Contains(errb, ab.guestParty) {
		t.Fatalf("a keyless member: exit %d: %s", code, errb)
	}
	if code, _, errb := cmd(t, "send", "--dir", a, "--encrypt", "--to-key", pubB, "--text", "x", "r1"); code != 2 || !strings.Contains(errb, "goes with a peer") {
		t.Fatalf("--to-key into a room: exit %d: %s", code, errb)
	}

	mid, _ := roomSendOK(t, a, "--encrypt", "--to", "bob", "--text", "sealed", "r1")
	mustOK(t, "serve", "--dir", b, "--once")
	rec := records(t, deliverDirOf(b), deliver.Inbox)[mid]
	if rec == nil {
		t.Fatal("no record at the keyed member")
	}
	keys, v, body := frontMatter(t, rec)
	if strings.Join(keys, " ") != "from to kind verified at group e2e" || v["e2e"] != e2e.Suite || v["group"] != id {
		t.Fatalf("record:\n%s", rec)
	}
	if plain, err := e2e.Open([]byte(body), secretB); err != nil || string(plain) != "sealed" {
		t.Fatalf("open: %q, %v", plain, err)
	}
}

// The forward carries every received record, an encrypted one marked e2e
// with the envelope for its body, a plain one as it is.
func TestForwardMarksE2E(t *testing.T) {
	p, h, _ := forwardPair(t)
	// In this process: a child would not trust the forward hook's certificate.
	pub, _, err := e2e.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	mustOK(t, "e2e", "publish", "--dir", p.guestDir, pub)
	mustOK(t, "serve", "--dir", p.hostDir, "--once")

	mustOK(t, "send", "--dir", p.hostDir, "--encrypt", "--text", "locked", "ancan")
	out := mustOK(t, "send", "--dir", p.hostDir, "--text", "plain words", "ancan")
	idPlain := sentRE.FindStringSubmatch(out)[1]
	before := h.count()
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if h.count() != before+2 {
		t.Fatalf("%d POSTs, want both records", h.count()-before)
	}
	f1, raw1 := h.post(t, before)
	f2, _ := h.post(t, before+1)
	var env string
	if err := json.Unmarshal(f1.Body, &env); err != nil {
		t.Fatal(err)
	}
	if !f1.E2E || !strings.HasPrefix(env, `{"e2e":1,`) || !bytes.Contains(raw1, []byte(`"e2e":true`)) || bytes.Contains(raw1, []byte("locked")) {
		t.Errorf("encrypted record %s", raw1)
	}
	if f2.E2E || f2.ID != idPlain || string(f2.Body) != `"plain words"` {
		t.Errorf("plain record %+v", f2)
	}
}

// A body starting like an envelope that is not one stays plain text.
func TestE2ENotAnEnvelopeIsPlain(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	id, _ := sendOK(t, p.hostDir, "--text", `{"e2e":"no"}`, "ancan")
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	keys, _, _ := frontMatter(t, records(t, deliverDirOf(p.guestDir), deliver.Inbox)[id])
	if strings.Join(keys, " ") != "from to kind verified at" {
		t.Fatalf("keys %v", keys)
	}
}
