package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// What the relay holds, from the client's side: a handshake and a message
// each way through the CLI, then every envelope the relay stored is read for
// the words the two parties said — the message body, both petnames, the
// sending agent and the host's details — as text, inside any base64 run, and
// as hex. The milestone-1 demo made the same scan of a live channel once
// (results/milestone-1.md § What the relay holds); this keeps it running.
// ccc-pages test/peer.spec.ts "what the relay holds" is the relay's half.
func TestRelayHoldsCiphertextOnly(t *testing.T) {
	const (
		bodyMarker    = "body-the-relay-must-never-read"
		taskMarker    = "task-the-relay-must-never-read"
		guestPetname  = "guest-petname-relay-must-never-read"
		hostPetname   = "host-petname-relay-must-never-read"
		senderAgent   = "sender-agent-relay-must-never-read"
		detailsMarker = "details-the-relay-must-never-read"
	)
	srv, _, base := relaytest.Start(t, login)
	cfg := config{
		Agents:  []card.Agent{{ID: "advisor", Accepts: []string{"text", "task"}}},
		Details: json.RawMessage(`{"advisor":{"type":"claude-code","note":"` + detailsMarker + `"}}`),
	}
	p := handshakeNamed(t, newDir(t, cfg), newDir(t, config{}), base, guestPetname, hostPetname)

	secrets := map[string]string{
		"body": bodyMarker, "task": taskMarker, "guest petname": guestPetname,
		"host petname": hostPetname, "sending agent": senderAgent, "details": detailsMarker,
	}
	// scan reads everything the relay holds for the channel; it runs after
	// each put, before the far end serves, so a leak is named where it entered.
	scan := func(after string, want int) {
		t.Helper()
		rows := append(srv.Envelopes(p.channel, "h2g"), srv.Envelopes(p.channel, "g2h")...)
		if len(rows) != want {
			t.Fatalf("after %s the relay holds %d envelopes, want %d", after, len(rows), want)
		}
		for _, row := range rows {
			for what, s := range secrets {
				if holds(row.Type+" "+row.Body, s) {
					t.Errorf("after %s the relay holds the %s in %s envelope #%d", after, what, row.Type, row.Seq)
				}
			}
		}
		for _, b := range srv.Blobs(p.channel) {
			for what, s := range secrets {
				if holds(string(srv.Blob(p.channel, b)), s) {
					t.Errorf("after %s the relay holds the %s in blob %s", after, what, b)
				}
			}
		}
	}
	handshaken := len(srv.Envelopes(p.channel, "h2g")) + len(srv.Envelopes(p.channel, "g2h"))
	scan("the handshake", handshaken)

	id, _ := sendOK(t, p.guestDir, "--kind", "text", "--from", senderAgent, "--text", "says: "+bodyMarker, hostPetname+"/advisor")
	scan("the text", handshaken+1)
	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	f := filepath.Join(t.TempDir(), "task.md")
	if err := os.WriteFile(f, []byte("# do\n\n"+taskMarker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id2, _ := sendOK(t, p.hostDir, "--kind", "task", "--from", "advisor", "--file", f, guestPetname)
	scan("the task", handshaken+2)
	mustOK(t, "serve", "--dir", p.guestDir, "--once")

	// The scan is not vacuous: both messages crossed and opened at the far end.
	if rec := records(t, deliverDirOf(p.hostDir), deliver.Inbox)[id]; !strings.Contains(string(rec), bodyMarker) {
		t.Fatalf("the host's inbox does not hold the text:\n%s", rec)
	}
	if rec := records(t, deliverDirOf(p.guestDir), deliver.Inbox)[id2]; !strings.Contains(string(rec), taskMarker) {
		t.Fatalf("the guest's inbox does not hold the task:\n%s", rec)
	}
}

var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{8,}`)

// holds reports whether marker sits in text as itself, as hex, or inside a
// base64 run (standard or url-safe, decoded at each of the four offsets so a
// run that starts mid-quantum still decodes).
func holds(text, marker string) bool {
	if strings.Contains(text, marker) || strings.Contains(strings.ToLower(text), hex.EncodeToString([]byte(marker))) {
		return true
	}
	for _, run := range base64Run.FindAllString(text, -1) {
		run = strings.NewReplacer("-", "+", "_", "/").Replace(run)
		for off := 0; off < 4 && off < len(run); off++ {
			r := run[off:]
			b, err := base64.RawStdEncoding.DecodeString(r[:len(r)-len(r)%4])
			if err == nil && strings.Contains(string(b), marker) {
				return true
			}
		}
	}
	return false
}
