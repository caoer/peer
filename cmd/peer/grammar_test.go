package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// send refuses every shape whose delivery record could not be written — a
// kind outside the vendor grammar, an agent segment with a space, a slash or
// over 64 characters — and keeps nothing: no outbox entry, no envelope on the
// relay, and the channel still delivers what follows.
func TestSendRefusesAddressARecordCannotCarry(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	before := len(srv.Envelopes(p.channel, "g2h"))

	mustRefuse(t, "unknown message kind", "send", "--dir", p.guestDir, "--kind", "vnd.acme.run", "--text", "x", "zt/advisor")
	mustRefuse(t, "is not an agent id", "send", "--dir", p.guestDir, "--from", "legal team", "--text", "x", "zt/advisor")
	mustRefuse(t, "is not an agent id", "send", "--dir", p.guestDir, "--text", "x", "zt/advisor x")
	mustRefuse(t, "is not an agent id", "send", "--dir", p.guestDir, "--text", "x", "zt/team/advisor")
	mustRefuse(t, "is not an agent id", "send", "--dir", p.guestDir, "--text", "x", "zt/"+strings.Repeat("a", 65))

	gp, err := openParty(p.guestDir)
	if err != nil {
		t.Fatal(err)
	}
	if es, _ := gp.outbox.Entries(); len(es) != 0 {
		t.Fatalf("the refused sends left %d outbox entries", len(es))
	}
	if n := len(srv.Envelopes(p.channel, "g2h")); n != before {
		t.Fatalf("the refused sends put %d envelopes", n-before)
	}

	good, _ := sendOK(t, p.guestDir, "--text", "an ordinary message", "zt/advisor")
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "delivered text "+good) {
		t.Fatalf("host serve:\n%s", out)
	}
}

// The vendor kind the design and message.go document — vnd.<party id>.<name>,
// so it carries the party id's colon — goes out, is delivered, and the
// ordinary message behind it is delivered too: every later serve starts.
func TestServeDeliversDocumentedVendorKind(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)

	kind := "vnd." + p.guestParty + ".ping"
	if !session.ValidKind(kind) {
		t.Fatalf("session.ValidKind refuses the documented shape %q", kind)
	}
	vendor, _ := sendOK(t, p.guestDir, "--kind", kind, "--text", "ping", "zt")
	good, _ := sendOK(t, p.guestDir, "--text", "an ordinary message behind it", "zt/advisor")

	for i := 1; i <= 3; i++ {
		code, out, errb := cmd(t, "serve", "--dir", p.hostDir, "--once")
		if code != 0 {
			t.Fatalf("serve %d: exit %d, stderr %q", i, code, strings.TrimSpace(errb))
		}
		if i == 1 && !strings.Contains(out, "delivered "+kind+" "+vendor) {
			t.Fatalf("serve 1 did not deliver the vendor message:\n%s", out)
		}
	}
	in := records(t, deliverDirOf(p.hostDir), deliver.Inbox)
	for _, id := range []string{vendor, good} {
		if _, ok := in[id]; !ok {
			t.Errorf("%s is not in the inbox (%d records)", id, len(in))
		}
	}
	fm, _, body := parseRecord(t, in[vendor])
	if fm["kind"] != `"`+kind+`"` || body != "ping" {
		t.Fatalf("vendor record %v %q", fm, body)
	}
}

// The accepts border held for the agents the card lists and was open to
// every other label: an agent id the card does not list took nil accepts,
// which Route reads as "every kind". A kind refused for the listed agent
// landed in the inbox when it was addressed one character beside it.
func TestServeQuarantinesAnAgentTheCardDoesNotList(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)

	listed, _ := sendOK(t, p.guestDir, "--kind", "question", "--text", "to the listed agent", "zt/advisor")
	unlisted, _ := sendOK(t, p.guestDir, "--kind", "question", "--text", "to an agent the card does not list", "zt/nosuchagent")
	beside, _ := sendOK(t, p.guestDir, "--kind", "vnd."+p.guestParty+".run", "--text", "one character beside it", "zt/advisor2")
	party, _ := sendOK(t, p.guestDir, "--kind", "question", "--text", "to the party itself", "zt")

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	in := records(t, deliverDirOf(p.hostDir), deliver.Inbox)
	q := records(t, deliverDirOf(p.hostDir), deliver.Quarantine)
	for _, id := range []string{listed, unlisted, beside} {
		if _, ok := q[id]; !ok {
			t.Errorf("%s is not in quarantine; serve said:\n%s", id, out)
		}
	}
	// The bare party address is the party itself, which takes every kind.
	if _, ok := in[party]; !ok {
		t.Errorf("a question to the party itself was not delivered:\n%s", out)
	}
	if len(in) != 1 || len(q) != 3 {
		t.Fatalf("%d records in the inbox, %d in quarantine", len(in), len(q))
	}
}

// A committed spool entry whose record can never be written — an older
// version wrote it, or the bytes rotted — is dropped with its reason instead
// of failing start, so delivery on every channel keeps running.
func TestServeStartDropsUnrenderableSpoolEntry(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)

	j, err := store.OpenJournal(filepath.Join(p.hostDir, spoolDir))
	if err != nil {
		t.Fatal(err)
	}
	m, err := session.NewMessage(p.guestParty, p.hostParty+"/advisor team", session.KindText, []byte("wedge"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	e := &store.Entry{ID: m.ID, Channel: p.channel, Seq: 99, Type: "msg", Body: plain}
	if err := j.Add(e); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkCommitted(e); err != nil {
		t.Fatal(err)
	}

	good, _ := sendOK(t, p.guestDir, "--text", "behind the unrenderable entry", "zt/advisor")
	code, out, errb := cmd(t, "serve", "--dir", p.hostDir, "--once")
	if code != 0 {
		t.Fatalf("serve: exit %d, stderr %q", code, strings.TrimSpace(errb))
	}
	if !strings.Contains(out, "dropped "+m.ID+" from the spool") {
		t.Fatalf("serve did not report the drop:\n%s", out)
	}
	if !strings.Contains(out, "delivered text "+good) {
		t.Fatalf("the message behind it was not delivered:\n%s", out)
	}
	if es, _ := j.Entries(); len(es) != 0 {
		t.Fatalf("spool after the drop: %+v", es)
	}
}
