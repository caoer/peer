package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/store"
)

// failKeys refuses the party keys record's write, as a state page answering
// 5xx would; every other record's write lands.
type failKeys struct{ store.Backend }

func (f failKeys) Store(ctx context.Context, key string, data []byte, expect int64) (int64, error) {
	if key == store.KeysKey {
		return 0, errors.New("state page: 503 (test)")
	}
	return f.Backend.Store(ctx, key, data, expect)
}

// landThenFail lets a channel record's write land and then answers with a
// transport error, the shape the pages backend has when the PUT went out and
// its answer did not come back.
type landThenFail struct{ store.Backend }

func (l landThenFail) Store(ctx context.Context, key string, data []byte, expect int64) (int64, error) {
	v, err := l.Backend.Store(ctx, key, data, expect)
	if err == nil && strings.HasPrefix(key, "ss.") {
		return 0, errors.New("state page: the answer was lost after the write (test)")
	}
	return v, err
}

// failChannel refuses a channel record's write before it lands, as a state
// page answering 503 would; every other record's write lands.
type failChannel struct{ store.Backend }

func (f failChannel) Store(ctx context.Context, key string, data []byte, expect int64) (int64, error) {
	if strings.HasPrefix(key, "ss.") {
		return 0, errors.New("state page: 503 (test)")
	}
	return f.Backend.Store(ctx, key, data, expect)
}

// handshakeNoServe stops after confirm, so neither side has decrypted a reply
// and the guest's next message is a PreKey message — the normal path between
// accept and the first serve.
func handshakeNoServe(t *testing.T, hostDir, guestDir, base string) *pair {
	t.Helper()
	p := &pair{hostDir: hostDir, guestDir: guestDir, hostRoot: rootOf(t, hostDir), guestRoot: rootOf(t, guestDir)}
	p.hostParty, p.guestParty = keys.PartyID(p.hostRoot.Public()), keys.PartyID(p.guestRoot.Public())
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	l, err := invite.Parse(link, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.channel = l.Channel
	out = mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	mustOK(t, "confirm", "--dir", hostDir, "--code", codeRE.FindStringSubmatch(out)[1], "ancan")
	return p
}

// A PreKey message whose channel commit lands and whose party keys commit
// fails: the keys failure leaves the spent one-time prekey as a spare and is
// reported, and the message is delivered. Before the fix the error came back
// after the commit, the spool entry was dropped and the message was gone for
// good, with the cursor past it.
func TestServeDeliversWhenTheKeysCommitFails(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	p := handshakeNoServe(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	id, _ := sendOK(t, p.guestDir, "--text", "sent before my serve ran", "zt/advisor")
	rows := srv.Envelopes(p.channel, "g2h")
	if last := rows[len(rows)-1]; last.Type != "prekey" {
		t.Fatalf("the guest's message is %s, want prekey", last.Type)
	}

	var out bytes.Buffer
	sv, err := openServer(p.hostDir, "", &out)
	if err != nil {
		t.Fatal(err)
	}
	sv.p.store = store.New(failKeys{sv.p.backend}, sv.p.id)
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err != nil {
		t.Fatalf("round with the keys write failing: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "stays a spare") {
		t.Errorf("the keys failure was not reported:\n%s", out.String())
	}
	if _, ok := records(t, deliverDirOf(p.hostDir), deliver.Inbox)[id]; !ok {
		t.Fatalf("%s was not delivered:\n%s", id, out.String())
	}
	if es, _ := sv.spool.Entries(); len(es) != 0 {
		t.Errorf("spool after the round: %+v", es)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if !hch.Seen(id) {
		t.Errorf("%s is not in the seen set", id)
	}
}

// A channel commit whose write landed and whose answer was lost: the spool
// entry stays on disk, so the next start finds the message seen and births it
// once. Before the fix any non-conflict commit error dropped the entry while
// the cursor was already past the message.
func TestServeKeepsTheSpoolEntryWhenTheChannelAnswerIsLost(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	id, _ := sendOK(t, p.guestDir, "--text", "its commit landed, its answer did not", "zt/advisor")

	var out bytes.Buffer
	sv, err := openServer(p.hostDir, "", &out)
	if err != nil {
		t.Fatal(err)
	}
	sv.p.store = store.New(landThenFail{sv.p.backend}, sv.p.id)
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err == nil {
		t.Fatalf("round: no error, want the lost answer\n%s", out.String())
	}
	es, _ := sv.spool.Entries()
	if len(es) != 1 || es[0].ID != id {
		t.Fatalf("spool after the lost answer: %+v", es)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if !hch.Seen(id) || hch.Cursor() < 2 {
		t.Fatalf("the write did not land: seen %v cursor %d", hch.Seen(id), hch.Cursor())
	}

	// The next start replays it: the entry is not marked committed, but the
	// channel record has seen its id, so it is born — once.
	log := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(log, "delivered text "+id) {
		t.Fatalf("the replay did not deliver %s:\n%s", id, log)
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Inbox)); n != 1 {
		t.Fatalf("%d records in the inbox", n)
	}
	if es, _ := sv.spool.Entries(); len(es) != 0 {
		t.Fatalf("spool after the replay: %+v", es)
	}
	if log := mustOK(t, "serve", "--dir", p.hostDir, "--once"); strings.Contains(log, "delivered") {
		t.Fatalf("a second start delivered again:\n%s", log)
	}
}

// A birth that fails after its channel commit landed — here an inbox that is
// not writable for one round — is born by the next round of the same serve:
// the cursor is past the message, so no pull brings it again, and the round
// replays the spool before it pulls.
func TestServeRoundBirthsWhatAFailedBirthLeft(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	id, _ := sendOK(t, p.guestDir, "--text", "born a round late", "zt/advisor")

	var out bytes.Buffer
	sv, err := openServer(p.hostDir, "", &out)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	inbox := filepath.Join(deliverDirOf(p.hostDir), string(deliver.Inbox))
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inbox, 0o500); err != nil {
		t.Fatal(err)
	}
	err = sv.round(ctx)
	if err := os.Chmod(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	if err == nil {
		t.Fatalf("round with the inbox not writable: no error\n%s", out.String())
	}
	es, _ := sv.spool.Entries()
	if len(es) != 1 || es[0].ID != id || !es[0].Committed {
		t.Fatalf("spool after the failed birth: %+v", es)
	}

	if err := sv.round(ctx); err != nil {
		t.Fatalf("next round: %v\n%s", err, out.String())
	}
	if _, ok := records(t, deliverDirOf(p.hostDir), deliver.Inbox)[id]; !ok {
		t.Fatalf("the next round did not birth %s:\n%s", id, out.String())
	}
	if es, _ := sv.spool.Entries(); len(es) != 0 {
		t.Fatalf("spool after the next round: %+v", es)
	}
}

// A channel commit whose write landed and whose answer was lost leaves an
// uncommitted spool entry whose id the channel has seen: the next round of
// the same serve births it once, long before later traffic could push the id
// out of the bounded seen set.
func TestServeRoundBirthsWhenTheCommitAnswerIsLost(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	id, _ := sendOK(t, p.guestDir, "--text", "its commit landed, its answer did not", "zt/advisor")

	var out bytes.Buffer
	sv, err := openServer(p.hostDir, "", &out)
	if err != nil {
		t.Fatal(err)
	}
	healthy := sv.p.store
	sv.p.store = store.New(landThenFail{sv.p.backend}, sv.p.id)
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err == nil {
		t.Fatalf("round: no error, want the lost answer\n%s", out.String())
	}
	if es, _ := sv.spool.Entries(); len(es) != 1 || es[0].ID != id || es[0].Committed {
		t.Fatalf("spool after the lost answer: %+v", es)
	}

	sv.p.store = healthy
	if err := sv.round(ctx); err != nil {
		t.Fatalf("next round: %v\n%s", err, out.String())
	}
	if n := strings.Count(out.String(), "delivered text "+id); n != 1 {
		t.Fatalf("%s delivered %d times by the next round:\n%s", id, n, out.String())
	}
	if es, _ := sv.spool.Entries(); len(es) != 0 {
		t.Fatalf("spool after the next round: %+v", es)
	}
}

// A channel commit refused before its write landed leaves an uncommitted
// spool entry the channel has not seen: the next round drops it before its
// pull brings the message again, so the message is born once and no stale
// entry waits to birth it a second time at a later start.
func TestServeRoundDropsAnEntryWhoseCommitDidNotLand(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	id, _ := sendOK(t, p.guestDir, "--text", "refused once, then fine", "zt/advisor")

	var out bytes.Buffer
	sv, err := openServer(p.hostDir, "", &out)
	if err != nil {
		t.Fatal(err)
	}
	healthy := sv.p.store
	sv.p.store = store.New(failChannel{sv.p.backend}, sv.p.id)
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err == nil {
		t.Fatalf("round: no error, want the refused write\n%s", out.String())
	}
	if es, _ := sv.spool.Entries(); len(es) != 1 || es[0].ID != id || es[0].Committed {
		t.Fatalf("spool after the refused write: %+v", es)
	}

	sv.p.store = healthy
	if err := sv.round(ctx); err != nil {
		t.Fatalf("next round: %v\n%s", err, out.String())
	}
	if n := strings.Count(out.String(), "delivered text "+id); n != 1 {
		t.Fatalf("%s delivered %d times by the next round:\n%s", id, n, out.String())
	}
	if es, _ := sv.spool.Entries(); len(es) != 0 {
		t.Fatalf("spool after the next round: %+v", es)
	}
}
