package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// unlabeledFixture is the shared shape of the unlabeled tests: a ucc host
// whose guest is bound, by peers/parties.md, to the fixture session.
func unlabeledFixture(t *testing.T) (*pair, string) {
	t.Helper()
	_, _, base := relaytest.Start(t, login)
	root := uccRoot(t)
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)
	if err := os.WriteFile(filepath.Join(root, "peers", "parties.md"), []byte(
		"# peers/parties.md — sender binding\n\n| party | to |\n|---|---|\n| "+p.guestParty+" | [["+uccSession+"/rosters/advisor-demo]] |\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, root
}

// noticeID is the refusal notice's id for a message id, as ucc.go derives it.
func noticeID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "refused-" + hex.EncodeToString(sum[:20])
}

// guestAnswers is the refusal-kind answers the guest side has delivered.
func guestAnswers(t *testing.T, dir string) (n int) {
	t.Helper()
	for _, b := range records(t, deliverDirOf(dir), deliver.Inbox) {
		fm, _, _ := parseRecord(t, b)
		if strings.Trim(fm["kind"], `"`) == "answer" || strings.Contains(strings.Trim(fm["kind"], `"`), ".unlabeled") {
			n++
		}
	}
	return n
}

// The unlabeled refusal is not silent (task peer-unlabeled-message-silent-drop):
// a message that names no agent of ours, or a label the map does not carry, is
// consumed exactly as before — skip line, born nowhere — but the commit's
// winner answers the sender on the same line with the labels it may address,
// and a notice record is born in the session peers/parties.md binds the sender
// to, its birth line in the delivered shape peer-wake follows. A refusal-kind
// message is answered never (the loop guard); its notice still lands.
func TestServeUnlabeledAnswer(t *testing.T) {
	p, root := unlabeledFixture(t)

	bare, _ := sendOK(t, p.guestDir, "--kind", "text", "--text", "body of bare", "zt")
	nobody, _ := sendOK(t, p.guestDir, "--kind", "text", "--text", "body of nobody", "zt/nobody")
	guard := "vnd." + p.guestParty + ".unlabeled"
	gid, _ := sendOK(t, p.guestDir, "--kind", guard, "--text", "their own refusal", "zt")
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")

	// The refusal is still a consume: a skip line with each reason, and the
	// message itself born nowhere.
	for _, c := range []struct{ id, reason string }{
		{bare, `unmapped label "": refused`},
		{nobody, `unmapped label "nobody": refused`},
		{gid, `unmapped label "": refused`},
	} {
		if !strings.Contains(out, "skip ancan #") || !strings.Contains(out, c.reason) {
			t.Errorf("serve did not refuse with %q:\n%s", c.reason, out)
		}
		if bornAnywhere(t, root, c.id) {
			t.Errorf("%s was born under the root", c.id)
		}
	}

	// The notice: born in the bound session's inbox, in its own id namespace,
	// leading NOT DELIVERED, for the refusal-kind message as well — only its
	// answer is withheld.
	notice := sessionRecords(t, root, deliver.Inbox)
	for _, id := range []string{bare, nobody, gid} {
		b, ok := notice[noticeID(id)]
		if !ok {
			t.Errorf("the notice for %s is not in the bound session's inbox; serve said:\n%s", id, out)
			continue
		}
		if !strings.Contains(string(b), "NOT DELIVERED") {
			t.Errorf("the notice for %s does not lead with NOT DELIVERED:\n%s", id, b)
		}
	}
	if _, ok := notice[bare+"-refused"]; ok {
		t.Errorf("the notice id is the message id with a suffix, not its own namespace")
	}
	want := "delivered vnd." + p.hostParty + ".unlabeled " + noticeID(bare) + " → " + filepath.Join(root, uccSession, "inbox", noticeID(bare)+".md")
	if !strings.Contains(out, want) {
		t.Errorf("the notice's birth line is not the delivered shape peer-wake follows:\nwant %q\nserve said:\n%s", want, out)
	}
	// The journal names the answer by the id the sender's record will carry.
	sum := sha256.Sum256([]byte(bare))
	if want := "unlabeled answer unlabeled-" + hex.EncodeToString(sum[:20]) + " → ancan for " + bare; !strings.Contains(out, want) {
		t.Errorf("serve did not journal the answer's id:\nwant %q\nserve said:\n%s", want, out)
	}
	// The notice for the loop-guarded message says its answer was withheld.
	if b, ok := notice[noticeID(gid)]; !ok || !strings.Contains(string(b), "withheld") {
		t.Errorf("the loop-guarded notice does not say the answer was withheld:\n%s", b)
	}

	// The answer on the line: the sender's side delivers it locally — two
	// answers, one per refusal, none for the refusal-kind message.
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	answers := 0
	for _, b := range records(t, deliverDirOf(p.guestDir), deliver.Inbox) {
		fm, _, body := parseRecord(t, b)
		if strings.Trim(fm["kind"], `"`) != "vnd."+p.hostParty+".unlabeled" {
			continue
		}
		answers++
		if fm["from"] != p.hostParty {
			t.Errorf("the answer is not from the party itself: %v", fm)
		}
		if !strings.Contains(body, "was not delivered") || !strings.Contains(body, "leader") {
			t.Errorf("the answer does not name the refusal and the labels:\n%s", body)
		}
	}
	if answers != 2 {
		t.Errorf("%d answers on the line, want 2 — the refusal-kind message is answered never", answers)
	}

	// A second serve re-answers nothing and births nothing.
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); strings.Contains(out, "delivered vnd.") || strings.Contains(out, "skip ancan") {
		t.Errorf("a second serve re-answered:\n%s", out)
	}
	if n := guestAnswers(t, p.guestDir); n != 2 {
		t.Errorf("%d answers on the sender's side after the second serve, want 2", n)
	}
}

// A host cut between an unlabeled refusal's commit and its answer and notice
// — the crash the review's finding 1 names — leaves the owed step in the
// spool, committed; the next start replays it once (answer out, notice born)
// and empties the spool; a start after that does nothing.
func TestServeUnlabeledCrashAfterCommitReplaysOnce(t *testing.T) {
	ctx := context.Background()
	p, root := unlabeledFixture(t)
	bare, _ := sendOK(t, p.guestDir, "--kind", "text", "--text", "body of bare", "zt")

	sv, err := openServer(p.hostDir, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	sv.beforeRefusal = func(e *store.Entry) error {
		if e.ID == bare {
			return errors.New("cut before the refusal step")
		}
		return nil
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err == nil || !strings.Contains(err.Error(), "cut before the refusal step") {
		t.Fatalf("round: %v", err)
	}
	spool := func() []*store.Entry {
		t.Helper()
		j, err := store.OpenJournal(filepath.Join(p.hostDir, spoolDir))
		if err != nil {
			t.Fatal(err)
		}
		es, err := j.Entries()
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	es := spool()
	if len(es) != 1 || es[0].ID != bare || !isRefusedType(es[0].Type) || !es[0].Committed {
		t.Fatalf("spool after the cut: %+v", es)
	}
	if len(sessionRecords(t, root, deliver.Inbox)) != 0 {
		t.Fatal("a notice was born before the cut")
	}
	if n := guestAnswers(t, p.guestDir); n != 0 {
		t.Fatalf("%d answers before the cut, want none", n)
	}

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "delivered vnd."+p.hostParty+".unlabeled "+noticeID(bare)+" → ") {
		t.Errorf("the replay did not birth the notice:\n%s", out)
	}
	if n := len(spool()); n != 0 {
		t.Errorf("%d entries left in the spool after the replay", n)
	}
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if n := guestAnswers(t, p.guestDir); n != 1 {
		t.Fatalf("%d answers after the replay, want 1", n)
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); strings.Contains(out, "delivered vnd.") || strings.Contains(out, "skip ancan") {
		t.Errorf("a start after the replay re-ran the step:\n%s", out)
	}
}

// A far party may choose a message id up to the grammar's 64 characters; the
// notice's own id stays inside the grammar and lands.
func TestServeUnlabeledLongFarID(t *testing.T) {
	ctx := context.Background()
	p, root := unlabeledFixture(t)

	gp, gch, gpe := channelOf(t, p.guestDir, "zt")
	gk, err := gp.keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 60)
	m := &session.Message{V: session.MessageVersion, ID: id, From: gp.partyID(), To: p.hostParty, Kind: session.KindText, At: time.Now().UTC(), Body: []byte("a long id")}
	if _, err := session.New(gch, gk).Send(ctx, gp.outbox, relay.New(gpe.Relay, nil), gpe.Token, m); err != nil {
		t.Fatal(err)
	}

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, `unmapped label "": refused`) {
		t.Errorf("the long-id message was not refused:\n%s", out)
	}
	if strings.Contains(out, "did not land") {
		t.Errorf("the notice for a long far id did not land:\n%s", out)
	}
	notice := sessionRecords(t, root, deliver.Inbox)
	if _, ok := notice[noticeID(id)]; !ok {
		t.Errorf("no notice record for the long id; serve said:\n%s", out)
	}
}

// A relay that refuses the answer on the receive path does not lose it: the
// round's send meets the refusal (a proxy in front of the relay refuses every
// envelope put once the refusal is claimed — the peer the round holds points
// at it), commits to the outbox, and the notice keeps the outbox promise; the
// answer goes out on the next round, once.
func TestServeUnlabeledSendFailedOutboxKeepsPromise(t *testing.T) {
	ctx := context.Background()
	p, root := unlabeledFixture(t)
	bare, _ := sendOK(t, p.guestDir, "--kind", "text", "--text", "body of bare", "zt")
	hp, err := openParty(p.hostDir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, hpe := channelOf(t, p.hostDir, "ancan")
	live, err := url.Parse(hpe.Relay)
	if err != nil {
		t.Fatal(err)
	}
	var refuse atomic.Bool
	fwd := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: live.Scheme, Host: live.Host})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/envelopes") {
			http.Error(w, "refused by the test", http.StatusServiceUnavailable)
			return
		}
		fwd.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	if err := roster.Update(ctx, hp.backend, func(r *roster.Roster) error {
		r.ByName("ancan").Relay = proxy.URL + live.Path
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var journal strings.Builder
	sv, err := openServer(p.hostDir, "", &journal)
	if err != nil {
		t.Fatal(err)
	}
	sv.beforeRefusal = func(e *store.Entry) error {
		if e.ID == bare {
			refuse.Store(true)
		}
		return nil
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err != nil {
		t.Fatalf("round with the refusing relay: %v", err)
	}
	refuse.Store(false)
	if !strings.Contains(journal.String(), "the relay did not take it") {
		t.Fatalf("the round's send did not meet the refusing relay:\n%s", journal.String())
	}
	b, ok := sessionRecords(t, root, deliver.Inbox)[noticeID(bare)]
	if !ok || !strings.Contains(string(b), "stays with the outbox") {
		t.Errorf("the notice does not keep the outbox promise:\n%s", b)
	}
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if n := guestAnswers(t, p.guestDir); n != 0 {
		t.Fatalf("%d answers reached the sender through the refusing relay", n)
	}

	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if n := guestAnswers(t, p.guestDir); n != 1 {
		t.Fatalf("%d answers after the relay came back, want 1", n)
	}
}

// An unlabeled refusal whose bound seat's session is not on this root (round-2
// finding 2: the notice dropped off the winner's root) waits before its
// consume, as a delivery waits: no answer, no notice, the cursor before the
// message. Once the session is on the root the next round answers once and
// births the notice there.
func TestServeUnlabeledNoticeWaitsForBoundSession(t *testing.T) {
	p, root := unlabeledFixture(t)
	bare, _ := sendOK(t, p.guestDir, "--kind", "text", "--text", "body of bare", "zt")

	sd := filepath.Join(root, filepath.FromSlash(uccSession))
	if err := os.Rename(sd, sd+".away"); err != nil {
		t.Fatal(err)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "ancan: waiting at #2: the notice's bound session is not on this root") {
		t.Fatalf("serve did not wait for the bound session:\n%s", out)
	}
	if strings.Contains(out, "skip ancan") || strings.Contains(out, "unlabeled answer") {
		t.Errorf("serve consumed or answered while the session was away:\n%s", out)
	}
	if _, hch, _ := channelOf(t, p.hostDir, "ancan"); hch.Cursor() != 1 {
		t.Fatalf("cursor %d after the wait, want 1", hch.Cursor())
	}
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if n := guestAnswers(t, p.guestDir); n != 0 {
		t.Fatalf("%d answers while the session was away", n)
	}
	if err := os.Rename(sd+".away", sd); err != nil {
		t.Fatal(err)
	}

	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if _, ok := sessionRecords(t, root, deliver.Inbox)[noticeID(bare)]; !ok {
		t.Fatalf("no notice once the session was back:\n%s", out)
	}
	if _, hch, _ := channelOf(t, p.hostDir, "ancan"); hch.Cursor() != 2 {
		t.Errorf("cursor %d after the refusal, want 2", hch.Cursor())
	}
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if n := guestAnswers(t, p.guestDir); n != 1 {
		t.Errorf("%d answers once the session was back, want 1", n)
	}
}

// However many hosts replay the refusal step, the line sees one answer: the
// answer's id is derived from the refused message's, and the receiver's
// replay protection refuses the second envelope of the same id. A re-planted
// committed entry — a second host's landed-but-errored commit, or a stale
// copy — re-runs the step: the re-send is refused there, the notice finds
// its own record already born.
func TestServeUnlabeledReplayIsIdempotentOnTheLine(t *testing.T) {
	ctx := context.Background()
	p, _ := unlabeledFixture(t)
	bare, _ := sendOK(t, p.guestDir, "--kind", "text", "--text", "body of bare", "zt")

	sv, err := openServer(p.hostDir, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var captured *store.Entry
	sv.beforeRefusal = func(e *store.Entry) error {
		if e.ID == bare {
			captured = &store.Entry{ID: e.ID, Channel: e.Channel, Seq: e.Seq, Type: e.Type, Body: e.Body, Committed: true}
		}
		return nil
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("the refusal step never reached its commit")
	}
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if n := guestAnswers(t, p.guestDir); n != 1 {
		t.Fatalf("%d answers after the first run, want 1", n)
	}

	// The second host's landed-but-errored commit: the same entry, still
	// committed, replayed after the first host already answered.
	j, err := store.OpenJournal(filepath.Join(p.hostDir, spoolDir))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Add(captured); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkCommitted(captured); err != nil {
		t.Fatal(err)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if n := guestAnswers(t, p.guestDir); n != 1 {
		t.Fatalf("%d answers after the replay, want 1 — the line saw a second answer", n)
	}
	if !strings.Contains(out, "already delivered vnd."+p.hostParty+".unlabeled "+noticeID(bare)) {
		t.Errorf("the replayed step did not find its notice already born:\n%s", out)
	}
}

// The notice's outcome text says what the answer did, and a relay that
// refuses the send loses nothing: the answer stays in the outbox and goes
// out on the next round, as peer send promises. The relay dies through the
// roster the replay loads, the send's own path.
func TestServeUnlabeledDeadRelayOutcomeAndOutbox(t *testing.T) {
	ctx := context.Background()
	p, root := unlabeledFixture(t)
	bare, _ := sendOK(t, p.guestDir, "--kind", "text", "--text", "body of bare", "zt")
	hp, err := openParty(p.hostDir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, hpe := channelOf(t, p.hostDir, "ancan")
	live := hpe.Relay

	sv, err := openServer(p.hostDir, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	sv.beforeRefusal = func(e *store.Entry) error {
		if e.ID != bare {
			return nil
		}
		return errors.New("cut before the refusal step")
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err == nil || !strings.Contains(err.Error(), "cut before the refusal step") {
		t.Fatalf("round: %v", err)
	}

	dead := func(dead bool) {
		t.Helper()
		if err := roster.Update(ctx, hp.backend, func(r *roster.Roster) error {
			if pe := r.ByName("ancan"); pe != nil {
				if dead {
					pe.Relay = "http://127.0.0.1:1"
				} else {
					pe.Relay = live
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	dead(true)
	// The pull from the dead relay fails the round's exit; the step still ran.
	code, out, _ := cmd(t, "serve", "--dir", p.hostDir, "--once")
	if code != 1 {
		t.Fatalf("serve under a dead relay exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "the relay did not take it") {
		t.Errorf("the send did not meet the dead relay:\n%s", out)
	}
	notice := sessionRecords(t, root, deliver.Inbox)
	b, ok := notice[noticeID(bare)]
	if !ok {
		t.Fatalf("no notice under a dead relay; serve said:\n%s", out)
	}
	if !strings.Contains(string(b), "The answer was answered") || !strings.Contains(string(b), "stays with the outbox") {
		t.Errorf("the notice's outcome text does not state the outbox promise:\n%s", b)
	}
	dead(false)
	if n := guestAnswers(t, p.guestDir); n != 0 {
		t.Fatalf("%d answers reached the sender through a dead relay", n)
	}

	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if n := guestAnswers(t, p.guestDir); n != 1 {
		t.Fatalf("%d answers after the relay came back, want 1", n)
	}
}

// The labels the answer lists come from the published card, not the live
// map: a row the map gained since the last card publish is not handed to a
// sender whose copy of the card predates it.
func TestServeUnlabeledLabelsFromPublishedCard(t *testing.T) {
	p, root := unlabeledFixture(t)

	b, err := os.ReadFile(filepath.Join(root, "peers", "seats.md"))
	if err != nil {
		t.Fatal(err)
	}
	row := "\n| ghost | [[" + uccSession + "/rosters/advisor-demo]] | text |\n"
	if err := os.WriteFile(filepath.Join(root, "peers", "seats.md"), append(b, []byte(row)...), 0o644); err != nil {
		t.Fatal(err)
	}

	sendOK(t, p.guestDir, "--kind", "text", "--text", "body of bare", "zt")
	_ = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	seen := ""
	for _, rec := range records(t, deliverDirOf(p.guestDir), deliver.Inbox) {
		fm, _, body := parseRecord(t, rec)
		if strings.Trim(fm["kind"], `"`) == "vnd."+p.hostParty+".unlabeled" {
			seen = body
		}
	}
	if seen == "" {
		t.Fatal("no answer to inspect")
	}
	if !strings.Contains(seen, "leader") {
		t.Errorf("the answer does not list the card's labels:\n%s", seen)
	}
	if strings.Contains(seen, "ghost") {
		t.Errorf("the answer lists a label the published card does not carry:\n%s", seen)
	}
}

// Two OS processes serve one shared state and one sessions root, racing on
// the same unlabeled messages: each refusal is answered once on the line and
// noticed once in the bound session, whichever host's commit wins, and both
// spools end empty (task peer-unlabeled-and-sa-doc-label: two serving hosts,
// one answer).
func TestTwoHostsServeUnlabeledAnswerOnce(t *testing.T) {
	for _, kind := range []string{"file", "pages"} {
		t.Run(kind, func(t *testing.T) {
			_, _, base := relaytest.Start(t, login)
			root := uccRoot(t)
			cfg := uccCfg(root)
			switch kind {
			case "file":
				cfg.State.Dir = filepath.Join(t.TempDir(), "shared-state")
			case "pages":
				ps := pagestest.New("state-0123456789abcdef", "zt:token")
				t.Cleanup(ps.Close)
				cfg.State = stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}
			}
			p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
			if err := os.WriteFile(filepath.Join(root, "peers", "parties.md"), []byte(
				"# peers/parties.md — sender binding\n\n| party | to |\n|---|---|\n| "+p.guestParty+" | [["+uccSession+"/rosters/advisor-demo]] |\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			var ids []string
			for i := 1; i <= 3; i++ {
				id, _ := sendOK(t, p.guestDir, "--kind", "text", "--text", fmt.Sprintf("bare %d", i), "zt")
				ids = append(ids, id)
			}
			hostB := secondHost(t, p.hostDir)
			a, b := startServeChild(t, p.hostDir), startServeChild(t, hostB)
			a.readUntil(t, "ready")
			b.readUntil(t, "ready")
			for _, c := range []*serveProc{a, b} {
				if _, err := io.WriteString(c.stdin, "go\n"); err != nil {
					t.Fatal(err)
				}
			}
			a.readUntil(t, "done")
			b.readUntil(t, "done")
			for _, c := range []*serveProc{a, b} {
				if err := c.cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			}
			if a.conflicts+b.conflicts < 1 {
				t.Errorf("no commit conflicted: the hosts did not race")
			}

			notice := sessionRecords(t, root, deliver.Inbox)
			for _, id := range ids {
				if _, ok := notice[noticeID(id)]; !ok {
					t.Errorf("no notice for %s in the bound session", id)
				}
				if bornAnywhere(t, root, id) {
					t.Errorf("%s was born under the root", id)
				}
			}
			if len(notice) != 3 || a.delivered+b.delivered != 3 {
				t.Errorf("%d notices, children delivered %d+%d, want 3 and 3", len(notice), a.delivered, b.delivered)
			}
			for _, d := range []string{p.hostDir, hostB} {
				j, err := store.OpenJournal(filepath.Join(d, spoolDir))
				if err != nil {
					t.Fatal(err)
				}
				if es, _ := j.Entries(); len(es) != 0 {
					t.Errorf("%s: spool holds %+v", d, es)
				}
			}

			_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
			if n := guestAnswers(t, p.guestDir); n != 3 {
				t.Errorf("%d answers on the sender's side, want 3 — one per refused message", n)
			}
		})
	}
}

// A row whose accepts carry doc and file (label sa on ZT's party, R739) takes
// documents: the published card lists the kinds, a doc addressed to the label
// lands as the quarantine record beside its session's inbox with the content
// host-local in <deliver>/quarantine/<id>/<name>, and a doc that names no agent
// is answered with that label among those it may address.
func TestServeDocToRowAcceptingDocs(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	root := uccRoot(t)
	mapPath := filepath.Join(root, "peers", "seats.md")
	b, err := os.ReadFile(mapPath)
	if err != nil {
		t.Fatal(err)
	}
	row := "| sa     | [[" + uccSession + "/rosters/advisor-demo]] | text task question answer doc file ack |\n"
	if err := os.WriteFile(mapPath, append(b, []byte(row)...), 0o644); err != nil {
		t.Fatal(err)
	}
	p := handshake(t, newDir(t, uccCfg(root)), newDir(t, config{}), base)
	if err := os.WriteFile(filepath.Join(root, "peers", "parties.md"), []byte(
		"# peers/parties.md — sender binding\n\n| party | to |\n|---|---|\n| "+p.guestParty+" | [["+uccSession+"/rosters/advisor-demo]] |\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, gch, _ := channelOf(t, p.guestDir, "zt")
	pinned, err := card.Verify(gch.Card(), p.hostRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, a := range pinned.Agents {
		if a.ID == "sa" {
			listed = a.Accepts
		}
	}
	if !slices.Contains(listed, "doc") || !slices.Contains(listed, "file") {
		t.Fatalf("the sender's pinned card does not list doc and file for sa: %v", listed)
	}

	ids := map[string]string{}
	for _, k := range []struct{ name, kind, to string }{
		{"doc", "doc", "zt/sa"}, {"file", "file", "zt/sa"}, {"bare", "doc", "zt"},
	} {
		f := filepath.Join(t.TempDir(), k.name+".md")
		if err := os.WriteFile(f, []byte("body of "+k.name), 0o600); err != nil {
			t.Fatal(err)
		}
		ids[k.name], _ = sendOK(t, p.guestDir, "--kind", k.kind, "--file", f, k.to)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")

	q := sessionRecords(t, root, deliver.Quarantine)
	for _, n := range []string{"doc", "file"} {
		rec, ok := q[ids[n]]
		if !ok {
			t.Errorf("%s to sa is not in its session's quarantine; serve said:\n%s", n, out)
			continue
		}
		if fm, _, _ := parseRecord(t, rec); fm["to"] != p.hostParty+"/sa" {
			t.Errorf("%s record to %q, want %s/sa", n, fm["to"], p.hostParty)
		}
		got, _ := filepath.Glob(filepath.Join(deliverDirOf(p.hostDir), string(deliver.Quarantine), ids[n], "*"))
		if len(got) != 1 {
			t.Errorf("%s content: %v, want one file in <deliver>/quarantine/%s/", n, got, ids[n])
		} else if strings.HasPrefix(got[0], root) {
			t.Errorf("%s content landed under the sessions root: %s", n, got[0])
		}
	}
	if bornAnywhere(t, root, ids["bare"]) {
		t.Errorf("the unlabeled doc was born under the root")
	}

	_ = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	seen := ""
	for _, rec := range records(t, deliverDirOf(p.guestDir), deliver.Inbox) {
		fm, _, body := parseRecord(t, rec)
		if strings.Trim(fm["kind"], `"`) == "vnd."+p.hostParty+".unlabeled" {
			seen = body
		}
	}
	if !strings.Contains(seen, "your doc message was not delivered") || !strings.Contains(seen, "— sa —") {
		t.Errorf("the unlabeled doc's answer does not name sa as the label to address:\n%s", seen)
	}
}
