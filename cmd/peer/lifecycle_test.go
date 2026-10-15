package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.mau.fi/libsignal/state/record"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

func writeConfig(t *testing.T, dir string, cfg config) {
	t.Helper()
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, configFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// hostKeyOf is the host's current card key as the guest holds it pinned.
func hostKeyOf(t *testing.T, ch *store.Channel, hostRoot *keys.Root) *card.Key {
	t.Helper()
	c, err := card.Verify(ch.Card(), hostRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.CurrentKey(c)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The host changes its details and publishes: the guest refreshes its pin
// without a prompt, the identity key unchanged; a card older than the pinned
// one is not applied; without root.json publish refuses with the rule.
func TestCardPublishRefreshesThePin(t *testing.T) {
	ctx := context.Background()
	srv, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)

	cfg := hostCfg()
	cfg.Details = json.RawMessage(`{"advisor":{"type":"claude-code","model":"fable"}}`)
	writeConfig(t, p.hostDir, cfg)
	out := mustOK(t, "card", "publish", "--dir", p.hostDir)
	if !strings.Contains(out, "card published to ancan (#") {
		t.Fatalf("card publish:\n%s", out)
	}
	out = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.Contains(out, "card from zt pinned") || strings.Contains(out, "waiting") {
		t.Fatalf("guest serve after publish:\n%s", out)
	}
	_, gch, _ := channelOf(t, p.guestDir, "zt")
	c, err := card.Verify(gch.Card(), p.hostRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Details) != string(cfg.Details) {
		t.Fatalf("guest pinned details %s", c.Details)
	}
	if got, ok := gch.RemoteIdentity(session.Addr); !ok || keys.CurveText(got) != c.Keys[0].Identity {
		t.Fatal("the refreshed card does not name the session's identity key")
	}
	if held, _ := gch.Held(); held != nil {
		t.Fatal("a refresh held a card for the human")
	}
	refreshed := gch.Card().Body

	// An older card than the pinned one: refused, consumed, the pin unchanged.
	hp, hch, hpe := channelOf(t, p.hostDir, "ancan")
	hk, _ := hp.store.Keys(ctx)
	_, old, err := hp.buildOwnCard(hp.id, hk.PartyKeys, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	om, _ := session.CardMessage(p.hostParty, p.guestParty, old)
	rcpt, err := session.New(hch, hk).Send(ctx, hp.outbox, rc, hpe.Token, om)
	if err != nil {
		t.Fatal(err)
	}
	out = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.Contains(out, "older than the pinned one") {
		t.Fatalf("guest serve on an older card:\n%s", out)
	}
	_, gch, _ = channelOf(t, p.guestDir, "zt")
	if !bytes.Equal(gch.Card().Body, refreshed) || gch.Cursor() != rcpt.Seq {
		t.Fatalf("older card: pin changed or cursor %d not past #%d", gch.Cursor(), rcpt.Seq)
	}
	if rows := srv.Envelopes(p.channel, "h2g"); len(rows) != 4 {
		t.Fatalf("relay h2g holds %d rows, want card, details, publish, old card", len(rows))
	}

	if err := os.Remove(filepath.Join(p.hostDir, rootFile)); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, rootFile+" is not in", "card", "publish", "--dir", p.hostDir)
}

// rotated is the guest after an identity change (design §3.2): a new
// identity key and signed prekey, the one-time prekeys it already holds, a
// card signed by its root that retires the old key now and names the new
// one, and its own copy of the channel with the host's card pinned.
type rotated struct {
	id       *keys.Identity
	k        *store.Keys
	ch       *store.Channel
	sess     *session.Session
	card     *card.Signed
	identity string
	outbox   *store.Journal
	token    string
}

func rotateGuest(t *testing.T, ctx context.Context, p *pair) *rotated {
	t.Helper()
	gp, gch, gpe := channelOf(t, p.guestDir, "zt")
	gk, err := gp.store.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	newID, err := keys.GenerateIdentity(p.guestRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	newPK, err := keys.GeneratePartyKeys(newID, 0)
	if err != nil {
		t.Fatal(err)
	}
	newPK.Prekeys, newPK.NextPrekeyID = gk.PartyKeys.Prekeys, gk.PartyKeys.NextPrekeyID
	now := time.Now()
	c := card.New(newID, newPK, nil, nil, now)
	old := card.New(gp.id, gk.PartyKeys, nil, nil, now).Keys[0]
	old.Until = &now
	c.Keys = append([]card.Key{old}, c.Keys...)
	signed, err := card.Sign(c, p.guestRoot)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := file.New(filepath.Join(t.TempDir(), "guest-rotated"))
	if err != nil {
		t.Fatal(err)
	}
	s2 := store.New(b2, newID)
	ch2, err := s2.Channel(ctx, p.channel)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := s2.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	k2.PartyKeys = newPK
	ch2.PinRoot(p.hostRoot.Public())
	ch2.PinCard(gch.Card())
	outbox, err := store.OpenJournal(filepath.Join(t.TempDir(), "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	return &rotated{id: newID, k: k2, ch: ch2, sess: session.New(ch2, k2), card: signed,
		identity: keys.CurveText(newID.PublicKey()), outbox: outbox, token: gpe.Token}
}

// establish opens the rotated guest's session from the host's card and one
// of the host's one-time prekeys (the symmetric prekey route, design §6.1).
func (r *rotated) establish(t *testing.T, ctx context.Context, rc *relay.Client, p *pair) {
	t.Helper()
	var opk *relay.Prekey
	if k, ok, err := rc.TakePrekey(ctx, p.channel, r.token); err != nil {
		t.Fatal(err)
	} else if ok {
		opk = &k
	}
	if err := r.sess.Establish(ctx, hostKeyOf(t, r.ch, p.hostRoot), opk); err != nil {
		t.Fatal(err)
	}
}

// put encrypts m in the rotated session and puts it on the channel.
func (r *rotated) put(t *testing.T, ctx context.Context, rc *relay.Client, p *pair, m *session.Message) relay.Receipt {
	t.Helper()
	e, err := r.sess.Encrypt(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	rcpt, err := rc.Put(ctx, p.channel, r.token, e)
	if err != nil {
		t.Fatal(err)
	}
	return rcpt
}

// keyChangeOnRelay is a confirmed pair after one message, with the guest's
// new card and a text under its new identity key on the relay.
func keyChangeOnRelay(t *testing.T, ctx context.Context, rc *relay.Client, base string) (*pair, *rotated, relay.Receipt, string, relay.Receipt) {
	t.Helper()
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	before, _ := sendOK(t, p.guestDir, "--text", "before the change", "zt/advisor")
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+before) {
		t.Fatalf("host serve before the change:\n%s", out)
	}
	rg := rotateGuest(t, ctx, p)
	rg.establish(t, ctx, rc, p)
	cm, _ := session.CardMessage(p.guestParty, p.hostParty, rg.card)
	cardRcpt := rg.put(t, ctx, rc, p, cm)
	tm, _ := session.NewMessage(p.guestParty+"/legal", p.hostParty+"/advisor", session.KindText, []byte("after the change"))
	textRcpt := rg.put(t, ctx, rc, p, tm)
	return p, rg, cardRcpt, tm.ID, textRcpt
}

// The plan's verify — 换身份密钥后旧会话作废、新会话接上: the guest's new card
// under its new identity key is held and the channel waits, every round;
// peer keys accept pins it and drops the old session; serve then builds the
// session from the record it waited at, delivers what followed, and a message
// under the old key — the old session's, or a new session under the retired
// key — is refused.
func TestKeyChangeHeldAcceptedAndRebuilt(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p, rg, cardRcpt, textID, _ := keyChangeOnRelay(t, ctx, rc, base)

	for i := 1; i <= 2; i++ {
		out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
		want := []string{"ancan: waiting at #" + itoa(cardRcpt.Seq), rg.identity, "peer keys accept ancan"}
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Fatalf("serve %d does not say %q:\n%s", i, w, out)
			}
		}
		_, hch, _ := channelOf(t, p.hostDir, "ancan")
		held, seq := hch.Held()
		if held == nil || seq != cardRcpt.Seq || !bytes.Equal(held.Body, rg.card.Body) {
			t.Fatalf("serve %d: held %v at #%d, want the new card at #%d", i, held != nil, seq, cardRcpt.Seq)
		}
		if hch.Cursor() >= cardRcpt.Seq {
			t.Fatalf("serve %d consumed the record the channel waits at: cursor %d", i, hch.Cursor())
		}
	}
	if n := len(records(t, deliverDirOf(p.hostDir), deliver.Inbox)); n != 1 {
		t.Fatalf("inbox holds %d records while the channel waits, want the one from before", n)
	}

	out := mustOK(t, "keys", "accept", "--dir", p.hostDir, "ancan")
	if !strings.Contains(out, "accepted ancan's new identity key "+rg.identity) || !strings.Contains(out, "their new session is on the relay (#"+itoa(cardRcpt.Seq)+")") {
		t.Fatalf("keys accept:\n%s", out)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if held, _ := hch.Held(); held != nil {
		t.Fatal("the held card stays after accept")
	}
	if !bytes.Equal(hch.Card().Body, rg.card.Body) {
		t.Fatal("accept did not pin the new card")
	}
	if has, _ := hch.ContainsSession(ctx, session.Addr); has {
		t.Fatal("the old session survives accept")
	}

	// 新会话接上: serve builds the session from the waiting record and
	// delivers the text behind it.
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "card from ancan pinned") || !strings.Contains(out, "delivered text "+textID) {
		t.Fatalf("host serve after accept:\n%s", out)
	}
	_, hch, _ = channelOf(t, p.hostDir, "ancan")
	if got, ok := hch.RemoteIdentity(session.Addr); !ok || keys.CurveText(got) != rg.identity {
		t.Fatal("the session is not under the new identity key")
	}

	// 旧会话作废: the old guest's send does not open here.
	old, _ := sendOK(t, p.guestDir, "--text", "from the old session", "zt/advisor")
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "skip ancan #") || strings.Contains(out, "delivered text "+old) {
		t.Fatalf("host serve on the old session's message:\n%s", out)
	}
	// A new session under the retired key is refused too.
	gp, gch, gpe := channelOf(t, p.guestDir, "zt")
	gk, _ := gp.store.Keys(ctx)
	gs := session.New(gch, gk)
	opk, _, _ := rc.TakePrekey(ctx, p.channel, gpe.Token)
	if err := gs.Establish(ctx, hostKeyOf(t, gch, p.hostRoot), &opk); err != nil {
		t.Fatal(err)
	}
	retired, _ := session.NewMessage(p.guestParty, p.hostParty, session.KindText, []byte("under the retired key"))
	if _, err := gs.Send(ctx, gp.outbox, rc, gpe.Token, retired); err != nil {
		t.Fatal(err)
	}
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "a text under an identity key the card does not list") || !strings.Contains(out, "refused") {
		t.Fatalf("host serve on a session under the retired key:\n%s", out)
	}
	in := records(t, deliverDirOf(p.hostDir), deliver.Inbox)
	if _, ok := in[textID]; !ok || len(in) != 2 {
		t.Fatalf("inbox holds %d records, the one after the change present: %v", len(in), ok)
	}

	// Host → guest flows on the new session.
	id, _ := sendOK(t, p.hostDir, "--text", "hello new key", "ancan")
	recs, err := rc.Pull(ctx, p.channel, rg.token, -1)
	if err != nil || len(recs) == 0 {
		t.Fatal(err)
	}
	m, err := rg.sess.Receive(ctx, recs[len(recs)-1])
	if err != nil || m.ID != id || string(m.Body) != "hello new key" {
		t.Fatalf("rotated guest receive: %+v %v", m, err)
	}
}

// peer keys reject discards the held card: the channel moves past the record
// it came in under, what followed under the new key is refused, the old
// session goes on, and nothing is held any more.
func TestKeyChangeRejected(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p, rg, cardRcpt, textID, textRcpt := keyChangeOnRelay(t, ctx, rc, base)

	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "waiting at #") {
		t.Fatalf("host serve:\n%s", out)
	}
	out := mustOK(t, "keys", "reject", "--dir", p.hostDir, "ancan")
	if !strings.Contains(out, "rejected ancan's new identity key "+rg.identity) {
		t.Fatalf("keys reject:\n%s", out)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if held, _ := hch.Held(); held != nil || hch.Cursor() != cardRcpt.Seq {
		t.Fatalf("after reject: held %v, cursor %d (want #%d)", held != nil, hch.Cursor(), cardRcpt.Seq)
	}
	pinned, _ := card.Verify(hch.Card(), p.guestRoot.Public())
	if got, _ := hch.RemoteIdentity(session.Addr); keys.CurveText(got) != pinned.Keys[0].Identity || pinned.Keys[0].Identity == rg.identity {
		t.Fatal("reject changed the pinned card or the session")
	}

	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "skip ancan #"+itoa(textRcpt.Seq)) || !strings.Contains(out, "refused") || strings.Contains(out, "delivered text "+textID) {
		t.Fatalf("host serve after reject:\n%s", out)
	}
	id, _ := sendOK(t, p.guestDir, "--text", "still on the old key", "zt/advisor")
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+id) {
		t.Fatalf("the old session after reject:\n%s", out)
	}
	mustRefuse(t, "nothing is held for ancan", "keys", "reject", "--dir", p.hostDir, "ancan")
	mustRefuse(t, "nothing is held for ancan", "keys", "accept", "--dir", p.hostDir, "ancan")
}

// A key change announced over the session in force: the card is held, the
// channel waits; accept finds no new session on the relay and builds one from
// the guest's prekey, sending this party's card in it, which the rotated guest
// reads; its reply on the new session is delivered.
func TestKeyChangeOverTheOldSession(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	rg := rotateGuest(t, ctx, p)

	gp, gch, gpe := channelOf(t, p.guestDir, "zt")
	gk, _ := gp.store.Keys(ctx)
	cm, _ := session.CardMessage(p.guestParty, p.hostParty, rg.card)
	rcpt, err := session.New(gch, gk).Send(ctx, gp.outbox, rc, gpe.Token, cm)
	if err != nil {
		t.Fatal(err)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "ancan: waiting at #"+itoa(rcpt.Seq)) || !strings.Contains(out, "peer keys accept ancan") {
		t.Fatalf("host serve on the card:\n%s", out)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if held, seq := hch.Held(); held == nil || seq != rcpt.Seq || hch.Cursor() != rcpt.Seq {
		t.Fatalf("held %v at #%d, cursor %d", held != nil, seq, hch.Cursor())
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "waiting at #") {
		t.Fatalf("second round not parked:\n%s", out)
	}

	out = mustOK(t, "keys", "accept", "--dir", p.hostDir, "ancan")
	if !strings.Contains(out, "a new one is built from their prekey") || !strings.Contains(out, "your card went out (#") {
		t.Fatalf("keys accept:\n%s", out)
	}
	_, hch, _ = channelOf(t, p.hostDir, "ancan")
	if has, _ := hch.ContainsSession(ctx, session.Addr); !has || !bytes.Equal(hch.Card().Body, rg.card.Body) {
		t.Fatal("accept left no session, or the new card unpinned")
	}

	// The rotated guest reads the host's card from the PreKey message and answers.
	recs, err := rc.Pull(ctx, p.channel, rg.token, -1)
	if err != nil || len(recs) == 0 {
		t.Fatal(err)
	}
	m, err := rg.sess.Receive(ctx, recs[len(recs)-1])
	if err != nil {
		t.Fatal(err)
	}
	hc, _, root, err := session.PeerCard(m)
	if err != nil || !bytes.Equal(root, p.hostRoot.Public()) || len(hc.Details) == 0 {
		t.Fatalf("host card in the new session: %v %v", hc, err)
	}
	reply, _ := session.NewMessage(p.guestParty, p.hostParty+"/advisor", session.KindText, []byte("on the new key"))
	if _, err := rg.sess.Send(ctx, rg.outbox, rc, rg.token, reply); err != nil {
		t.Fatal(err)
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+reply.ID) {
		t.Fatalf("host serve on the reply:\n%s", out)
	}
}

// A new identity key without the root's signature is refused: the record is
// consumed, nothing held, the channel goes on — and what follows under that
// key is refused too, since no card made it the peer's.
func TestKeyChangeWithoutRootSignatureIsRefused(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	rg := rotateGuest(t, ctx, p)
	rg.establish(t, ctx, rc, p)
	// The same card with a signature the root did not make.
	forged := &card.Signed{Body: rg.card.Body, Sig: append([]byte(nil), rg.card.Sig...)}
	forged.Sig[0] ^= 1
	cm, _ := session.CardMessage(p.guestParty, p.hostParty, forged)
	cardRcpt := rg.put(t, ctx, rc, p, cm)
	tm, _ := session.NewMessage(p.guestParty, p.hostParty, session.KindText, []byte("after a forged card"))
	textRcpt := rg.put(t, ctx, rc, p, tm)

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	for _, w := range []string{"skip ancan #" + itoa(cardRcpt.Seq), "refused", "skip ancan #" + itoa(textRcpt.Seq)} {
		if !strings.Contains(out, w) {
			t.Fatalf("host serve does not say %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "waiting") || strings.Contains(out, "delivered text "+tm.ID) {
		t.Fatalf("a forged card held or delivered:\n%s", out)
	}
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if held, _ := hch.Held(); held != nil || hch.Cursor() != textRcpt.Seq {
		t.Fatalf("held %v, cursor %d", held != nil, hch.Cursor())
	}
	id, _ := sendOK(t, p.guestDir, "--text", "the old session goes on", "zt/advisor")
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+id) {
		t.Fatalf("the old session after a refused change:\n%s", out)
	}
}

// After an accepted rotation, whoever still holds the retired key and can put
// on the channel (the peer's relay token, which rotation keeps, or the relay)
// plays the peer's older card back in a new session under that key. It does
// not supersede the pinned card, so serve refuses it with the reason and the
// channel goes on; peer keys accept refuses such a card too and peer keys
// reject discards it; the peer's own older card in the session in force is
// skipped the same way.
func TestRetiredKeyCannotRollBackThePinnedCard(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)

	// What the attacker holds: the guest's identity and card from before the
	// rotation.
	gp, _, gpe := channelOf(t, p.guestDir, "zt")
	oldID := gp.id
	oc, err := gp.store.OwnCard(ctx)
	if err != nil || !oc.Present() {
		t.Fatalf("guest card record: %v", err)
	}
	oldCard := oc.Details

	// The genuine rotation, accepted by the host's human.
	mustOK(t, "identity", "rotate", "--dir", p.guestDir, "--yes")
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "peer keys accept ancan") {
		t.Fatalf("host serve on the rotation:\n%s", out)
	}
	mustOK(t, "keys", "accept", "--dir", p.hostDir, "ancan")
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	pinned := hch.Card().Body

	// The attacker: the retired key, a session to the host's key, the old
	// card and a text behind it.
	ab, err := file.New(filepath.Join(t.TempDir(), "attacker"))
	if err != nil {
		t.Fatal(err)
	}
	as := store.New(ab, oldID)
	ach, _ := as.Channel(ctx, p.channel)
	ak, _ := as.Keys(ctx)
	if ak.PartyKeys, err = keys.GeneratePartyKeys(oldID, 1); err != nil {
		t.Fatal(err)
	}
	_, gch, _ := channelOf(t, p.guestDir, "zt")
	ach.PinRoot(p.hostRoot.Public())
	ach.PinCard(gch.Card())
	atk := &rotated{id: oldID, k: ak, ch: ach, sess: session.New(ach, ak), token: gpe.Token}
	atk.establish(t, ctx, rc, p)
	cm, _ := session.CardMessage(p.guestParty, p.hostParty, oldCard)
	cardRcpt := atk.put(t, ctx, rc, p, cm)
	tm, _ := session.NewMessage(p.guestParty+"/legal", p.hostParty+"/advisor", session.KindText, []byte("from the retired key"))
	textRcpt := atk.put(t, ctx, rc, p, tm)

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	for _, w := range []string{"skip ancan #" + itoa(cardRcpt.Seq) + ": a card under a new identity key that does not supersede the pinned one: it was issued", "skip ancan #" + itoa(textRcpt.Seq)} {
		if !strings.Contains(out, w) {
			t.Fatalf("host serve does not say %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "waiting at #") || strings.Contains(out, "delivered text "+tm.ID) {
		t.Fatalf("the old card held or the retired key's text delivered:\n%s", out)
	}
	_, hch, _ = channelOf(t, p.hostDir, "ancan")
	if held, _ := hch.Held(); held != nil || hch.Cursor() != textRcpt.Seq || !bytes.Equal(hch.Card().Body, pinned) {
		t.Fatalf("held %v, cursor %d (want #%d), pin unchanged %v", held != nil, hch.Cursor(), textRcpt.Seq, bytes.Equal(hch.Card().Body, pinned))
	}

	// The same card held on the channel: accept refuses it and changes
	// nothing, reject discards it.
	hch.Hold(oldCard, cardRcpt.Seq)
	if err := hch.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "the held card does not supersede the pinned one: it was issued", "keys", "accept", "--dir", p.hostDir, "ancan")
	_, hch, _ = channelOf(t, p.hostDir, "ancan")
	if !bytes.Equal(hch.Card().Body, pinned) {
		t.Fatal("a refused accept changed the pinned card")
	}
	mustOK(t, "keys", "reject", "--dir", p.hostDir, "ancan")

	// The guest's older card in the session in force: skipped, nothing held.
	gp, gch, gpe = channelOf(t, p.guestDir, "zt")
	var sink bytes.Buffer
	if err := gp.publish(ctx, *gpe, oldCard, gch.Announced(), &sink); err != nil {
		t.Fatal(err)
	}
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "a card naming a new identity key that does not supersede the pinned one") || strings.Contains(out, "waiting at #") {
		t.Fatalf("host serve on the guest's older card:\n%s", out)
	}

	// The channel goes on under the new key.
	id, _ := sendOK(t, p.guestDir, "--text", "on the new key", "zt/advisor")
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+id) {
		t.Fatalf("host serve after the refusals:\n%s", out)
	}
}

// A rotation card from a peer whose clock runs ahead of this host's gives the
// old key an until still in this host's future. It names another current key
// and gives the session's key an until, so it is a key change whatever the
// until says against this host's clock: serve holds it for the human, the
// pinned card stays as it was, and peer keys accept has it to apply.
func TestRotationUnderClockSkewIsHeld(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	gp, _, gpe := channelOf(t, p.guestDir, "zt")
	gk, _ := gp.store.Keys(ctx)
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	pinned := hch.Card().Body

	// What peer identity rotate builds and sends on a guest whose clock is an
	// hour ahead.
	skewNow := time.Now().Add(time.Hour)
	newID, err := keys.GenerateIdentity(gp.id.Party)
	if err != nil {
		t.Fatal(err)
	}
	newPK := &keys.PartyKeys{SignedPrekey: gk.PartyKeys.SignedPrekey, Prekeys: gk.PartyKeys.Prekeys, NextPrekeyID: gk.PartyKeys.NextPrekeyID}
	if err := newPK.RotateSignedPrekey(newID); err != nil {
		t.Fatal(err)
	}
	old := card.New(gp.id, gk.PartyKeys, nil, nil, skewNow).Keys[0]
	old.Until = &skewNow
	_, details, err := gp.buildOwnCard(newID, newPK, skewNow, old)
	if err != nil {
		t.Fatal(err)
	}
	var sink bytes.Buffer
	if err := gp.publish(ctx, *gpe, details, newPK.SignedPrekey.ID(), &sink); err != nil {
		t.Fatal(err)
	}

	newKey := keys.CurveText(newID.PublicKey())
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "ancan: waiting at #") || !strings.Contains(out, "names a new identity key "+newKey) || strings.Contains(out, "card from ancan pinned") {
		t.Fatalf("host serve on the skewed rotation card:\n%s", out)
	}
	_, hch, _ = channelOf(t, p.hostDir, "ancan")
	if held, _ := hch.Held(); held == nil || !bytes.Equal(held.Body, details.Body) || !bytes.Equal(hch.Card().Body, pinned) {
		t.Fatalf("held %v, pin unchanged %v", held != nil, bytes.Equal(hch.Card().Body, pinned))
	}
	if out := mustOK(t, "keys", "accept", "--dir", p.hostDir, "ancan"); !strings.Contains(out, "accepted ancan's new identity key "+newKey) {
		t.Fatalf("keys accept:\n%s", out)
	}
}

// ageSignedPrekey makes the party's current signed prekey look age old.
func ageSignedPrekey(t *testing.T, ctx context.Context, dir string, age time.Duration) {
	t.Helper()
	p, err := openParty(dir)
	if err != nil {
		t.Fatal(err)
	}
	k, err := p.keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	spk := k.PartyKeys.SignedPrekey
	k.PartyKeys.SignedPrekey = record.NewSignedPreKey(spk.ID(), time.Now().Add(-age).Unix(), spk.KeyPair(), spk.Signature(), keys.Serializer.SignedPreKeyRecord)
	if err := k.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// serve rotates a signed prekey past its interval and republishes the card;
// not again before the next interval; a session a peer built from the card
// that announced the old key still opens; without root.json serve says where
// to rotate and peer card publish does it.
func TestSignedPrekeyRotation(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	ageSignedPrekey(t, ctx, p.hostDir, 31*24*time.Hour)

	// The guest opens a session from the card it holds (signed prekey 1) and
	// holds its first message back until after the rotation.
	gp, gch, gpe := channelOf(t, p.guestDir, "zt")
	gk, _ := gp.store.Keys(ctx)
	gs := session.New(gch, gk)
	opk, _, _ := rc.TakePrekey(ctx, p.channel, gpe.Token)
	if err := gs.Establish(ctx, hostKeyOf(t, gch, p.hostRoot), &opk); err != nil {
		t.Fatal(err)
	}
	pending, _ := session.NewMessage(p.guestParty, p.hostParty, session.KindText, []byte("built from signed prekey 1"))
	penv, err := gs.Encrypt(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := gch.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "signed prekey rotated: 1 → 2") || !strings.Contains(out, "card published to ancan (#") {
		t.Fatalf("host serve with a stale signed prekey:\n%s", out)
	}
	hp, _, _ := channelOf(t, p.hostDir, "ancan")
	hk, _ := hp.store.Keys(ctx)
	if hk.PartyKeys.SignedPrekey.ID() != 2 || hk.PartyKeys.PreviousSignedPrekey == nil || hk.PartyKeys.PreviousSignedPrekey.ID() != 1 {
		t.Fatalf("after rotation: current %d, previous %v", hk.PartyKeys.SignedPrekey.ID(), hk.PartyKeys.PreviousSignedPrekey)
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); strings.Contains(out, "rotated") || strings.Contains(out, "published") {
		t.Fatalf("a fresh signed prekey rotated again:\n%s", out)
	}
	out = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.Contains(out, "card from zt pinned") {
		t.Fatalf("guest serve after the rotation:\n%s", out)
	}
	_, gch, _ = channelOf(t, p.guestDir, "zt")
	if key := hostKeyOf(t, gch, p.hostRoot); key.SignedPrekey.ID != 2 {
		t.Fatalf("guest holds signed prekey %d, want 2", key.SignedPrekey.ID)
	}
	if _, err := rc.Put(ctx, p.channel, gpe.Token, penv); err != nil {
		t.Fatal(err)
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+pending.ID) {
		t.Fatalf("a session from the previous signed prekey does not open:\n%s", out)
	}

	// Without the root the host cannot announce a new key: it says so and
	// leaves the keys alone; card publish, where the root is, rotates.
	ageSignedPrekey(t, ctx, p.hostDir, 31*24*time.Hour)
	rootBytes, err := os.ReadFile(filepath.Join(p.hostDir, rootFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(p.hostDir, rootFile)); err != nil {
		t.Fatal(err)
	}
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "run peer card publish where root.json is") || strings.Contains(out, "rotated") {
		t.Fatalf("host serve without root:\n%s", out)
	}
	hp, _, _ = channelOf(t, p.hostDir, "ancan")
	if hk, _ = hp.store.Keys(ctx); hk.PartyKeys.SignedPrekey.ID() != 2 {
		t.Fatalf("a host without root rotated to %d", hk.PartyKeys.SignedPrekey.ID())
	}
	if err := os.WriteFile(filepath.Join(p.hostDir, rootFile), rootBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	out = mustOK(t, "card", "publish", "--dir", p.hostDir)
	if !strings.Contains(out, "signed prekey rotated: 2 → 3") || !strings.Contains(out, "card published to ancan (#") {
		t.Fatalf("card publish with a stale signed prekey:\n%s", out)
	}
}

// serve restocks a channel's one-time prekeys when the count falls below
// keys.oneTimeMin, up to the channel's ten, and not otherwise.
func TestRestockOneTimePrekeys(t *testing.T) {
	ctx := context.Background()
	srv, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	if hch.Deposited() != prekeysPerChannel-1 || srv.Prekeys(p.channel, "h2g") != prekeysPerChannel-1 {
		t.Fatalf("after the handshake the host counts %d deposited, the relay holds %d", hch.Deposited(), srv.Prekeys(p.channel, "h2g"))
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); strings.Contains(out, "deposited") {
		t.Fatalf("a full channel restocked:\n%s", out)
	}

	// The guest rebuilds its session five times, a one-time prekey each.
	var ids []string
	for i := 0; i < 5; i++ {
		gp, gch, gpe := channelOf(t, p.guestDir, "zt")
		gk, _ := gp.store.Keys(ctx)
		gs := session.New(gch, gk)
		opk, ok, err := rc.TakePrekey(ctx, p.channel, gpe.Token)
		if err != nil || !ok {
			t.Fatalf("take %d: %v %v", i, ok, err)
		}
		if err := gs.Establish(ctx, hostKeyOf(t, gch, p.hostRoot), &opk); err != nil {
			t.Fatal(err)
		}
		m, _ := session.NewMessage(p.guestParty, p.hostParty, session.KindText, []byte("rebuilt"))
		if _, err := gs.Send(ctx, gp.outbox, rc, gpe.Token, m); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	if n := srv.Prekeys(p.channel, "h2g"); n != prekeysPerChannel-6 {
		t.Fatalf("relay holds %d host prekeys, want %d", n, prekeysPerChannel-6)
	}
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "ancan: deposited 6 one-time prekeys; the relay holds 10") {
		t.Fatalf("host serve with four prekeys left:\n%s", out)
	}
	for _, id := range ids {
		if !strings.Contains(out, "delivered text "+id) {
			t.Fatalf("message %s of a rebuilt session not delivered:\n%s", id, out)
		}
	}
	_, hch, _ = channelOf(t, p.hostDir, "ancan")
	if hch.Deposited() != prekeysPerChannel || srv.Prekeys(p.channel, "h2g") != prekeysPerChannel {
		t.Fatalf("after restock the host counts %d, the relay holds %d", hch.Deposited(), srv.Prekeys(p.channel, "h2g"))
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); strings.Contains(out, "deposited") {
		t.Fatalf("a restocked channel restocked again:\n%s", out)
	}
	// The new private halves are in the record: a session from a restocked key opens.
	gp, gch, gpe := channelOf(t, p.guestDir, "zt")
	gk, _ := gp.store.Keys(ctx)
	gs := session.New(gch, gk)
	opk, _, _ := rc.TakePrekey(ctx, p.channel, gpe.Token)
	if err := gs.Establish(ctx, hostKeyOf(t, gch, p.hostRoot), &opk); err != nil {
		t.Fatal(err)
	}
	m, _ := session.NewMessage(p.guestParty, p.hostParty, session.KindText, []byte("from a restocked key"))
	if _, err := gs.Send(ctx, gp.outbox, rc, gpe.Token, m); err != nil {
		t.Fatal(err)
	}
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+m.ID) {
		t.Fatalf("a session from a restocked key:\n%s", out)
	}
}

// prekeyAnswers fronts the fake relay and answers the next prekey deposit as
// told: lost stores the keys and answers 502, as a gateway that lost the
// relay's answer does; refuse answers too_large and stores nothing.
type prekeyAnswers struct {
	proxy        http.Handler
	lost, refuse atomic.Bool
}

func (f *prekeyAnswers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/prekeys") {
		switch {
		case f.lost.CompareAndSwap(true, false):
			f.proxy.ServeHTTP(httptest.NewRecorder(), r)
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"gateway (test)","code":"down"}`))
			return
		case f.refuse.CompareAndSwap(true, false):
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			w.Write([]byte(`{"error":"a side holds at most 200 prekeys (test)","code":"too_large"}`))
			return
		}
	}
	f.proxy.ServeHTTP(w, r)
}

// A deposit the relay refuses stored nothing, and its keys leave the record.
// A deposit the relay stored and whose answer was lost keeps the private
// halves, and the next restock puts the same keys again instead of new ones:
// every key the relay hands out opens on this side.
func TestRestockKeepsKeysTheRelayMayHold(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	fr := &prekeyAnswers{proxy: httputil.NewSingleHostReverseProxy(target)}
	proxy := httptest.NewServer(fr)
	t.Cleanup(proxy.Close)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), proxy.URL+"/peer")

	// The host's count says the relay is low: every round restocks.
	hp, hch, _ := channelOf(t, p.hostDir, "ancan")
	hch.SetDeposited(0)
	if err := hch.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	held := srv.Prekeys(p.channel, "h2g")
	var out bytes.Buffer
	sv, err := openServer(p.hostDir, "", &out)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	nextID := func() uint32 {
		t.Helper()
		k, err := hp.keys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return k.PartyKeys.NextPrekeyID
	}

	first := nextID()
	fr.refuse.Store(true)
	if err := sv.round(ctx); err == nil || !strings.Contains(err.Error(), "too_large") {
		t.Fatalf("round with the deposit refused: %v", err)
	}
	k, err := hp.keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for id := first; id < first+prekeysPerChannel; id++ {
		if r, _ := k.LoadPreKey(ctx, id); r != nil {
			t.Errorf("prekey %d of the refused deposit stays in the record", id)
		}
	}

	lost := nextID()
	fr.lost.Store(true)
	if err := sv.round(ctx); err == nil || !strings.Contains(err.Error(), "restock:") {
		t.Fatalf("round with the deposit answer lost: %v", err)
	}
	if n := srv.Prekeys(p.channel, "h2g"); n != held+prekeysPerChannel {
		t.Fatalf("the relay holds %d host prekeys, want %d", n, held+prekeysPerChannel)
	}
	if k, err = hp.keys(ctx); err != nil {
		t.Fatal(err)
	}
	_, _, gpe := channelOf(t, p.guestDir, "zt")
	rc := relay.New(gpe.Relay, nil)
	for {
		pk, ok, err := rc.TakePrekey(ctx, p.channel, gpe.Token)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if r, _ := k.LoadPreKey(ctx, pk.ID); r == nil {
			t.Errorf("the relay hands out prekey %d and the host's keys record has no private half", pk.ID)
		}
	}

	// The relay answers again: the restock puts the same keys, not new ones,
	// and records the count the relay answers.
	if err := sv.round(ctx); err != nil {
		t.Fatalf("round with the relay answering: %v\n%s", err, out.String())
	}
	if next := nextID(); next != lost+prekeysPerChannel {
		t.Fatalf("next prekey id %d, want %d: the restock after the lost answer made new keys", next, lost+prekeysPerChannel)
	}
	if _, hch, _ := channelOf(t, p.hostDir, "ancan"); hch.Deposited() != srv.Prekeys(p.channel, "h2g") {
		t.Fatalf("the host counts %d deposited, the relay holds %d", hch.Deposited(), srv.Prekeys(p.channel, "h2g"))
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
