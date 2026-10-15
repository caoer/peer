package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
