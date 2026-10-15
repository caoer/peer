package session_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

const login = "zt:owner-secret"

// party is one side: its keys, its signed card and its store on a file backend.
type party struct {
	root   *keys.Root
	id     *keys.Identity
	signed *card.Signed
	card   *card.Card
	store  *store.Store
}

func newParty(t *testing.T) *party {
	t.Helper()
	root, err := keys.GenerateRoot()
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.GenerateIdentity(root.Public())
	if err != nil {
		t.Fatal(err)
	}
	pk, err := keys.GeneratePartyKeys(id, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := file.New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	p := &party{root: root, id: id, store: store.New(b, id)}
	// The party keys record is seeded as the host does from init's file.
	ctx := context.Background()
	k, err := p.store.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	k.PartyKeys = pk
	if err := k.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	p.signed, err = card.Sign(card.New(id, pk, nil, nil, time.Now()), root)
	if err != nil {
		t.Fatal(err)
	}
	if p.card, err = card.Verify(p.signed, root.Public()); err != nil {
		t.Fatal(err)
	}
	return p
}

// open loads the party's channel and keys snapshots, as a fresh process would.
func (p *party) open(t *testing.T, channel string) *session.Session {
	t.Helper()
	ctx := context.Background()
	ch, err := p.store.Channel(ctx, channel)
	if err != nil {
		t.Fatal(err)
	}
	k, err := p.store.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return session.New(ch, k)
}

func commit(t *testing.T, s *session.Session) {
	t.Helper()
	ctx := context.Background()
	if err := s.Channel.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Keys.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func text(t *testing.T, from, to, body string) *session.Message {
	t.Helper()
	m, err := session.NewMessage(from, to, session.KindText, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func record(seq int64, e envelope.Envelope) relay.Record {
	return relay.Record{Seq: seq, At: time.Now(), Env: e}
}

func TestCode(t *testing.T) {
	a, b := newParty(t), newParty(t)
	const ch = "0123456789abcdef0123456789abcdef"
	s1, s2 := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	code := session.Code(ch, a.root.Public(), b.root.Public(), s1)
	if !regexp.MustCompile(`^[0-9]{8}$`).MatchString(code) {
		t.Fatalf("code %q is not 8 digits", code)
	}
	if code != session.Code(ch, a.root.Public(), b.root.Public(), s1) {
		t.Fatal("code is not a function of its inputs")
	}
	// The same pair on two invites: a new secret, a new channel, a new code.
	if code == session.Code(ch, a.root.Public(), b.root.Public(), s2) {
		t.Fatal("code ignores the link secret")
	}
	if code == session.Code("fedcba9876543210fedcba9876543210", a.root.Public(), b.root.Public(), s1) {
		t.Fatal("code ignores the channel")
	}
	if code == session.Code(ch, b.root.Public(), a.root.Public(), s1) {
		t.Fatal("code ignores who invited")
	}
	if code == session.Code(ch, a.root.Public(), newParty(t).root.Public(), s1) {
		t.Fatal("code ignores the invitee's root")
	}
	if !session.CodeMatches(code, code) || session.CodeMatches(code, "00000000") || session.CodeMatches(code[:7], code) {
		t.Fatal("CodeMatches")
	}
}

// The accept proof binds every input; CheckProof admits the exact proof and
// refuses an absent, malformed, mis-sized or different one.
func TestProof(t *testing.T) {
	a, b := newParty(t), newParty(t)
	const ch = "0123456789abcdef0123456789abcdef"
	secret := bytes.Repeat([]byte{7}, 16)
	ai, bi := a.id.PublicKey(), b.id.PublicKey()
	proof := session.Proof(secret, ch, a.root.Public(), b.root.Public(), ai, bi)
	if len(proof) != session.ProofSize {
		t.Fatalf("proof is %d bytes", len(proof))
	}
	if !bytes.Equal(proof, session.Proof(secret, ch, a.root.Public(), b.root.Public(), ai, bi)) {
		t.Fatal("proof is not a function of its inputs")
	}
	others := map[string][]byte{
		"secret":            session.Proof(bytes.Repeat([]byte{8}, 16), ch, a.root.Public(), b.root.Public(), ai, bi),
		"channel":           session.Proof(secret, "fedcba9876543210fedcba9876543210", a.root.Public(), b.root.Public(), ai, bi),
		"roots swapped":     session.Proof(secret, ch, b.root.Public(), a.root.Public(), ai, bi),
		"invitee root":      session.Proof(secret, ch, a.root.Public(), newParty(t).root.Public(), ai, bi),
		"identities":        session.Proof(secret, ch, a.root.Public(), b.root.Public(), bi, ai),
		"invitee identity":  session.Proof(secret, ch, a.root.Public(), b.root.Public(), ai, newParty(t).id.PublicKey()),
		"inviter identity":  session.Proof(secret, ch, a.root.Public(), b.root.Public(), newParty(t).id.PublicKey(), bi),
		"secret and inputs": session.Proof(nil, ch, a.root.Public(), b.root.Public(), ai, bi),
	}
	for name, other := range others {
		if bytes.Equal(proof, other) {
			t.Errorf("proof ignores %s", name)
		}
	}
	m := &session.Message{Proof: session.EncodeProof(proof)}
	if err := session.CheckProof(m, proof); err != nil {
		t.Fatalf("exact proof: %v", err)
	}
	bad := map[string]string{
		"absent":       "",
		"other":        session.EncodeProof(others["secret"]),
		"31 bytes":     session.EncodeProof(proof[:31]),
		"33 bytes":     session.EncodeProof(append(append([]byte(nil), proof...), 0)),
		"padded":       session.EncodeProof(proof) + "=",
		"std alphabet": "+" + session.EncodeProof(proof)[1:],
		"not base64":   "!" + session.EncodeProof(proof)[1:],
	}
	for name, p := range bad {
		if err := session.CheckProof(&session.Message{Proof: p}, proof); !errors.Is(err, session.ErrProof) {
			t.Errorf("%s: %v, want ErrProof", name, err)
		}
	}
	// The field survives the message round trip and is absent when empty.
	msg, _ := session.NewMessage("a", "b", session.KindCard, []byte("x"))
	b1, _ := msg.Marshal()
	if strings.Contains(string(b1), `"proof"`) {
		t.Fatal("empty proof is written")
	}
	msg.Proof = session.EncodeProof(proof)
	b2, _ := msg.Marshal()
	got, err := session.UnmarshalMessage(b2)
	if err != nil || got.Proof != msg.Proof {
		t.Fatalf("proof round trip: %q %v", got.Proof, err)
	}
}

// X3DH from the card, a message each way, every step from a fresh load;
// the first-contact check; duplicates and replays refused.
func TestEstablishAndExchange(t *testing.T) {
	ctx := context.Background()
	host, guest := newParty(t), newParty(t)
	const ch = "c1"

	// The host deposits one-time prekeys; the guest takes the first.
	hs := host.open(t, ch)
	pks, err := session.NewPrekeys(ctx, hs.Keys, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pks) != 3 || pks[0].ID != 3 || hs.Keys.PartyKeys.NextPrekeyID != 6 {
		t.Fatalf("prekeys %+v, next %d", pks, hs.Keys.PartyKeys.NextPrekeyID)
	}
	commit(t, hs)

	// Establish wants the card pinned first; with it, X3DH against the card's key.
	gs := guest.open(t, ch)
	key, err := session.CurrentKey(host.card)
	if err != nil {
		t.Fatal(err)
	}
	if err := gs.Establish(ctx, key, &pks[0]); !errors.Is(err, session.ErrNoCard) {
		t.Fatalf("establish without a pinned card: %v", err)
	}
	gs.Channel.PinRoot(host.root.Public())
	gs.Channel.PinCard(host.signed)
	if err := gs.Establish(ctx, key, &pks[0]); err != nil {
		t.Fatal(err)
	}
	m1 := text(t, "guest", "host", "hello host")
	e1, err := gs.Encrypt(ctx, m1)
	if err != nil {
		t.Fatal(err)
	}
	if e1.Type != envelope.Prekey {
		t.Fatalf("first message type %s, want prekey", e1.Type)
	}
	commit(t, gs)

	// The host receives from a fresh load, checks the first contact, pins.
	hs = host.open(t, ch)
	got, err := hs.Receive(ctx, record(0, e1))
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "hello host" || got.ID != m1.ID || got.Kind != session.KindText {
		t.Fatalf("received %+v", got)
	}
	if err := hs.CheckIdentity(guest.card); err != nil {
		t.Fatalf("first contact against the guest's card: %v", err)
	}
	if err := hs.CheckIdentity(newParty(t).card); !errors.Is(err, session.ErrIdentity) {
		t.Fatalf("first contact against another card: %v, want ErrIdentity", err)
	}
	if ok, _ := hs.Keys.ContainsPreKey(ctx, pks[0].ID); ok {
		t.Fatal("used one-time prekey still held")
	}
	if hs.Channel.Cursor() != 0 || !hs.Channel.Seen(m1.ID) {
		t.Fatalf("cursor %d seen %v", hs.Channel.Cursor(), hs.Channel.Seen(m1.ID))
	}
	hs.Channel.PinRoot(guest.root.Public())
	hs.Channel.PinCard(guest.signed)
	commit(t, hs)

	// The same record again is a duplicate by cursor; under a new seq the ratchet refuses it.
	hs = host.open(t, ch)
	if _, err := hs.Receive(ctx, record(0, e1)); !errors.Is(err, session.ErrDuplicate) {
		t.Fatalf("record at the cursor: %v, want ErrDuplicate", err)
	}
	if _, err := hs.Receive(ctx, record(7, e1)); err == nil || errors.Is(err, session.ErrDuplicate) {
		t.Fatalf("replayed ciphertext under a new seq: %v, want a decrypt error", err)
	}

	// The host replies; the guest reads it from a fresh load and answers with a normal message.
	hs = host.open(t, ch)
	r1 := text(t, "host", "guest", "hi guest")
	er1, err := hs.Encrypt(ctx, r1)
	if err != nil {
		t.Fatal(err)
	}
	commit(t, hs)
	gs = guest.open(t, ch)
	got, err = gs.Receive(ctx, record(0, er1))
	if err != nil || string(got.Body) != "hi guest" {
		t.Fatalf("guest receive: %+v %v", got, err)
	}
	e2, err := gs.Encrypt(ctx, text(t, "guest", "host", "again"))
	if err != nil {
		t.Fatal(err)
	}
	if e2.Type != envelope.Msg {
		t.Fatalf("message after the reply has type %s, want msg", e2.Type)
	}
	commit(t, gs)
	hs = host.open(t, ch)
	if got, err := hs.Receive(ctx, record(1, e2)); err != nil || string(got.Body) != "again" {
		t.Fatalf("host receive: %+v %v", got, err)
	}

	// Not a message, malformed, and a relay error never reach the library.
	hs = host.open(t, ch)
	cardEnv, _ := envelope.PackCard(guest.signed.Body, guest.signed.Sig)
	if _, err := hs.Receive(ctx, record(9, cardEnv)); !errors.Is(err, session.ErrNotMessage) {
		t.Fatalf("card envelope: %v, want ErrNotMessage", err)
	}
	if _, err := hs.Receive(ctx, record(9, envelope.Envelope{Type: envelope.Msg, Body: []byte{0x33, 0x0a, 0}})); err == nil {
		t.Fatal("malformed message accepted")
	}
	bad := record(9, envelope.Envelope{})
	bad.Err = errors.New("relay bytes")
	if _, err := hs.Receive(ctx, bad); err == nil || err.Error() != "relay bytes" {
		t.Fatalf("record with Err: %v", err)
	}
}

// Decision 5's send order through a relay: the commit lands before the
// put; a conflicting commit drops the ciphertext and puts nothing; a put
// that fails after the commit leaves the committed entry in the outbox.
func TestSendOrder(t *testing.T) {
	ctx := context.Background()
	srv, rc, _ := relaytest.Start(t, login)
	host, guest := newParty(t), newParty(t)
	chn, err := rc.Create(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	guestToken, err := rc.Join(ctx, chn.ID, chn.InviteToken)
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := store.OpenJournal(filepath.Join(t.TempDir(), "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	entries := func() int {
		es, err := outbox.Entries()
		if err != nil {
			t.Fatal(err)
		}
		return len(es)
	}

	gs := guest.open(t, chn.ID)
	gs.Channel.PinRoot(host.root.Public())
	gs.Channel.PinCard(host.signed)
	key, _ := session.CurrentKey(host.card)
	if err := gs.Establish(ctx, key, nil); err != nil {
		t.Fatal(err)
	}
	// Two loads of the same version: the second Send conflicts and puts nothing.
	gs2 := guest.open(t, chn.ID)
	gs2.Channel.PinRoot(host.root.Public())
	gs2.Channel.PinCard(host.signed)
	if err := gs2.Establish(ctx, key, nil); err != nil {
		t.Fatal(err)
	}
	r, err := gs.Send(ctx, outbox, rc, guestToken, text(t, "g", "h", "one"))
	if err != nil || r.Dir != "g2h" || r.Seq != 0 {
		t.Fatalf("send: %+v %v", r, err)
	}
	if _, err := gs2.Send(ctx, outbox, rc, guestToken, text(t, "g", "h", "two")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("conflicting send: %v, want ErrConflict", err)
	}
	if n := len(srv.Envelopes(chn.ID, "g2h")); n != 1 {
		t.Fatalf("%d envelopes on the relay, want 1", n)
	}
	if entries() != 0 {
		t.Fatal("an outbox entry survived")
	}

	// A put refused after the commit: the entry stays, marked committed, and the state advanced.
	gs = guest.open(t, chn.ID)
	v := gs.Channel.Version()
	_, err = gs.Send(ctx, outbox, rc, chn.InviteToken /* not a side token */, text(t, "g", "h", "three"))
	var pe *session.PutError
	if !errors.As(err, &pe) || !errors.Is(err, relay.ErrBadToken) || pe.Entry == nil {
		t.Fatalf("put failure: %v", err)
	}
	es, _ := outbox.Entries()
	if len(es) != 1 || !es[0].Committed || es[0].Channel != chn.ID || es[0].Type != "prekey" {
		t.Fatalf("outbox after put failure: %+v", es)
	}
	if gs.Channel.Version() != v+1 {
		t.Fatalf("version %d after the commit, want %d", gs.Channel.Version(), v+1)
	}
	// The replay puts it with the right token.
	err = store.ReplayOutbox(outbox, func(e *store.Entry) error {
		typ, err := envelope.ParseType(e.Type)
		if err != nil {
			return err
		}
		_, err = rc.Put(ctx, e.Channel, guestToken, envelope.Envelope{Type: typ, Body: e.Body})
		return err
	})
	if err != nil || entries() != 0 || len(srv.Envelopes(chn.ID, "g2h")) != 2 {
		t.Fatalf("replay: %v, %d entries, %d envelopes", err, entries(), len(srv.Envelopes(chn.ID, "g2h")))
	}
}

// The first-contact check reads the card's keys[].until: a session built
// under a key the card has retired is not the party's, and the key in force
// on the same card still is.
func TestCheckIdentitySkipsARetiredKey(t *testing.T) {
	ctx := context.Background()
	p := newParty(t)
	oldID, err := keys.GenerateIdentity(p.root.Public())
	if err != nil {
		t.Fatal(err)
	}
	oldPK, err := keys.GeneratePartyKeys(oldID, 1)
	if err != nil {
		t.Fatal(err)
	}
	newPK, err := keys.GeneratePartyKeys(p.id, 1)
	if err != nil {
		t.Fatal(err)
	}
	rotated := card.New(p.id, newPK, nil, nil, time.Now())
	void := time.Now().Add(-time.Hour)
	retired := card.New(oldID, oldPK, nil, nil, time.Now().Add(-2*time.Hour)).Keys[0]
	retired.Until = &void
	rotated.Keys = append([]card.Key{retired}, rotated.Keys...)
	signed, err := card.Sign(rotated, p.root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := card.Verify(signed, p.root.Public())
	if err != nil {
		t.Fatal(err)
	}

	s := p.open(t, "c1")
	if err := s.Channel.SaveIdentity(ctx, session.Addr, oldID.KeyPair.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckIdentity(c); !errors.Is(err, session.ErrIdentity) {
		t.Errorf("a session under the retired key: %v, want ErrIdentity", err)
	}
	if err := s.Channel.SaveIdentity(ctx, session.Addr, p.id.KeyPair.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckIdentity(c); err != nil {
		t.Errorf("a session under the key in force: %v", err)
	}
	cur, err := session.CurrentKey(c)
	if err != nil || cur.Identity != keys.CurveText(p.id.PublicKey()) {
		t.Fatalf("CurrentKey took %+v, want the bundle in force (%v)", cur, err)
	}
}

func TestMessageFormat(t *testing.T) {
	m, err := session.NewMessage("ed25519:a/advisor", "ed25519:b/legal", session.KindTask, []byte("do it"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := session.UnmarshalMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != m.ID || got.From != m.From || got.To != m.To || got.Kind != m.Kind || !got.At.Equal(m.At) || string(got.Body) != "do it" {
		t.Fatalf("round trip %+v, want %+v", got, m)
	}
	if _, err := session.NewMessage("a", "b", "x-custom", nil); !errors.Is(err, session.ErrKind) {
		t.Fatalf("x- kind: %v", err)
	}
	// A vendor kind is vnd.<party id>.<name>: the shape a delivery record can
	// carry. A shorter vendor label, or one with a character the record's
	// frontmatter line cannot hold, is not a kind.
	party := keys.PartyID(newParty(t).root.Public())
	if _, err := session.NewMessage("a", "b", "vnd."+party+".ping", nil); err != nil {
		t.Fatalf("vendor kind: %v", err)
	}
	for _, bad := range []string{"vnd.zt.ping", "vnd." + party + ".do thing", "vnd." + party, "vnd."} {
		if _, err := session.NewMessage("a", "b", bad, nil); !errors.Is(err, session.ErrKind) {
			t.Errorf("kind %q: %v, want ErrKind", bad, err)
		}
	}
	if _, err := session.UnmarshalMessage([]byte(`{"v":1,"kind":"text"}`)); err == nil {
		t.Fatal("message without id accepted")
	}
	big, _ := session.NewMessage("a", "b", session.KindFile, make([]byte, envelope.MaxBody))
	if _, err := big.Marshal(); !errors.Is(err, envelope.ErrTooLarge) {
		t.Fatalf("oversized message: %v", err)
	}
}
