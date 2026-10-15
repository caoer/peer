package main

// The trust rules a relay could bend, each with the test that bites when the
// check is bypassed: card #0 is verified under the root the LINK pins (design
// §3.4, §4), and a key change arrives only on a card signed by the PINNED root
// and naming the key the record came under (design §3.2).

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/session"
)

// A relay that swaps in a card #0 validly signed by its own root is refused:
// the link's root is the one that counts, not the card's.
func TestAcceptRefusesCardZeroOfAnotherRoot(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	ch, err := rc.Create(ctx, login)
	if err != nil {
		t.Fatal(err)
	}
	mallory, _ := keys.GenerateRoot()
	mID, _ := keys.GenerateIdentity(mallory.Public())
	mPK, _ := keys.GeneratePartyKeys(mID, 1)
	mCard, err := card.Sign(card.New(mID, mPK, nil, nil, time.Now()), mallory)
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.PackCard(mCard.Body, mCard.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Put(ctx, ch.ID, ch.HostToken, env); err != nil {
		t.Fatal(err)
	}
	inviter, _ := keys.GenerateRoot()
	secret, _ := invite.NewSecret()
	l, err := invite.New(base, ch.ID, ch.InviteToken, inviter.Public(), secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "against the link's root key", "accept", "--dir", newDir(t, config{}), l.String())
}

// A PreKey record under a new identity carrying a card signed by another root
// than the pinned one is refused and consumed; the channel never waits on it.
func TestKeyChangeFromAnotherRootDoesNotPark(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	rg := rotateGuest(t, ctx, p)
	rg.establish(t, ctx, rc, p)
	mallory, _ := keys.GenerateRoot()
	c := card.New(rg.id, rg.k.PartyKeys, nil, nil, time.Now())
	c.Party = keys.PartyID(mallory.Public())
	forged, err := card.Sign(c, mallory)
	if err != nil {
		t.Fatal(err)
	}
	cm, _ := session.CardMessage(c.Party, p.hostParty, forged)
	rg.put(t, ctx, rc, p, cm)
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if strings.Contains(out, "waiting") || !strings.Contains(out, "another root than the pinned one") {
		t.Fatalf("a card from another root parked the channel or was not refused by name:\n%s", out)
	}
}

// A genuine root-signed card replayed under an identity it does not name — a
// relay holding an old card of the peer — is refused, never held.
func TestKeyChangeCardNotNamingTheRecordKeyDoesNotPark(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	x := rotateGuest(t, ctx, p) // the identity the record comes under
	y := rotateGuest(t, ctx, p) // a genuine card naming another identity
	x.establish(t, ctx, rc, p)
	cm, _ := session.CardMessage(p.guestParty, p.hostParty, y.card)
	x.put(t, ctx, rc, p, cm)
	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if strings.Contains(out, "waiting") || !strings.Contains(out, "does not name the key the record came under") {
		t.Fatalf("a card not naming the record's key parked the channel or was not refused by name:\n%s", out)
	}
}

// A card sent in the session in force, naming the key the session runs under
// but signed by another root than the pinned one, is skipped by name and
// consumed; the pin is unchanged and nothing is held.
func TestInSessionCardFromAnotherRootIsSkipped(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	_, hch, _ := channelOf(t, p.hostDir, "ancan")
	pinned := hch.Card().Body

	gp, gch, gpe := channelOf(t, p.guestDir, "zt")
	gk, err := gp.store.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mallory, _ := keys.GenerateRoot()
	c := card.New(gp.id, gk.PartyKeys, nil, nil, time.Now())
	c.Party = keys.PartyID(mallory.Public())
	forged, err := card.Sign(c, mallory)
	if err != nil {
		t.Fatal(err)
	}
	cm, _ := session.CardMessage(p.guestParty, p.hostParty, forged)
	rcpt, err := session.New(gch, gk).Send(ctx, gp.outbox, rc, gpe.Token, cm)
	if err != nil {
		t.Fatal(err)
	}

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "skip ancan #"+itoa(rcpt.Seq)+": card: signed by another root than the pinned one") || strings.Contains(out, "pinned\n") || strings.Contains(out, "waiting") {
		t.Fatalf("an in-session card from another root was not skipped by name:\n%s", out)
	}
	_, hch, _ = channelOf(t, p.hostDir, "ancan")
	if held, _ := hch.Held(); held != nil || !bytes.Equal(hch.Card().Body, pinned) || hch.Cursor() != rcpt.Seq {
		t.Fatalf("held %v, pin changed %v, cursor %d not past #%d", held != nil, !bytes.Equal(hch.Card().Body, pinned), hch.Cursor(), rcpt.Seq)
	}
}
