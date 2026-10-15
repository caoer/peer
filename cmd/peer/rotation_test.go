package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

// A peer that rotates its identity key (design §3.2) sends its new card in a
// new session under the new key, which the pinned card cannot admit. Those
// envelopes belong to the version that applies a key change, so serve parks
// the channel there: the cursor stays before them, every round says so, and
// a later pull still finds them. Before the fix the cursor was committed past
// the card and every message behind it, one log line each, nothing delivered.
func TestServeParksARotatedIdentity(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)

	// What the channel did before the rotation is delivered as usual.
	before, _ := sendOK(t, p.guestDir, "--text", "before the rotation", "zt/advisor")
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+before) {
		t.Fatalf("host serve before the rotation:\n%s", out)
	}

	_, gch, gpe := channelOf(t, p.guestDir, "zt")
	hostCard, err := card.Verify(gch.Card(), p.hostRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := session.CurrentKey(hostCard)
	if err != nil {
		t.Fatal(err)
	}

	// The guest rotates: a new identity key and party keys, a new card signed
	// by the same root key, and a fresh session built from the host's card.
	newID, err := keys.GenerateIdentity(p.guestRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	newPK, err := keys.GeneratePartyKeys(newID, 2)
	if err != nil {
		t.Fatal(err)
	}
	newCard, err := card.Sign(card.New(newID, newPK, nil, []string{base}, time.Now()), p.guestRoot)
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
	rotated := session.New(ch2, k2)
	var opk *relay.Prekey
	if k, ok, err := rc.TakePrekey(ctx, p.channel, gpe.Token); err != nil {
		t.Fatal(err)
	} else if ok {
		opk = &k
	}
	if err := rotated.Establish(ctx, hostKey, opk); err != nil {
		t.Fatal(err)
	}
	cm, err := session.CardMessage(p.guestParty, p.hostParty, newCard)
	if err != nil {
		t.Fatal(err)
	}
	ce, err := rotated.Encrypt(ctx, cm)
	if err != nil {
		t.Fatal(err)
	}
	cardRcpt, err := rc.Put(ctx, p.channel, gpe.Token, ce)
	if err != nil {
		t.Fatal(err)
	}
	tm, err := session.NewMessage(p.guestParty+"/legal", p.hostParty+"/advisor", session.KindText, []byte("sent after the rotation"))
	if err != nil {
		t.Fatal(err)
	}
	te, err := rotated.Encrypt(ctx, tm)
	if err != nil {
		t.Fatal(err)
	}
	textRcpt, err := rc.Put(ctx, p.channel, gpe.Token, te)
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 2; i++ {
		out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
		if !strings.Contains(out, "waiting at #") {
			t.Fatalf("serve %d did not report the channel waiting:\n%s", i, out)
		}
		_, hch, _ := channelOf(t, p.hostDir, "ancan")
		if hch.Cursor() >= cardRcpt.Seq {
			t.Fatalf("serve %d consumed the rotation: cursor %d, the new card is #%d", i, hch.Cursor(), cardRcpt.Seq)
		}
	}

	// Both envelopes are still ahead of the cursor, so the version that can
	// apply a key change will find them where the peer put them.
	_, hch, hpe := channelOf(t, p.hostDir, "ancan")
	recs, err := rc.Pull(ctx, p.channel, hpe.Token, hch.Cursor())
	if err != nil {
		t.Fatal(err)
	}
	held := map[int64]bool{}
	for _, rec := range recs {
		held[rec.Seq] = true
	}
	if !held[cardRcpt.Seq] || !held[textRcpt.Seq] {
		t.Fatalf("a pull from cursor %d sees %v, want the new card #%d and the message #%d", hch.Cursor(), held, cardRcpt.Seq, textRcpt.Seq)
	}
	in := records(t, deliverDirOf(p.hostDir), deliver.Inbox)
	if _, ok := in[before]; !ok || len(in) != 1 {
		t.Fatalf("the host inbox holds %d records, the one from before the rotation present: %v", len(in), ok)
	}
}
