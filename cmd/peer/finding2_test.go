package main

// Regression for review finding 2 (chain/review/20261014-2142-peer-u7u8 § 2),
// adapted from the review's end-to-end probe: a joiner holding the invite
// token and the channel id but not the link secret — the relay operator,
// who minted the token and reads card #0 — is refused at the accept proof,
// before the code is compared and before any human step, whatever code the
// host types. The probe searched for a root whose v1 code equalled the
// victim's; here that matched code is typed directly (codeV1), which is all
// a finished search yields. The search program stays out of the suite.
//
// This file uses no API the §4 revision added, so it also runs against the
// base it fixes: there the first shape is refused for the wrong reason and
// the second shape confirms the joiner.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

// codeLine matches the 8 digits of accept's code line in any revision.
var codeLine = regexp.MustCompile(`(?m)^code ([0-9]{8})`)

// codeV1 is the §4 v1 derivation: sha256(label || inviter || invitee) mod 1e8.
func codeV1(inviter, invitee ed25519.PublicKey) string {
	h := sha256.New()
	h.Write([]byte("peer verification code v1"))
	h.Write(inviter)
	h.Write(invitee)
	return fmt.Sprintf("%08d", binary.BigEndian.Uint64(h.Sum(nil)[:8])%100000000)
}

// joinWithTokenOnly runs accept's wire steps with what the relay knows — the
// token and the channel id — under a fresh root, and sends that root's card
// as envelope #1; mutate, when given, edits the card message before it is
// encrypted. It returns the joiner's root.
func joinWithTokenOnly(t *testing.T, rc *relay.Client, l invite.Link, mutate func(*session.Message)) ed25519.PublicKey {
	t.Helper()
	ctx := context.Background()
	root, _ := keys.GenerateRoot()
	id, _ := keys.GenerateIdentity(root.Public())
	pk, _ := keys.GeneratePartyKeys(id, 1)
	own, err := card.Sign(card.New(id, pk, nil, nil, time.Now()), root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := file.New(filepath.Join(t.TempDir(), "joiner"))
	st := store.New(b, id)
	guest, err := rc.Join(ctx, l.Channel, l.Token)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := rc.Pull(ctx, l.Channel, guest, -1)
	if err != nil || len(recs) != 1 {
		t.Fatalf("pull card #0: %+v %v", recs, err)
	}
	body, sig, _ := envelope.UnpackCard(recs[0].Env.Body)
	hostCard, err := card.Verify(&card.Signed{Body: body, Sig: sig}, l.Root)
	if err != nil {
		t.Fatal(err)
	}
	opk, _, _ := rc.TakePrekey(ctx, l.Channel, guest)
	ch, _ := st.Channel(ctx, l.Channel)
	k, _ := st.Keys(ctx)
	k.PartyKeys = pk
	ch.PinRoot(l.Root)
	ch.PinCard(&card.Signed{Body: body, Sig: sig})
	s := session.New(ch, k)
	key, _ := session.CurrentKey(hostCard)
	if err := s.Establish(ctx, key, &opk); err != nil {
		t.Fatal(err)
	}
	m, _ := session.CardMessage(keys.PartyID(root.Public()), keys.PartyID(l.Root), own)
	if mutate != nil {
		mutate(m)
	}
	e, err := s.Encrypt(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Put(ctx, l.Channel, guest, e); err != nil {
		t.Fatal(err)
	}
	return root.Public()
}

// inviteLink runs invite for name on hostDir and parses the printed link.
func inviteLink(t *testing.T, hostDir, base, name string) (string, invite.Link) {
	t.Helper()
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, name)
	link, _, _ := strings.Cut(out, "\n")
	l, err := invite.Parse(link, time.Now())
	if err != nil {
		t.Fatalf("link %q: %v", link, err)
	}
	return link, l
}

// A joiner without the link secret is refused at the proof with any code,
// and with the code the v1 derivation gives its root; nothing is kept.
func TestConfirmRefusesJoinerWithoutSecret(t *testing.T) {
	_, rc, base := relaytest.Start(t, login)
	hostDir := newDir(t, config{})
	hostRoot := rootOf(t, hostDir)
	shapes := []struct {
		name string
		code func(joiner ed25519.PublicKey) string
	}{
		{"any code", func(ed25519.PublicKey) string { return "00000000" }},
		{"the v1 code of the joiner's root", func(j ed25519.PublicKey) string { return codeV1(hostRoot.Public(), j) }},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			_, l := inviteLink(t, hostDir, base, "ancan")
			_, hch0, _ := channelOf(t, hostDir, "ancan")
			joiner := joinWithTokenOnly(t, rc, l, nil)
			mustRefuse(t, "proof", "confirm", "--dir", hostDir, "--code", sh.code(joiner), "ancan")
			_, hch, hpe := channelOf(t, hostDir, "ancan")
			if hch.Version() != hch0.Version() || hch.Card() != nil || hch.Root() != nil || hpe.State != roster.Invited {
				t.Fatalf("refused confirm kept state: version %d→%d card %v root %v state %s",
					hch0.Version(), hch.Version(), hch.Card() != nil, hch.Root() != nil, hpe.State)
			}
		})
	}
}

// Two invites of the same pair print two codes, and the genuine guest, who
// holds the secret, is confirmed on both.
func TestCodeDiffersPerInvite(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	hostDir, guestDir := newDir(t, config{}), newDir(t, config{})
	link1, _ := inviteLink(t, hostDir, base, "ancan")
	link2, _ := inviteLink(t, hostDir, base, "ancan-again")
	out1 := mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link1)
	out2 := mustOK(t, "accept", "--dir", guestDir, "--name", "zt-again", link2)
	m1, m2 := codeLine.FindStringSubmatch(out1), codeLine.FindStringSubmatch(out2)
	if m1 == nil || m2 == nil {
		t.Fatalf("accept printed no code line:\n%s\n%s", out1, out2)
	}
	if m1[1] == m2[1] {
		t.Fatalf("the same pair got the same code %s on two invites", m1[1])
	}
	mustOK(t, "confirm", "--dir", hostDir, "--code", m1[1], "ancan")
	mustOK(t, "confirm", "--dir", hostDir, "--code", m2[1], "ancan-again")
	for _, name := range []string{"ancan", "ancan-again"} {
		if _, _, hpe := channelOf(t, hostDir, name); hpe.State != roster.Confirmed {
			t.Fatalf("%s: state %s", name, hpe.State)
		}
	}
}
