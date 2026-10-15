package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
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

const login = "zt:owner-secret"

// codeRE matches accept's code line: the 8-digit code and the guest's own id.
var codeRE = regexp.MustCompile(`(?m)^code ([0-9]{8})  your id (ed25519:[A-Za-z0-9_-]{43})$`)

// newDir is an initialised peer directory with the given config.json.
func newDir(t *testing.T, cfg config) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "peer")
	if _, err := initDir(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, configFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	// The card on the state carries the config: what the root's place does
	// after writing config.json. A config whose seat map is not there yet
	// cannot open the party; its test writes the map and publishes itself.
	if err := runCardPublish(context.Background(), dir, io.Discard); err != nil {
		t.Logf("card publish after init: %v", err)
	}
	return dir
}

func rootOf(t *testing.T, dir string) *keys.Root {
	t.Helper()
	r := new(keys.Root)
	if err := readJSON(filepath.Join(dir, rootFile), r); err != nil {
		t.Fatal(err)
	}
	return r
}

// cmd runs the CLI and returns its exit code, stdout and stderr.
func cmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	t.Logf("peer %s → %d\n%s%s", strings.Join(args, " "), code, out.String(), errb.String())
	return code, out.String(), errb.String()
}

func mustOK(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errb := cmd(t, args...)
	if code != 0 {
		t.Fatalf("peer %s: exit %d: %s", strings.Join(args, " "), code, errb)
	}
	return out
}

func mustRefuse(t *testing.T, reason string, args ...string) {
	t.Helper()
	code, _, errb := cmd(t, args...)
	if code != 1 || !strings.Contains(errb, reason) {
		t.Fatalf("peer %s: exit %d, stderr %q, want a refusal naming %q", strings.Join(args, " "), code, errb, reason)
	}
}

// channelOf is the peer's channel record and roster entry as a fresh process loads them.
func channelOf(t *testing.T, dir, name string) (*party, *store.Channel, *roster.Peer) {
	t.Helper()
	ctx := context.Background()
	p, err := openParty(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		t.Fatal(err)
	}
	pe := r.ByName(name)
	if pe == nil {
		t.Fatalf("%s: no roster entry for %s", dir, name)
	}
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		t.Fatal(err)
	}
	return p, ch, pe
}

// Two parties on a fake relay: invite → accept → confirm, a wrong code
// refused and nothing kept, the relay holding ciphertext and the host's
// card alone, the guest reading the host's details card from a fresh load,
// a reply back, and a second use of the link refused.
func TestInviteAcceptConfirm(t *testing.T) {
	ctx := context.Background()
	srv, rc, base := relaytest.Start(t, login)
	// The card's relays are config's relay: the card on the state is signed
	// where the root is, from config, and a relay given to invite as a flag
	// alone never reaches it.
	hostDir := newDir(t, config{
		Relay:   base,
		Agents:  []card.Agent{{ID: "advisor", Accepts: []string{"text", "task"}}},
		Details: json.RawMessage(`{"model":"fable"}`),
	})
	guestDir := newDir(t, config{})
	hostRoot, guestRoot := rootOf(t, hostDir), rootOf(t, guestDir)

	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	l, err := invite.Parse(link, time.Now())
	if err != nil {
		t.Fatalf("link %q: %v", link, err)
	}
	if !bytes.Equal(l.Root, hostRoot.Public()) {
		t.Fatal("link does not carry the host's root key")
	}
	if rows := srv.Envelopes(l.Channel, "h2g"); len(rows) != 1 || rows[0].Type != "card" {
		t.Fatalf("after invite the relay holds %+v", rows)
	}
	if n := srv.Prekeys(l.Channel, "h2g"); n != prekeysPerChannel {
		t.Fatalf("host deposited %d prekeys, want %d", n, prekeysPerChannel)
	}
	// The link secret is in the host's sealed channel record before the link exists.
	_, hch0, _ := channelOf(t, hostDir, "ancan")
	if hch0.Version() != 1 || !bytes.Equal(hch0.Secret(), l.Secret) {
		t.Fatalf("host channel after invite: version %d, secret stored %v", hch0.Version(), bytes.Equal(hch0.Secret(), l.Secret))
	}

	out = mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)
	m := codeRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("accept printed no code line:\n%s", out)
	}
	code := m[1]
	if code != session.Code(l.Channel, hostRoot.Public(), guestRoot.Public(), l.Secret) {
		t.Fatal("printed code is not Code(channel, inviter root, invitee root, secret)")
	}
	if m[2] != keys.PartyID(guestRoot.Public()) {
		t.Fatalf("code line names %s, want the guest's own id", m[2])
	}
	if rows := srv.Envelopes(l.Channel, "g2h"); len(rows) != 1 || rows[0].Type != "prekey" {
		t.Fatalf("after accept the relay holds %+v", rows)
	}
	if srv.Prekeys(l.Channel, "h2g") != prekeysPerChannel-1 || srv.Prekeys(l.Channel, "g2h") != prekeysPerChannel {
		t.Fatalf("prekeys host %d guest %d", srv.Prekeys(l.Channel, "h2g"), srv.Prekeys(l.Channel, "g2h"))
	}
	_, gch, gpe := channelOf(t, guestDir, "zt")
	if gpe.State != roster.Accepted || gpe.Side != roster.Guest || gpe.Channel != l.Channel || !relay.ValidToken(gpe.Token) {
		t.Fatalf("guest roster %+v", gpe)
	}
	if !bytes.Equal(gch.Root(), hostRoot.Public()) || gch.Card() == nil || gch.Cursor() != 0 || !bytes.Equal(gch.Secret(), l.Secret) {
		t.Fatalf("guest channel: root pinned %v, card %v, cursor %d, secret stored %v", gch.Root() != nil, gch.Card() != nil, gch.Cursor(), bytes.Equal(gch.Secret(), l.Secret))
	}

	// A wrong code refuses, names the peer's id, and keeps nothing.
	mustRefuse(t, "code does not match for "+keys.PartyID(guestRoot.Public()), "confirm", "--dir", hostDir, "--code", "00000000", "ancan")
	_, hch, hpe := channelOf(t, hostDir, "ancan")
	if hch.Version() != hch0.Version() || hch.Card() != nil || hch.Root() != nil || hpe.State != roster.Invited {
		t.Fatalf("refused confirm kept state: version %d card %v root %v state %s", hch.Version(), hch.Card() != nil, hch.Root() != nil, hpe.State)
	}
	if rows := srv.Envelopes(l.Channel, "h2g"); len(rows) != 1 {
		t.Fatalf("refused confirm put %d envelopes", len(rows)-1)
	}

	out = mustOK(t, "confirm", "--dir", hostDir, "--code", code, "ancan")
	if !strings.Contains(out, "confirmed ancan ("+keys.PartyID(guestRoot.Public())+")") {
		t.Fatalf("confirm output %q", out)
	}
	hp, hch, hpe := channelOf(t, hostDir, "ancan")
	if hpe.State != roster.Confirmed || hpe.Side != roster.Host {
		t.Fatalf("host roster %+v", hpe)
	}
	if !bytes.Equal(hch.Root(), guestRoot.Public()) || hch.Cursor() != 0 {
		t.Fatalf("host channel: root is guest's %v, cursor %d", bytes.Equal(hch.Root(), guestRoot.Public()), hch.Cursor())
	}
	pinned, err := card.Verify(hch.Card(), guestRoot.Public())
	if err != nil {
		t.Fatalf("pinned guest card: %v", err)
	}
	if got, ok := hch.RemoteIdentity(session.Addr); !ok || keys.CurveText(got) != pinned.Keys[0].Identity {
		t.Fatal("session identity is not the pinned card's")
	}
	hk, _ := hp.store.Keys(ctx)
	if n := len(hk.PartyKeys.Prekeys); n != keys.InitialPrekeys+prekeysPerChannel-1 {
		t.Fatalf("host holds %d one-time prekeys, want init's %d + %d − the used one", n, keys.InitialPrekeys, prekeysPerChannel)
	}
	// The relay saw the host's card in clear and two ciphertexts, nothing else.
	rows := srv.Envelopes(l.Channel, "h2g")
	if len(rows) != 2 || rows[0].Type != "card" || rows[1].Type != "msg" {
		t.Fatalf("relay h2g %+v", rows)
	}
	if rows := srv.Envelopes(l.Channel, "g2h"); len(rows) != 1 || rows[0].Type != "prekey" {
		t.Fatalf("relay g2h %+v", rows)
	}

	// The guest, from a fresh load, reads the host's details card and replies;
	// the host reads the reply from a fresh load: the state round-trips both ways.
	gp, gch, gpe := channelOf(t, guestDir, "zt")
	gk, _ := gp.store.Keys(ctx)
	gs := session.New(gch, gk)
	recs, err := rc.Pull(ctx, l.Channel, gpe.Token, gch.Cursor())
	if err != nil || len(recs) != 1 || recs[0].Seq != 1 {
		t.Fatalf("guest pull: %+v %v", recs, err)
	}
	dm, err := gs.Receive(ctx, recs[0])
	if err != nil {
		t.Fatal(err)
	}
	details, _, root, err := session.PeerCard(dm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, hostRoot.Public()) || string(details.Details) != `{"model":"fable"}` || len(details.Agents) != 1 || details.Relays[0] != base {
		t.Fatalf("details card: root is host's %v, details %s, agents %+v, relays %v", bytes.Equal(root, hostRoot.Public()), details.Details, details.Agents, details.Relays)
	}
	if dm.From != keys.PartyID(hostRoot.Public()) || dm.To != keys.PartyID(guestRoot.Public()) {
		t.Fatalf("details card addressed %s → %s", dm.From, dm.To)
	}
	reply, _ := session.NewMessage(dm.To, dm.From, session.KindText, []byte("got your card"))
	if _, err := gs.Send(ctx, gp.outbox, rc, gpe.Token, reply); err != nil {
		t.Fatal(err)
	}
	hp, hch, hpe = channelOf(t, hostDir, "ancan")
	hk, _ = hp.store.Keys(ctx)
	hs := session.New(hch, hk)
	recs, err = rc.Pull(ctx, l.Channel, hpe.Token, hch.Cursor())
	if err != nil || len(recs) != 1 {
		t.Fatalf("host pull: %+v %v", recs, err)
	}
	if recs[0].Env.Type != envelope.Msg {
		t.Fatalf("reply after the host's message has type %s, want msg", recs[0].Env.Type)
	}
	if got, err := hs.Receive(ctx, recs[0]); err != nil || string(got.Body) != "got your card" {
		t.Fatalf("host receive: %+v %v", got, err)
	}

	// The link joins once: a second party is refused and keeps nothing.
	thirdDir := newDir(t, config{})
	mustRefuse(t, "used already", "accept", "--dir", thirdDir, "--name", "zt", link)
	tp, _ := openParty(thirdDir)
	tr, _ := roster.Load(ctx, tp.backend)
	tch, _ := tp.store.Channel(ctx, l.Channel)
	if len(tr.Peers) != 0 || tch.Version() != 0 {
		t.Fatalf("refused accept kept state: %d peers, channel version %d", len(tr.Peers), tch.Version())
	}
	// Confirming twice, or a peer that never accepted, refuses.
	mustRefuse(t, "confirmed already", "confirm", "--dir", hostDir, "--code", code, "ancan")
	mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "nobody")
	mustRefuse(t, "not run peer accept", "confirm", "--dir", hostDir, "--code", code, "nobody")
}

// Whoever used the link holds a session identity that is not the card's
// (someone with a copy of the real invitee's card, design §3.4): confirm
// refuses even with the code that card would give, and keeps nothing.
func TestConfirmRefusesIdentityMismatch(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	hostDir := newDir(t, config{})
	hostRoot := rootOf(t, hostDir)
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	l, err := invite.Parse(link, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Ancan's real card, as Mallory holds a copy of it.
	ancanRoot, _ := keys.GenerateRoot()
	ancanID, _ := keys.GenerateIdentity(ancanRoot.Public())
	ancanPK, _ := keys.GeneratePartyKeys(ancanID, 1)
	ancanCard, err := card.Sign(card.New(ancanID, ancanPK, nil, nil, time.Now()), ancanRoot)
	if err != nil {
		t.Fatal(err)
	}

	// Mallory joins with the link and builds the session under her own identity.
	malloryRoot, _ := keys.GenerateRoot()
	malloryID, _ := keys.GenerateIdentity(malloryRoot.Public())
	mb, _ := file.New(filepath.Join(t.TempDir(), "mallory"))
	ms := store.New(mb, malloryID)
	guest, err := rc.Join(ctx, l.Channel, l.Token)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := rc.Pull(ctx, l.Channel, guest, -1)
	if err != nil || len(recs) != 1 {
		t.Fatal(err)
	}
	body, sig, _ := envelope.UnpackCard(recs[0].Env.Body)
	hostCard, err := card.Verify(&card.Signed{Body: body, Sig: sig}, l.Root)
	if err != nil {
		t.Fatal(err)
	}
	opk, _, _ := rc.TakePrekey(ctx, l.Channel, guest)
	mch, _ := ms.Channel(ctx, l.Channel)
	mk, _ := ms.Keys(ctx)
	mk.PartyKeys, _ = keys.GeneratePartyKeys(malloryID, 1)
	mch.PinRoot(l.Root)
	mch.PinCard(&card.Signed{Body: body, Sig: sig})
	sess := session.New(mch, mk)
	key, _ := session.CurrentKey(hostCard)
	if err := sess.Establish(ctx, key, &opk); err != nil {
		t.Fatal(err)
	}
	msg, _ := session.CardMessage(keys.PartyID(ancanRoot.Public()), keys.PartyID(l.Root), ancanCard)
	e, err := sess.Encrypt(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Put(ctx, l.Channel, guest, e); err != nil {
		t.Fatal(err)
	}

	code := session.Code(l.Channel, hostRoot.Public(), ancanRoot.Public(), l.Secret)
	mustRefuse(t, "not the card's", "confirm", "--dir", hostDir, "--code", code, "ancan")
	_, hch, hpe := channelOf(t, hostDir, "ancan")
	if hch.Version() != 1 || hch.Card() != nil || hpe.State != roster.Invited {
		t.Fatalf("refused confirm kept state: version %d card %v state %s", hch.Version(), hch.Card() != nil, hpe.State)
	}
}

func TestAcceptRefusesBadLinks(t *testing.T) {
	guestDir := newDir(t, config{})
	mustRefuse(t, "malformed", "accept", "--dir", guestDir, "https://x/peer/i/abc#v1.t.r.1")
	_, rc, base := relaytest.Start(t, login)
	ch, _ := rc.Create(context.Background(), login)
	root, _ := keys.GenerateRoot()
	secret, _ := invite.NewSecret()
	l, _ := invite.New(base, ch.ID, ch.InviteToken, root.Public(), secret, time.Now().Add(-invite.Validity-time.Hour))
	mustRefuse(t, "expired", "accept", "--dir", guestDir, l.String())
	// A link whose root does not sign envelope #0 is refused after the join.
	l, _ = invite.New(base, ch.ID, ch.InviteToken, root.Public(), secret, time.Now())
	mustRefuse(t, "not the inviter's card", "accept", "--dir", guestDir, l.String())
}
