package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// Without --yes the command prints the cost and refuses: nothing changes.
func TestIdentityRotateRefusesWithoutYes(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	before, _ := os.ReadFile(filepath.Join(p.hostDir, identityFile))
	puts := len(srv.Envelopes(p.channel, "h2g"))
	code, out, errb := cmd(t, "identity", "rotate", "--dir", p.hostDir)
	if code != 1 || !strings.Contains(errb, "--yes") {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
	for _, want := range []string{"The cost:", "1 channel(s) is dropped", "1 confirmed peer(s) must run peer keys accept", "identity.json.retired-"} {
		if !strings.Contains(out, want) {
			t.Errorf("the cost does not say %q:\n%s", want, out)
		}
	}
	after, _ := os.ReadFile(filepath.Join(p.hostDir, identityFile))
	if !bytes.Equal(before, after) || len(srv.Envelopes(p.channel, "h2g")) != puts {
		t.Fatal("a refused rotate changed the identity file or put an envelope")
	}
	// A fleet host holds no root.json: it cannot rotate.
	if err := os.Remove(filepath.Join(p.guestDir, rootFile)); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "root.json is not in", "identity", "rotate", "--dir", p.guestDir, "--yes")
}

// The host rotates its identity key: the card retiring the old key goes out
// under the session in force and the guest holds it for its human; the
// host's sessions are gone, so a text the guest sends meanwhile is refused;
// after peer keys accept the guest builds a session from the host's prekey
// under the new key and a text flows each way. The old identity file stays
// beside the new one, retired; the keys record carries a signed prekey under
// the new key and the one-time prekeys as they were.
func TestIdentityRotate(t *testing.T) {
	ctx := context.Background()
	_, rc, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	oldIdentity, _ := os.ReadFile(filepath.Join(p.hostDir, identityFile))
	hp, _, _ := channelOf(t, p.hostDir, "ancan")
	hk, _ := hp.store.Keys(ctx)
	prekeys, oldSpk := len(hk.PartyKeys.Prekeys), hk.PartyKeys.SignedPrekey.ID()

	out := mustOK(t, "identity", "rotate", "--dir", p.hostDir, "--yes")
	for _, want := range []string{"card published to ancan (#", "sessions dropped on 1 channel(s)", "signed prekey " + itoa(int64(oldSpk)+1) + " under the new key", "fleet: put the new identity.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("rotate did not say %q:\n%s", want, out)
		}
	}
	newIdentity, _ := os.ReadFile(filepath.Join(p.hostDir, identityFile))
	if bytes.Equal(oldIdentity, newIdentity) {
		t.Fatal("identity.json unchanged")
	}
	retired, _ := filepath.Glob(filepath.Join(p.hostDir, identityFile+".retired-*"))
	if len(retired) != 1 {
		t.Fatalf("retired identity files: %v", retired)
	}
	if b, _ := os.ReadFile(retired[0]); !bytes.Equal(b, oldIdentity) {
		t.Fatal("the retired file is not the old identity")
	}
	hp, hch, _ := channelOf(t, p.hostDir, "ancan")
	hk, _ = hp.store.Keys(ctx)
	if hk.PartyKeys.PreviousSignedPrekey != nil || hk.PartyKeys.SignedPrekey.ID() != oldSpk+1 || len(hk.PartyKeys.Prekeys) != prekeys {
		t.Fatalf("keys record: previous %v, signed prekey %d, %d prekeys (want %d)", hk.PartyKeys.PreviousSignedPrekey != nil, hk.PartyKeys.SignedPrekey.ID(), len(hk.PartyKeys.Prekeys), prekeys)
	}
	if has, _ := hch.ContainsSession(ctx, session.Addr); has {
		t.Fatal("the host still holds the old session")
	}
	oc, err := hp.store.OwnCard(ctx)
	if err != nil || oc.Identity != keys.CurveText(hp.id.PublicKey()) {
		t.Fatalf("card record: %v, identity %s", err, oc.Identity)
	}
	c, err := card.Verify(oc.Details, p.hostRoot.Public())
	if err != nil || len(c.Keys) != 2 || c.Keys[0].Until == nil || c.Keys[1].Until != nil || c.Keys[1].Identity != oc.Identity {
		t.Fatalf("the new card: %v %+v", err, c)
	}

	// The guest holds the card and waits; a text it sends under the old
	// session no longer opens on the host.
	out = mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.Contains(out, "zt: waiting at #") || !strings.Contains(out, "peer keys accept zt") {
		t.Fatalf("guest serve on the rotation card:\n%s", out)
	}
	out = mustOK(t, "send", "--dir", p.guestDir, "--text", "under the old key", "zt/advisor")
	stale := sentRE.FindStringSubmatch(out)
	if stale == nil {
		t.Fatalf("guest send:\n%s", out)
	}
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "skip ancan #"+stale[4]) || strings.Contains(out, "delivered") {
		t.Fatalf("host serve on a text under the old key:\n%s", out)
	}

	// The guest accepts: a session from the host's prekey under the new key,
	// its card in it; the host pins it and a text flows each way.
	out = mustOK(t, "keys", "accept", "--dir", p.guestDir, "zt")
	if !strings.Contains(out, "a new one is built from their prekey") || !strings.Contains(out, "your card went out (#") {
		t.Fatalf("keys accept:\n%s", out)
	}
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "card from ancan pinned") {
		t.Fatalf("host serve on the guest's new session:\n%s", out)
	}
	out = mustOK(t, "send", "--dir", p.guestDir, "--text", "on the new key", "zt/advisor")
	m := sentRE.FindStringSubmatch(out)
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); m == nil || !strings.Contains(out, "delivered text "+m[1]) {
		t.Fatalf("host serve on the new session:\n%s", out)
	}
	out = mustOK(t, "send", "--dir", p.hostDir, "--text", "back to you", "ancan")
	m = sentRE.FindStringSubmatch(out)
	if out := mustOK(t, "serve", "--dir", p.guestDir, "--once"); m == nil || !strings.Contains(out, "delivered text "+m[1]) {
		t.Fatalf("guest serve on the host's reply:\n%s", out)
	}
	_ = rc
}

// A channel that is not confirmed gets no card and loses its session, so
// nothing on it opens again: the cost names each such channel with its state
// and how it is set up again — the host side invites again, the guest side
// accepts the same link again — and the rotation's last line repeats it.
func TestIdentityRotateNamesUnconfirmedChannels(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	hostDir, guestDir := newDir(t, hostCfg()), newDir(t, config{})
	out := mustOK(t, "invite", "--dir", hostDir, "--relay", base, "--login", login, "ancan")
	link, _, _ := strings.Cut(out, "\n")
	mustOK(t, "accept", "--dir", guestDir, "--name", "zt", link)

	// The guest between its accept and the host's confirm, the host with its
	// invite out.
	guestStep := "zt (accepted): peer accept <the same link> before it expires"
	hostStep := "ancan (invited): peer invite ancan"
	for dir, want := range map[string]string{guestDir: guestStep, hostDir: hostStep} {
		code, out, errb := cmd(t, "identity", "rotate", "--dir", dir)
		if code != 1 || !strings.Contains(errb, "--yes") {
			t.Fatalf("exit %d, stderr %q", code, errb)
		}
		if !strings.Contains(out, "1 channel(s) not confirmed get no card") || !strings.Contains(out, want) {
			t.Errorf("the cost does not name the channel that is not confirmed (%q):\n%s", want, out)
		}
	}

	out = mustOK(t, "identity", "rotate", "--dir", guestDir, "--yes")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "fleet: ") || !strings.Contains(last, guestStep) {
		t.Fatalf("the last line does not repeat the step for zt:\n%s", out)
	}
}

// putBumpRelay fronts the fake relay and runs the armed bump once, on the
// next envelope put — another host of the party committing the keys record
// while the rotation is on the network.
type putBumpRelay struct {
	proxy http.Handler
	bump  atomic.Pointer[func()]
}

func (b *putBumpRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/envelopes") {
		if f := b.bump.Swap(nil); f != nil {
			(*f)()
		}
	}
	b.proxy.ServeHTTP(w, r)
}

// Another serving host restocks one-time prekeys while the rotation sends its
// card: the keys record the rotation writes keeps the private halves that
// host committed, whose public halves are on the relay, and carries the
// signed prekey the rotation card announced.
func TestIdentityRotateKeepsAConcurrentRestock(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	br := &putBumpRelay{proxy: httputil.NewSingleHostReverseProxy(target)}
	front := httptest.NewServer(br)
	t.Cleanup(front.Close)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), front.URL+"/peer")

	var restocked []uint32
	bump := func() {
		op, err := openParty(p.hostDir)
		if err != nil {
			t.Error(err)
			return
		}
		k, err := op.keys(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		pks, err := session.NewPrekeys(ctx, k, 5)
		if err != nil {
			t.Error(err)
			return
		}
		if err := k.Commit(ctx); err != nil {
			t.Error(err)
			return
		}
		r, err := roster.Load(ctx, op.backend)
		if err != nil {
			t.Error(err)
			return
		}
		pe := r.ByName("ancan")
		if _, err := relay.New(pe.Relay, nil).PutPrekeys(ctx, p.channel, pe.Token, pks); err != nil {
			t.Error(err)
			return
		}
		for _, pk := range pks {
			restocked = append(restocked, pk.ID)
		}
	}
	br.bump.Store(&bump)
	var out bytes.Buffer
	if err := runIdentityRotate(ctx, p.hostDir, true, &out); err != nil {
		t.Fatalf("rotate: %v\n%s", err, out.String())
	}
	if len(restocked) == 0 {
		t.Fatalf("the restock never ran under the rotation:\n%s", out.String())
	}

	hp, _, _ := channelOf(t, p.hostDir, "ancan")
	k, err := hp.keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range restocked {
		if r, _ := k.LoadPreKey(ctx, id); r == nil {
			t.Errorf("one-time prekey %d, deposited during the rotation, is gone from the keys record", id)
		}
	}
	if last := restocked[len(restocked)-1]; k.PartyKeys.NextPrekeyID <= last {
		t.Errorf("next prekey id %d, want past the restocked %d", k.PartyKeys.NextPrekeyID, last)
	}
	oc, err := hp.store.OwnCard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := card.Verify(oc.Details, p.hostRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	cur, err := session.CurrentKey(c)
	if err != nil {
		t.Fatal(err)
	}
	spk := k.PartyKeys.SignedPrekey
	if k.PartyKeys.PreviousSignedPrekey != nil || cur.SignedPrekey.ID != spk.ID() || cur.SignedPrekey.Pub != keys.CurveText(spk.KeyPair().PublicKey().PublicKey()) {
		t.Fatalf("keys record: signed prekey %d (previous held %v), the card announced %d", spk.ID(), k.PartyKeys.PreviousSignedPrekey != nil, cur.SignedPrekey.ID)
	}
}

// A state page that fails the keys record's write after the re-seal stops
// the rotation part way, with the state sealed under the new key: the key is
// on disk as identity.json.next, so the party still opens the state, and
// running the rotation again completes it — identity.json is the new key,
// .next is gone, the keys record carries a signed prekey under the new key,
// and the guest takes the key and talks to it.
func TestIdentityRotateCompletesAfterAStateFailure(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	ps := pagestest.New("state-0123456789abcdef", "zt:state-secret")
	target, err := url.Parse(ps.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var armed atomic.Bool
	var keysPuts atomic.Int32
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Armed: the re-seal's copy of the keys record lands, the rotation's
		// own write of it meets a 503.
		if armed.Load() && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/"+store.KeysKey) && keysPuts.Add(1) == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"unavailable"}`))
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	cfg := hostCfg()
	cfg.State = stateConfig{Page: front.URL, Slug: ps.Slug, Login: ps.Bearer}
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	idPath, nextPath := filepath.Join(p.hostDir, identityFile), filepath.Join(p.hostDir, identityFile+".next")
	oldIdentity, _ := os.ReadFile(idPath)

	armed.Store(true)
	code, out, errb := cmd(t, "identity", "rotate", "--dir", p.hostDir, "--yes")
	armed.Store(false)
	if code != 1 || !strings.Contains(out, "state re-sealed under the new identity key") {
		t.Fatalf("rotate with the keys write failing: exit %d\n%s%s", code, out, errb)
	}
	// The state opens under the identity the party picks.
	np, err := openParty(p.hostDir)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := roster.Load(ctx, np.backend); err != nil || len(r.Peers) != 1 {
		t.Fatalf("the state after the stopped rotation: %v", err)
	}
	next, err := os.ReadFile(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(nextPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity.json.next: %v %v", fi.Mode(), err)
	}
	if b, _ := os.ReadFile(idPath); !bytes.Equal(b, oldIdentity) || bytes.Equal(next, oldIdentity) {
		t.Fatal("identity.json changed, or identity.json.next is the old key")
	}
	if !strings.Contains(errb, "peer identity rotate --yes again") {
		t.Errorf("the stopped rotation does not say how to complete it: %q", errb)
	}

	out = mustOK(t, "identity", "rotate", "--dir", p.hostDir, "--yes")
	if b, _ := os.ReadFile(idPath); !bytes.Equal(b, next) {
		t.Fatalf("identity.json is not the key identity.json.next held:\n%s", out)
	}
	for _, name := range []string{identityFile + ".next", partyKeysFile + ".next"} {
		if _, err := os.Stat(filepath.Join(p.hostDir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s after the rotation completed: %v", name, err)
		}
	}
	retired, _ := filepath.Glob(filepath.Join(p.hostDir, identityFile+".retired-*"))
	if len(retired) != 1 {
		t.Fatalf("retired identity files: %v", retired)
	}
	if b, _ := os.ReadFile(retired[0]); !bytes.Equal(b, oldIdentity) {
		t.Fatal("the retired file is not the old identity")
	}
	hp, _, _ := channelOf(t, p.hostDir, "ancan")
	k, err := hp.keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oc, err := hp.store.OwnCard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := card.Verify(oc.Details, p.hostRoot.Public())
	if err != nil {
		t.Fatal(err)
	}
	cur, err := session.CurrentKey(c)
	if err != nil {
		t.Fatal(err)
	}
	spk := k.PartyKeys.SignedPrekey
	if cur.Identity != keys.CurveText(hp.id.PublicKey()) || cur.SignedPrekey.ID != spk.ID() || cur.SignedPrekey.Pub != keys.CurveText(spk.KeyPair().PublicKey().PublicKey()) {
		t.Fatalf("keys record: signed prekey %d; the card names %s with signed prekey %d", spk.ID(), cur.Identity, cur.SignedPrekey.ID)
	}

	// The guest takes the new key; a text flows on a session under it.
	if out := mustOK(t, "serve", "--dir", p.guestDir, "--once"); !strings.Contains(out, "peer keys accept zt") {
		t.Fatalf("guest serve on the rotation:\n%s", out)
	}
	mustOK(t, "keys", "accept", "--dir", p.guestDir, "zt")
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "card from ancan pinned") {
		t.Fatalf("host serve on the guest's new session:\n%s", out)
	}
	id, _ := sendOK(t, p.guestDir, "--text", "after the completed rotation", "zt/advisor")
	if out := mustOK(t, "serve", "--dir", p.hostDir, "--once"); !strings.Contains(out, "delivered text "+id) {
		t.Fatalf("host serve:\n%s", out)
	}
}

// On a pages state the rotation re-seals every record under the new
// identity's key: a host still holding the old identity file cannot open
// the roster, the new one reads it whole.
func TestIdentityRotateReseals(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	ps := pagestest.New("state-0123456789abcdef", "zt:state-secret")
	cfg := hostCfg()
	cfg.State = stateConfig{Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}
	p := handshake(t, newDir(t, cfg), newDir(t, config{}), base)
	oldIdentity, _ := os.ReadFile(filepath.Join(p.hostDir, identityFile))

	out := mustOK(t, "identity", "rotate", "--dir", p.hostDir, "--yes")
	if !strings.Contains(out, "state re-sealed under the new identity key: ") {
		t.Fatalf("rotate on a pages state:\n%s", out)
	}
	// The old identity, as a fleet host that was not redeployed holds it.
	stale := filepath.Join(t.TempDir(), "stale")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{identityFile: oldIdentity} {
		if err := os.WriteFile(filepath.Join(stale, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cb, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(stale, configFile), cb, 0o600); err != nil {
		t.Fatal(err)
	}
	sp, err := openParty(stale)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roster.Load(ctx, sp.backend); !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("the old identity opened the re-sealed roster: %v", err)
	}
	np, err := openParty(p.hostDir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := roster.Load(ctx, np.backend)
	if err != nil || len(r.Peers) != 1 || r.Peers[0].Name != "ancan" {
		t.Fatalf("the new identity's roster: %v %+v", err, r)
	}
	if ch, err := np.store.Channel(ctx, p.channel); err != nil || ch.Card() == nil || ch.Cursor() < 1 {
		t.Fatalf("the re-sealed channel record: %v", err)
	}
	if out := mustOK(t, "serve", "--dir", p.guestDir, "--once"); !strings.Contains(out, "peer keys accept zt") {
		t.Fatalf("guest serve:\n%s", out)
	}
}
