package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.mau.fi/libsignal/ecc"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/status"
	"github.com/caoer/peer/internal/store"
)

// cmdIdentity is `peer identity rotate`: the sender side of an identity
// change (design §3.2: 身份密钥只在怀疑泄露时换). The root key signs a card
// listing the old identity key with its until and the new key with a signed
// prekey under it; the card goes out on every confirmed channel under the
// session in force, then every session is dropped (换身份密钥即作废旧会话),
// the state is re-sealed under the new identity's key, the keys record takes
// the new signed prekey (the one-time prekeys stay — they are not bound to
// the identity) and a new identity.json is written. What the card names is
// on disk before it goes out — the new key as identity.json.next until it is
// renamed over identity.json, its signed prekey as keys.json.next until the
// keys record holds it — so a rotation that stops part way leaves a key that
// opens the state, and running the command again completes that rotation.
// Without --yes it prints what that costs the fleet and refuses.
func cmdIdentity(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "usage: peer identity rotate [--dir D] [--yes]")
		return 2
	}
	if len(args) == 0 || args[0] != "rotate" {
		return usage()
	}
	fl := flag.NewFlagSet("identity rotate", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	yes := fl.Bool("yes", false, "rotate: the cost printed without this flag is understood")
	if err := fl.Parse(args[1:]); err != nil {
		return 2
	}
	if fl.NArg() != 0 {
		return usage()
	}
	if err := runIdentityRotate(context.Background(), *dirFlag, *yes, stdout); err != nil {
		fmt.Fprintf(stderr, "peer identity rotate: %v\n", err)
		return 1
	}
	return 0
}

// errNoYes is the refusal without --yes.
var errNoYes = errors.New("refused: run again with --yes once the cost above is understood")

// A rotation keeps what its card names on disk from before the card goes
// out: nextIdentityFile holds the new identity until it is renamed over
// identity.json, so a key that opens the state is there at every step;
// nextKeysFile holds the new signed prekey until the keys record does, so a
// rotation completed by a second run commits the key the card announced.
const (
	nextIdentityFile = identityFile + ".next"
	nextKeysFile     = partyKeysFile + ".next"
)

// nextIdentity is the identity a rotation that has not completed moves to,
// nil when there is none. A .next that is the identity in force already is
// removed: its rotation completed.
func nextIdentity(dir string, current *keys.Identity) (*keys.Identity, error) {
	path := filepath.Join(dir, nextIdentityFile)
	next := new(keys.Identity)
	if err := readJSON(path, next); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if next.PublicKey() == current.PublicKey() {
		return nil, os.Remove(path)
	}
	return next, nil
}

func runIdentityRotate(ctx context.Context, dir string, yes bool, out io.Writer) (err error) {
	dir, err = peerDir(dir)
	if err != nil {
		return err
	}
	p, err := openParty(dir)
	if err != nil {
		return err
	}
	if p.root == nil {
		return errNoRoot(dir)
	}
	// The identity in force is identity.json's. A rotation that stopped part
	// way left the key it moves to in identity.json.next; it is completed
	// under that key, not begun again — its card may be out and the state
	// sealed under that key already.
	oldID := new(keys.Identity)
	if err := readJSON(filepath.Join(dir, identityFile), oldID); err != nil {
		return err
	}
	newID, err := nextIdentity(dir, oldID)
	if err != nil {
		return err
	}
	resume := newID != nil
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return err
	}
	sealed := p.cfg.State.Page != "" || p.cfg.State.Slug != ""
	oldIdentity := keys.CurveText(oldID.PublicKey())
	if !yes {
		if resume {
			fmt.Fprintf(out, "a rotation to identity key %s stopped part way (%s holds it): --yes completes it under that key\n", keys.CurveText(newID.PublicKey()), nextIdentityFile)
		}
		printRotateCost(out, r, sealed, oldIdentity)
		return errNoYes
	}
	// Once the new key is on disk, a failure says how the rotation completes.
	nextOnDisk := resume
	defer func() {
		if err != nil && nextOnDisk {
			err = fmt.Errorf("%w; the rotation stopped part way and %s holds the new key: run peer identity rotate --yes again to complete it", err, nextIdentityFile)
		}
	}()
	oldBackend, err := openBackend(dir, p.cfg, oldID)
	if err != nil {
		return err
	}

	now := time.Now()
	if !resume {
		if newID, err = keys.GenerateIdentity(oldID.Party); err != nil {
			return err
		}
	}
	newIdentity := keys.CurveText(newID.PublicKey())
	newBackend, err := openBackend(dir, p.cfg, newID)
	if err != nil {
		return err
	}
	if resume {
		// Its re-seal may have begun: it is finished first, and the rest
		// reads the state under the new key.
		fmt.Fprintf(out, "completing the rotation to identity key %s\n", newIdentity)
		if sealed {
			if err := reseal(ctx, oldBackend, newBackend, r, out); err != nil {
				return err
			}
		}
		p.id, p.backend, p.store = newID, newBackend, store.New(newBackend, newID)
	}
	k, err := p.keys(ctx)
	if err != nil {
		return err
	}
	// The signed prekey under the new identity key, on disk before the card
	// names it; announce is whether the card still goes out.
	newPK, announce, err := rotationPrekey(dir, k.PartyKeys, newID)
	if err != nil {
		return err
	}

	// 1. The card: the old key with its until, then the new key — signed by
	// the root, the same card the state holds from here (every host's).
	old, err := p.retiredKey(ctx, oldID, k.PartyKeys, now)
	if err != nil {
		return err
	}
	public, details, err := p.buildOwnCard(newID, newPK, now, old)
	if err != nil {
		return err
	}
	// The new identity on disk before the card names it, and before any
	// record is sealed under it.
	if !resume {
		b, err := json.MarshalIndent(newID, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(dir, nextIdentityFile), append(b, '\n')); err != nil {
			return err
		}
		nextOnDisk = true
	}
	fmt.Fprintf(out, "new identity key %s; %s retires at %s\n", newIdentity, oldIdentity, old.Until.UTC().Format(time.RFC3339))

	// 2. Out on every confirmed channel under the session in force: the peer
	// holds it for its human (U13's receiver) and rebuilds from our prekeys
	// after peer keys accept.
	for _, pe := range r.Peers {
		if !announce || pe.State != roster.Confirmed {
			continue
		}
		if err := p.publish(ctx, pe, details, newPK.SignedPrekey.ID(), out); err != nil {
			fmt.Fprintf(out, "%s: the card was not sent (%v); they learn the new key from your next session\n", pe.Name, err)
		}
	}

	// 3. The state under the new identity's seal: every record copied under
	// CAS, so a host that commits meanwhile is seen, not overwritten.
	if sealed && !resume {
		if err := reseal(ctx, oldBackend, newBackend, r, out); err != nil {
			return err
		}
	}

	// 4. Under the new identity: the keys record, every session dropped, the
	// card record.
	ns := store.New(newBackend, newID)
	nk, err := commitRotatedKeys(ctx, ns, k.PartyKeys, newPK)
	if err != nil {
		return fmt.Errorf("keys record: %w", err)
	}
	if err := os.Remove(filepath.Join(dir, nextKeysFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dropped := 0
	for _, pe := range r.Peers {
		ch, err := ns.Channel(ctx, pe.Channel)
		if err != nil {
			return err
		}
		if has, _ := ch.ContainsSession(ctx, session.Addr); has {
			dropped++
		}
		if err := ch.DeleteAllSessions(ctx); err != nil {
			return err
		}
		if err := ch.Commit(ctx); err != nil {
			return fmt.Errorf("%s: commit: %w", pe.Name, err)
		}
	}
	if err := putOwnCard(ctx, ns, newID, newPK, now, public, details); err != nil {
		return err
	}
	fmt.Fprintf(out, "sessions dropped on %d channel(s); signed prekey %d under the new key; %d one-time prekeys kept\n", dropped, nk.SignedPrekey.ID(), len(nk.Prekeys))

	// 5. The identity file: the old one kept beside it, retired, then
	// identity.json.next renamed over it — the one step that makes the new
	// key identity.json and leaves no .next.
	retired := filepath.Join(dir, identityFile+".retired-"+now.UTC().Format("20060102T150405Z"))
	b, err := os.ReadFile(filepath.Join(dir, identityFile))
	if err != nil {
		return err
	}
	if err := writeNew(retired, b); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(dir, nextIdentityFile), filepath.Join(dir, identityFile)); err != nil {
		return err
	}
	nextOnDisk = false
	fmt.Fprintf(out, "wrote %s; the old one is %s\n", filepath.Join(dir, identityFile), filepath.Base(retired))
	fleet := fmt.Sprintf("fleet: put the new %s where sops holds it and deploy; a host still holding the old one cannot open the state until then. Each peer runs peer keys accept <you> after checking the new key with you over a channel you trust.", identityFile)
	if steps := unconfirmedSteps(r); len(steps) > 0 {
		fleet += " Not confirmed, so set up again: " + strings.Join(steps, "; ") + "."
	}
	fmt.Fprintln(out, fleet)
	return nil
}

// unconfirmedSteps lists each channel that is not confirmed with how it is
// set up again after a rotation, which sends it no card and drops its
// session: the host side invites again, since its invite's card names the
// retired key; the guest side accepts the same link again, which builds a
// session to the invite's card under the new key.
func unconfirmedSteps(r *roster.Roster) []string {
	var steps []string
	for _, pe := range r.Peers {
		switch {
		case pe.State == roster.Confirmed:
		case pe.Side == roster.Host:
			steps = append(steps, fmt.Sprintf("%s (%s): peer invite %s, and send them the new link", pe.Name, pe.State, pe.Name))
		default:
			steps = append(steps, fmt.Sprintf("%s (%s): peer accept <the same link> before it expires (once it has, ask %s for a new invite)", pe.Name, pe.State, pe.Name))
		}
	}
	return steps
}

// printRotateCost is what --yes acknowledges.
func printRotateCost(out io.Writer, r *roster.Roster, sealed bool, identity string) {
	confirmed := 0
	for _, pe := range r.Peers {
		if pe.State == roster.Confirmed {
			confirmed++
		}
	}
	fmt.Fprintf(out, "peer identity rotate replaces identity key %s. The cost:\n", identity)
	fmt.Fprintf(out, "- every session on the %d channel(s) is dropped: nothing a peer sent under the old key opens after this, and each of the %d confirmed peer(s) must run peer keys accept <you> before a message flows again\n", len(r.Peers), confirmed)
	if steps := unconfirmedSteps(r); len(steps) > 0 {
		fmt.Fprintf(out, "- %d channel(s) not confirmed get no card and lose their session, so nothing on them opens again and the other side is not told: an invite you sent carries a card naming the old key, so its guest is never confirmed; on a link you accepted the host's confirm still succeeds and it sends into a channel you cannot open. Set each up again:\n", len(steps))
		for _, s := range steps {
			fmt.Fprintf(out, "  - %s\n", s)
		}
	}
	if sealed {
		fmt.Fprintln(out, "- the shared state is re-sealed under the new identity key: every fleet host that holds the old identity.json cannot open it from this moment until the new identity.json is in sops and deployed — peer serve there fails every round until then")
	} else {
		fmt.Fprintln(out, "- the file state stays readable; a second host of this party needs the new identity.json before it serves again")
	}
	fmt.Fprintln(out, "- the old identity.json is kept beside the new one as identity.json.retired-<time>; the old key signs nothing and opens nothing from here")
}

// commitRotatedKeys writes the keys record under the new identity: the
// record as st holds it — its one-time prekeys and next id as another host
// may have restocked or spent them while the rotation ran — with rotated's
// signed prekey, the one the card announced, and no previous one (the old
// was signed by the retired key and opens nothing a peer may still send). An
// absent record starts from seed, the keys init wrote. A conflict reloads
// the record and builds again.
func commitRotatedKeys(ctx context.Context, st *store.Store, seed, rotated *keys.PartyKeys) (*keys.PartyKeys, error) {
	for try := 1; ; try++ {
		k, err := st.Keys(ctx)
		if err != nil {
			return nil, err
		}
		held := k.PartyKeys
		if held == nil {
			held = seed
		}
		k.PartyKeys = &keys.PartyKeys{SignedPrekey: rotated.SignedPrekey, Prekeys: held.Prekeys, NextPrekeyID: held.NextPrekeyID}
		err = k.Commit(ctx)
		if err == nil {
			return k.PartyKeys, nil
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			return nil, err
		}
	}
}

// rotationPrekey is the signed prekey a rotation to newID commits, and
// whether its card still goes out. A stopped rotation's, from keys.json.next,
// is announced again: the keys record does not hold it yet, so every session
// is in force. One the keys record holds under newID already is the stopped
// rotation's after its commit: its card is out. Otherwise a new one with the
// next id after held's goes on disk as keys.json.next before the card names
// it.
func rotationPrekey(dir string, held *keys.PartyKeys, newID *keys.Identity) (*keys.PartyKeys, bool, error) {
	path := filepath.Join(dir, nextKeysFile)
	pending := new(keys.PartyKeys)
	switch err := readJSON(path, pending); {
	case err == nil && signedBy(pending, newID):
		return &keys.PartyKeys{SignedPrekey: pending.SignedPrekey}, true, nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, false, err
	}
	if signedBy(held, newID) {
		return &keys.PartyKeys{SignedPrekey: held.SignedPrekey}, false, nil
	}
	pk := &keys.PartyKeys{SignedPrekey: held.SignedPrekey}
	if err := pk.RotateSignedPrekey(newID); err != nil {
		return nil, false, err
	}
	pk.PreviousSignedPrekey = nil
	b, err := json.Marshal(pk)
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, false, err
	}
	return pk, true, nil
}

// retiredKey is the old identity key's entry on the rotation card, until now
// unless it carries an until already. The keys record gives it while its
// signed prekey is the old key's; once a stopped rotation committed the new
// key's, the card on the state gives it — that card lists the old key.
func (p *party) retiredKey(ctx context.Context, oldID *keys.Identity, pk *keys.PartyKeys, now time.Time) (card.Key, error) {
	if signedBy(pk, oldID) {
		old := card.New(oldID, pk, nil, nil, now).Keys[0]
		old.Until = &now
		return old, nil
	}
	want := keys.CurveText(oldID.PublicKey())
	oc, err := p.store.OwnCard(ctx)
	if err != nil {
		return card.Key{}, err
	}
	if oc.Present() {
		if c, err := card.Verify(oc.Details, p.root.Public()); err == nil {
			for _, old := range c.Keys {
				if old.Identity != want {
					continue
				}
				if old.Until == nil {
					old.Until = &now
				}
				return old, nil
			}
		}
	}
	return card.Key{}, fmt.Errorf("neither the keys record nor the card on the state carries identity key %s", want)
}

// signedBy reports whether pk's signed prekey carries id's signature.
func signedBy(pk *keys.PartyKeys, id *keys.Identity) bool {
	spk := pk.SignedPrekey
	return ecc.VerifySignature(id.KeyPair.PublicKey().PublicKey(), spk.KeyPair().PublicKey().Serialize(), spk.Signature())
}

// reseal copies every record a rotation moves — the roster, the keys and
// card records, each channel's record and activity, the rooms record and
// each room's state — from the old seal to the new one.
func reseal(ctx context.Context, from, to store.Backend, r *roster.Roster, out io.Writer) error {
	names := []string{roster.Key, store.KeysKey, store.OwnCardKey, roomsKey}
	for _, pe := range r.Peers {
		names = append(names, store.ChannelKey(pe.Channel), status.ActivityKey(pe.Channel))
	}
	if l, err := loadRooms(ctx, from); err != nil {
		return fmt.Errorf("re-seal %s: %w", roomsKey, err)
	} else {
		for _, ref := range l.Rooms {
			names = append(names, room.Key(ref.ID))
		}
	}
	n := 0
	for _, name := range names {
		moved, err := copyRecord(ctx, from, to, name)
		if err != nil {
			return fmt.Errorf("re-seal %s: %w", name, err)
		}
		if moved {
			n++
		}
	}
	fmt.Fprintf(out, "state re-sealed under the new identity key: %d records\n", n)
	return nil
}

// copyRecord copies one record from the old to the new backend at the same
// version, so another host's commit between the read and the write refuses
// and the copy is read again. It reports whether the record is on the new
// backend: absent records are skipped, and one the new backend opens already
// — a rotation completing a stopped one — stays as it is.
func copyRecord(ctx context.Context, from, to store.Backend, key string) (bool, error) {
	for try := 1; ; try++ {
		data, v, err := from.Load(ctx, key)
		if errors.Is(err, store.ErrCorrupt) {
			if moved, _, terr := to.Load(ctx, key); terr == nil && moved != nil {
				return true, nil
			}
		}
		if err != nil {
			return false, err
		}
		if data == nil {
			return false, nil
		}
		if _, err := to.Store(ctx, key, data, v); err == nil {
			return true, nil
		} else if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			return false, err
		}
	}
}
