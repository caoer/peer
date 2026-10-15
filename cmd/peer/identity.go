package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
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
// the identity) and a new identity.json is written. Without --yes it prints
// what that costs the fleet and refuses.
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

func runIdentityRotate(ctx context.Context, dir string, yes bool, out io.Writer) error {
	dir, err := peerDir(dir)
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
	k, err := p.keys(ctx)
	if err != nil {
		return err
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return err
	}
	sealed := p.cfg.State.Page != "" || p.cfg.State.Slug != ""
	oldIdentity := keys.CurveText(p.id.PublicKey())
	if !yes {
		printRotateCost(out, r, sealed, oldIdentity)
		return errNoYes
	}

	now := time.Now()
	newID, err := keys.GenerateIdentity(p.id.Party)
	if err != nil {
		return err
	}
	// The signed prekey under the new identity key, with the next id: the
	// card announces it and the keys record takes it in step 4.
	newPK := &keys.PartyKeys{SignedPrekey: k.PartyKeys.SignedPrekey}
	if err := newPK.RotateSignedPrekey(newID); err != nil {
		return err
	}

	// 1. The card: the old key with its until, then the new key — signed by
	// the root, the same card the state holds from here (every host's).
	old := card.New(p.id, k.PartyKeys, nil, nil, now).Keys[0]
	old.Until = &now
	public, details, err := p.buildOwnCard(newID, newPK, now, old)
	if err != nil {
		return err
	}
	newIdentity := keys.CurveText(newID.PublicKey())
	fmt.Fprintf(out, "new identity key %s; %s retires at %s\n", newIdentity, oldIdentity, now.UTC().Format(time.RFC3339))

	// 2. Out on every confirmed channel under the session in force: the peer
	// holds it for its human (U13's receiver) and rebuilds from our prekeys
	// after peer keys accept.
	for _, pe := range r.Peers {
		if pe.State != roster.Confirmed {
			continue
		}
		if err := p.publish(ctx, pe, details, newPK.SignedPrekey.ID(), out); err != nil {
			fmt.Fprintf(out, "%s: the card was not sent (%v); they learn the new key from your next session\n", pe.Name, err)
		}
	}

	// 3. The state under the new identity's seal: every record copied under
	// CAS, so a host that commits meanwhile is seen, not overwritten.
	newBackend, err := openBackend(dir, p.cfg, newID)
	if err != nil {
		return err
	}
	if sealed {
		names := []string{roster.Key, store.KeysKey, store.OwnCardKey}
		for _, pe := range r.Peers {
			names = append(names, store.ChannelKey(pe.Channel), status.ActivityKey(pe.Channel))
		}
		n := 0
		for _, name := range names {
			copied, err := copyRecord(ctx, p.backend, newBackend, name)
			if err != nil {
				return fmt.Errorf("re-seal %s: %w", name, err)
			}
			if copied {
				n++
			}
		}
		fmt.Fprintf(out, "state re-sealed under the new identity key: %d records\n", n)
	}

	// 4. Under the new identity: the keys record, every session dropped, the
	// card record.
	ns := store.New(newBackend, newID)
	nk, err := commitRotatedKeys(ctx, ns, k.PartyKeys, newPK)
	if err != nil {
		return fmt.Errorf("keys record: %w", err)
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

	// 5. The identity file: the old one kept beside it, retired.
	retired := filepath.Join(dir, identityFile+".retired-"+now.UTC().Format("20060102T150405Z"))
	if err := os.Rename(filepath.Join(dir, identityFile), retired); err != nil {
		return err
	}
	b, err := json.MarshalIndent(newID, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, identityFile), append(b, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s; the old one is %s\n", filepath.Join(dir, identityFile), filepath.Base(retired))
	fmt.Fprintf(out, "fleet: put the new %s where sops holds it and deploy; a host still holding the old one cannot open the state until then. Each peer runs peer keys accept <you> after checking the new key with you over a channel you trust.\n", identityFile)
	return nil
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

// copyRecord copies one record from the old to the new backend at the same
// version, so another host's commit between the read and the write refuses
// and the copy is read again. Absent records are skipped.
func copyRecord(ctx context.Context, from, to store.Backend, key string) (bool, error) {
	for try := 1; ; try++ {
		data, v, err := from.Load(ctx, key)
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
