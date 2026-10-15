package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// keysConfig is config.json's keys: the key lifecycle serve runs (design §3.2).
type keysConfig struct {
	// SignedPrekeyEvery is how old the signed prekey may grow before serve
	// replaces it — a Go duration such as "720h", the default (30 days).
	SignedPrekeyEvery string `json:"signedPrekeyEvery,omitempty"`
	// OneTimeMin is the one-time prekey count on a channel below which serve
	// deposits up to prekeysPerChannel again; default 5.
	OneTimeMin int `json:"oneTimeMin,omitempty"`
}

const (
	defaultSignedPrekeyEvery = 30 * 24 * time.Hour
	defaultOneTimeMin        = 5
)

// signedPrekeyEvery is the rotation interval the config names, or the default.
func (c config) signedPrekeyEvery() (time.Duration, error) {
	if c.Keys.SignedPrekeyEvery == "" {
		return defaultSignedPrekeyEvery, nil
	}
	d, err := time.ParseDuration(c.Keys.SignedPrekeyEvery)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: keys.signedPrekeyEvery %q is not a positive duration such as \"720h\"", configFile, c.Keys.SignedPrekeyEvery)
	}
	return d, nil
}

// oneTimeMin is the restock threshold the config names, or the default.
func (c config) oneTimeMin() int {
	if c.Keys.OneTimeMin <= 0 {
		return defaultOneTimeMin
	}
	return c.Keys.OneTimeMin
}

// rotateIfDue replaces the signed prekey when the current one is older than
// keys.signedPrekeyEvery and commits the party keys record under CAS; a
// conflict reloads and checks again, since another host may have rotated. It
// reports the rotation and returns whether one happened. The caller holds the
// root key: the new key is announced by the card, and nothing else can sign
// one.
func rotateIfDue(ctx context.Context, p *party, k *store.Keys, now time.Time, out io.Writer) (bool, error) {
	every, err := p.cfg.signedPrekeyEvery()
	if err != nil {
		return false, err
	}
	for try := 1; ; try++ {
		if now.Sub(k.PartyKeys.SignedPrekeyIssued()) < every {
			return false, nil
		}
		old := k.PartyKeys.SignedPrekey.ID()
		if err := k.PartyKeys.RotateSignedPrekey(p.id); err != nil {
			return false, err
		}
		err := k.Commit(ctx)
		if err == nil {
			fmt.Fprintf(out, "signed prekey rotated: %d → %d\n", old, k.PartyKeys.SignedPrekey.ID())
			// The card on the state names the new key from here; the
			// channels' announced marks fall behind it and serve resends.
			if _, err := p.signOwnCard(ctx, k.PartyKeys, now); err != nil {
				return true, err
			}
			return true, nil
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			return false, fmt.Errorf("rotate signed prekey: %w", err)
		}
		fresh, err := p.keys(ctx)
		if err != nil {
			return false, err
		}
		*k = *fresh
	}
}

// cmdKeys is `peer keys accept|reject <name>`: the human's answer to a peer's
// new identity key that serve holds (design §3.2: 有根签名的也先提示人再生效).
func cmdKeys(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "usage: peer keys accept [--dir D] <name> | peer keys reject [--dir D] <name>")
		return 2
	}
	if len(args) == 0 || (args[0] != "accept" && args[0] != "reject") {
		return usage()
	}
	verb := args[0]
	fl := flag.NewFlagSet("keys "+verb, flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	if err := fl.Parse(args[1:]); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		return usage()
	}
	var err error
	if verb == "accept" {
		err = runKeysAccept(context.Background(), *dirFlag, fl.Arg(0), stdout)
	} else {
		err = runKeysReject(context.Background(), *dirFlag, fl.Arg(0), stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "peer keys %s: %v\n", verb, err)
		return 1
	}
	return 0
}

// heldOf opens the party, the peer's channel and the card held on it.
func heldOf(ctx context.Context, dir, name string) (*party, roster.Peer, *store.Channel, *card.Signed, *card.Card, int64, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, roster.Peer{}, nil, nil, nil, 0, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, roster.Peer{}, nil, nil, nil, 0, err
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return nil, roster.Peer{}, nil, nil, nil, 0, err
	}
	pe := r.ByName(name)
	if pe == nil {
		return nil, roster.Peer{}, nil, nil, nil, 0, fmt.Errorf("no peer named %s", name)
	}
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return nil, roster.Peer{}, nil, nil, nil, 0, err
	}
	held, seq := ch.Held()
	if held == nil {
		return nil, roster.Peer{}, nil, nil, nil, 0, fmt.Errorf("nothing is held for %s: serve has not seen a card of theirs naming a new identity key", name)
	}
	c, err := card.Verify(held, ch.Root())
	if err != nil {
		return nil, roster.Peer{}, nil, nil, nil, 0, fmt.Errorf("the held card does not verify against %s's pinned root (%v): peer keys reject %s discards it", name, err, name)
	}
	return p, *pe, ch, held, c, seq, nil
}

// runKeysAccept applies the held card: the old session is deleted, the new
// card pinned — from here the peer's new identity key alone is trusted, and
// the old one only until the until the card gives it — and a session exists
// again: the peer's, when its first PreKey message is the record the channel
// waited at, else one built here from the peer's prekey (U7's accept path;
// prekey routing is symmetric, §6.1), carried by this party's card when the
// root is here and by the next peer send otherwise. A held card that does not
// supersede the pinned one is refused and nothing changes; peer keys reject
// discards it.
func runKeysAccept(ctx context.Context, dir, name string, out io.Writer) error {
	p, pe, ch, held, c, seq, err := heldOf(ctx, dir, name)
	if err != nil {
		return err
	}
	key, err := session.CurrentKey(c)
	if err != nil {
		return fmt.Errorf("the held card: %w", err)
	}
	if err := supersedes(ch.Card(), c); err != nil {
		return fmt.Errorf("the held card does not supersede the pinned one: %v; peer keys reject %s discards it", err, name)
	}
	newIdentity, err := keys.ParseCurve(key.Identity)
	if err != nil {
		return err
	}
	if err := ch.DeleteAllSessions(ctx); err != nil {
		return err
	}
	ch.PinCard(held)
	ch.ClearHeld()
	rc := relay.New(pe.Relay, nil)
	k, err := p.keys(ctx)
	if err != nil {
		return err
	}
	// The peer may have opened the new session already: the record the
	// channel waited at is then its first PreKey message under the new key.
	recs, err := rc.Pull(ctx, pe.Channel, pe.Token, ch.Cursor())
	if err != nil {
		return fmt.Errorf("pull: %w", err)
	}
	if len(recs) > 0 && recs[0].Err == nil && recs[0].Seq == seq {
		if got, err := session.PrekeyIdentity(recs[0].Env); err == nil && got == newIdentity {
			if err := ch.Commit(ctx); err != nil {
				return fmt.Errorf("commit: %w", err)
			}
			fmt.Fprintf(out, "accepted %s's new identity key %s: the old session is dropped; their new session is on the relay (#%d) and peer serve picks it up\n", name, key.Identity, seq)
			return nil
		}
	}
	var opk *relay.Prekey
	if pk, ok, err := rc.TakePrekey(ctx, pe.Channel, pe.Token); err != nil {
		return fmt.Errorf("take prekey: %w", err)
	} else if ok {
		opk = &pk
	}
	s := session.New(ch, k)
	if err := s.Establish(ctx, key, opk); err != nil {
		return fmt.Errorf("establish session: %w", err)
	}
	built := "a new one is built from their prekey"
	if opk == nil {
		built = "a new one is built from their signed prekey (they hold no one-time prekey on the channel)"
	}
	own, stale, announced, err := p.ownCard(ctx, true)
	if err != nil {
		if err := ch.Commit(ctx); err != nil {
			return fmt.Errorf("commit: %w", err)
		}
		fmt.Fprintf(out, "accepted %s's new identity key %s: the old session is dropped, %s; your next peer send carries it, and serve sends your card once it is on the state (%v)\n", name, key.Identity, built, err)
		return nil
	}
	if stale != "" {
		fmt.Fprintln(out, stale)
	}
	dm, err := session.CardMessage(p.partyID(), keys.PartyID(ch.Root()), own)
	if err != nil {
		return err
	}
	ch.SetAnnounced(announced)
	rcpt, err := s.Send(ctx, p.outbox, rc, pe.Token, dm)
	var putErr *session.PutError
	switch {
	case err == nil:
		fmt.Fprintf(out, "accepted %s's new identity key %s: the old session is dropped, %s; your card went out (#%d)\n", name, key.Identity, built, rcpt.Seq)
	case errors.As(err, &putErr):
		fmt.Fprintf(out, "accepted %s's new identity key %s: the old session is dropped, %s; your card is committed but the relay did not take it (%v) and stays in the outbox\n", name, key.Identity, built, putErr.Err)
	default:
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// runKeysReject discards the held card. The record it came in under is
// refused — the cursor moves past it when the channel waited there — and
// nothing else changes: the pinned card and the session stay as they are.
func runKeysReject(ctx context.Context, dir, name string, out io.Writer) error {
	_, _, ch, _, c, seq, err := heldOf(ctx, dir, name)
	if err != nil {
		return err
	}
	identity := "(no current key)"
	if key, err := session.CurrentKey(c); err == nil {
		identity = key.Identity
	}
	ch.ClearHeld()
	if seq > ch.Cursor() {
		ch.SetCursor(seq)
	}
	if err := ch.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	fmt.Fprintf(out, "rejected %s's new identity key %s: the card is discarded; the pinned card and the session stay as they are\n", name, identity)
	return nil
}

// holdLine is what serve prints for a channel waiting on the human.
func holdLine(name string, c *card.Card, seq int64) string {
	identity := "(no current key)"
	if key, err := session.CurrentKey(c); err == nil {
		identity = key.Identity
	}
	return fmt.Sprintf("%s: waiting at #%d: their card names a new identity key %s, issued %s, signed by their root; verify the change with them over a channel you trust, then run peer keys accept %s — peer keys reject %s discards it\n", name, seq, identity, c.Issued.Format(time.RFC3339), name, name)
}

// supersedes is nil when c, a root-signed card naming a new identity key,
// moves past the pinned card: issued after it, and with a current key the
// pinned card does not list with an until. Anything else is an older card of
// the peer's played again — whoever holds the key a rotation retired, and can
// put on the channel, would roll the rotation back to that key (design §3.2).
func supersedes(pinned *card.Signed, c *card.Card) error {
	if pinned == nil {
		return nil
	}
	var old card.Card
	if err := json.Unmarshal(pinned.Body, &old); err != nil {
		return fmt.Errorf("the pinned card does not read: %v", err)
	}
	if !c.Issued.After(old.Issued) {
		return fmt.Errorf("it was issued %s, not after the pinned card (%s)", c.Issued.Format(time.RFC3339), old.Issued.Format(time.RFC3339))
	}
	key, err := session.CurrentKey(c)
	if err != nil {
		return nil
	}
	for i := range old.Keys {
		if old.Keys[i].Until != nil && old.Keys[i].Identity == key.Identity {
			return fmt.Errorf("its current key %s is one the pinned card retires", key.Identity)
		}
	}
	return nil
}

// prekeyIdentityText is the identity key a PreKey envelope carries, in the
// card's text form, or "" for any other record.
func prekeyIdentityText(e envelope.Envelope) string {
	raw, err := session.PrekeyIdentity(e)
	if err != nil {
		return ""
	}
	return keys.CurveText(raw)
}
