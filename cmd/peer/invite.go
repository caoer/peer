package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
)

// cmdInvite opens a channel for a peer: create it on the party's relay, put
// the card as envelope #0, deposit one-time prekeys, keep the link secret in
// the channel record, print the link (design §3.4 step 1, §4). The link is
// printed once and shown nowhere else.
func cmdInvite(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("invite", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	relayFlag := fl.String("relay", "", "relay base, e.g. https://example.com/peer (default config.json relay)")
	loginFlag := fl.String("login", "", "ccc-pages owner login <user>:<token> (default config.json login)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer invite [--dir D] [--relay URL] [--login USER:TOKEN] <name>")
		return 2
	}
	name := fl.Arg(0)
	link, err := runInvite(context.Background(), *dirFlag, *relayFlag, *loginFlag, name)
	if err != nil {
		fmt.Fprintf(stderr, "peer invite: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, link)
	fmt.Fprintf(stdout, "send this link to %s over a channel you already trust; it is valid for %s and joins once.\n", name, invite.Validity)
	fmt.Fprintf(stdout, "when %s reads back the 8-digit code and their id, run: peer confirm %s --code <code>; it shows their id to compare\n", name, name)
	return 0
}

func runInvite(ctx context.Context, dir, relayBase, login, name string) (string, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return "", err
	}
	p, err := openParty(dir)
	if err != nil {
		return "", err
	}
	if relayBase == "" {
		relayBase = p.cfg.Relay
	}
	if login == "" {
		login = p.cfg.Login
	}
	if relayBase == "" || login == "" {
		return "", fmt.Errorf("the relay and its owner login are needed: --relay and --login, or relay and login in %s", configFile)
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return "", err
	}
	if err := nameTaken(r, name, ""); err != nil {
		return "", err
	}
	k, err := p.keys(ctx)
	if err != nil {
		return "", err
	}
	now := time.Now()
	signed, _, _, err := p.ownCard(ctx, false)
	if err != nil {
		return "", err
	}
	cardEnv, err := envelope.PackCard(signed.Body, signed.Sig)
	if err != nil {
		return "", err
	}

	rc := relay.New(relayBase, nil)
	ch, err := rc.Create(ctx, login)
	if err != nil {
		return "", fmt.Errorf("create channel: %w", err)
	}
	if _, err := rc.Put(ctx, ch.ID, ch.HostToken, cardEnv); err != nil {
		return "", fmt.Errorf("put card: %w", err)
	}
	// The private halves are committed before the public halves are
	// deposited: a key the relay hands out must be one this party holds.
	pks, err := session.NewPrekeys(ctx, k, prekeysPerChannel)
	if err != nil {
		return "", err
	}
	if err := k.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit party keys: %w", err)
	}
	deposited, err := rc.PutPrekeys(ctx, ch.ID, ch.HostToken, pks)
	if err != nil {
		return "", fmt.Errorf("deposit prekeys: %w", err)
	}
	// The link secret lives in the channel record, committed before the
	// roster names the channel and before the link exists. A crash between
	// here and the roster write leaves an orphan record; the next invite for
	// the name mints a new channel.
	secret, err := invite.NewSecret()
	if err != nil {
		return "", err
	}
	rec, err := p.store.Channel(ctx, ch.ID)
	if err != nil {
		return "", err
	}
	rec.SetSecret(secret)
	rec.SetDeposited(deposited)
	rec.SetAnnounced(k.PartyKeys.SignedPrekey.ID())
	if err := rec.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit channel record: %w", err)
	}
	err = roster.Update(ctx, p.backend, func(r *roster.Roster) error {
		if err := nameTaken(r, name, ""); err != nil {
			return err
		}
		r.Set(roster.Peer{Name: name, Channel: ch.ID, Relay: relayBase, Side: roster.Host, Token: ch.HostToken, State: roster.Invited})
		return nil
	})
	if err != nil {
		return "", err
	}
	link, err := invite.New(relayBase, ch.ID, ch.InviteToken, p.id.Party, secret, now)
	if err != nil {
		return "", err
	}
	return link.String(), nil
}
