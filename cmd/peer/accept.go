package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
)

// cmdAccept joins the channel an invite link names: pin the inviter's root
// key, redeem the token, verify card #0, take a one-time prekey, run X3DH,
// send this party's card as #1 inside the session with the accept proof
// under the link secret, deposit prekeys, print the verification code and
// this party's id (design §3.4 step 2, §4). A refusal keeps nothing; the
// inviter re-invites.
func cmdAccept(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("accept", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	nameFlag := fl.String("name", "", "local name for the inviter (default its party id)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: peer accept [--dir D] [--name N] <link>")
		return 2
	}
	res, err := runAccept(context.Background(), *dirFlag, *nameFlag, fl.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "peer accept: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "code %s  your id %s\n", res.code, res.self)
	fmt.Fprintf(stdout, "joined %s (%s) on channel %s\n", res.name, res.party, res.channel)
	fmt.Fprintf(stdout, "read the code and your id back to %s in the chat the link came from; they confirm with both.\n", res.name)
	return 0
}

type acceptResult struct {
	name, party, self, channel, code string
}

func runAccept(ctx context.Context, dir, name, rawLink string) (*acceptResult, error) {
	now := time.Now()
	l, err := invite.Parse(rawLink, now)
	if err != nil {
		return nil, err
	}
	dir, err = peerDir(dir)
	if err != nil {
		return nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, err
	}
	party := keys.PartyID(l.Root)
	if name == "" {
		name = party
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return nil, err
	}
	// A previous accept of this link may have joined, kept its row and then
	// failed: the token on the row is this side's only way back to the
	// channel, so the handshake goes on from there instead of asking for a
	// link that cannot be issued again. With a session built there is nothing
	// left to redo — the host confirms with the code.
	var guest string
	if cur := r.ByChannel(l.Channel); cur != nil {
		if cur.State != roster.Accepted {
			return nil, fmt.Errorf("this invite was accepted already (peer %s)", cur.Name)
		}
		ch, err := p.store.Channel(ctx, l.Channel)
		if err != nil {
			return nil, err
		}
		has, err := ch.ContainsSession(ctx, session.Addr)
		if err != nil {
			return nil, err
		}
		if has {
			return acceptedResult(cur.Name, party, l, p), nil
		}
		name, guest = cur.Name, cur.Token
	}
	if err := nameTaken(r, name, " with --name"); err != nil {
		return nil, err
	}
	k, err := p.keys(ctx)
	if err != nil {
		return nil, err
	}

	rc := relay.New(l.Relay, nil)
	if guest == "" {
		guest, err = rc.Join(ctx, l.Channel, l.Token)
		if errors.Is(err, relay.ErrTokenUsed) {
			return nil, fmt.Errorf("the invite link was used already: ask %s for a new one", name)
		}
		if err != nil {
			return nil, fmt.Errorf("join: %w", err)
		}
	}
	recs, err := rc.Pull(ctx, l.Channel, guest, -1)
	if err != nil {
		return nil, fmt.Errorf("pull card: %w", err)
	}
	if len(recs) == 0 || recs[0].Seq != 0 || recs[0].Err != nil || recs[0].Env.Type != envelope.Card {
		return nil, errors.New("envelope #0 is not the inviter's card: refusing; ask for a new invite")
	}
	body, sig, err := envelope.UnpackCard(recs[0].Env.Body)
	if err != nil {
		return nil, err
	}
	signed := &card.Signed{Body: body, Sig: sig}
	c, err := card.Verify(signed, l.Root)
	if err != nil {
		return nil, fmt.Errorf("card #0 against the link's root key: %w; refusing", err)
	}
	key, err := session.CurrentKey(c)
	if err != nil {
		return nil, err
	}
	hostIdentity, err := keys.ParseCurve(key.Identity)
	if err != nil {
		return nil, err
	}
	// The card is the inviter's and the link is spent: keep the row with its
	// token before any of the work below can fail, so a failure there is
	// resumable by another peer accept with the same link. A refusal above
	// this line keeps nothing and the inviter re-invites.
	if err := roster.Update(ctx, p.backend, func(r *roster.Roster) error {
		r.Set(roster.Peer{Name: name, Channel: l.Channel, Relay: l.Relay, Side: roster.Guest, Token: guest, State: roster.Accepted})
		return nil
	}); err != nil {
		return nil, err
	}
	var opk *relay.Prekey
	if pk, ok, err := rc.TakePrekey(ctx, l.Channel, guest); err != nil {
		return nil, fmt.Errorf("take prekey: %w", err)
	} else if ok {
		opk = &pk
	}

	ch, err := p.store.Channel(ctx, l.Channel)
	if err != nil {
		return nil, err
	}
	ch.PinRoot(l.Root)
	ch.PinCard(signed)
	ch.SetCursor(0)
	ch.SetSecret(l.Secret)
	s := session.New(ch, k)
	if err := s.Establish(ctx, key, opk); err != nil {
		return nil, fmt.Errorf("establish session: %w; refusing", err)
	}
	own, _, announced, err := p.ownCard(ctx, false)
	if err != nil {
		return nil, err
	}
	m, err := session.CardMessage(p.partyID(), party, own)
	if err != nil {
		return nil, err
	}
	// The proof rides on the first card message alone: the host checks it
	// before any prompt, so a joiner without the secret never reaches a human.
	m.Proof = session.EncodeProof(session.Proof(l.Secret, l.Channel, l.Root, p.id.Party, hostIdentity, p.id.PublicKey()))
	pks, err := session.NewPrekeys(ctx, k, prekeysPerChannel)
	if err != nil {
		return nil, err
	}
	if err := k.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit party keys: %w", err)
	}
	// The deposit below follows the send that commits the channel, so the
	// count is recorded ahead of it; serve's first restock corrects it.
	ch.SetDeposited(len(pks))
	ch.SetAnnounced(announced)
	if _, err := s.Send(ctx, p.outbox, rc, guest, m); err != nil {
		var pe *session.PutError
		if errors.As(err, &pe) {
			// The token is spent and the card never arrived: the channel is abandoned.
			p.outbox.Remove(pe.Entry)
			return nil, fmt.Errorf("put card: %w; the invite cannot be retried, ask %s for a new one", pe.Err, name)
		}
		return nil, fmt.Errorf("send card: %w", err)
	}
	if _, err := rc.PutPrekeys(ctx, l.Channel, guest, pks); err != nil {
		return nil, fmt.Errorf("deposit prekeys: %w", err)
	}
	return acceptedResult(name, party, l, p), nil
}

// acceptedResult is what accept prints: the code of this invite and the
// guest's own id, read back together over the chat the link came on.
func acceptedResult(name, party string, l invite.Link, p *party) *acceptResult {
	return &acceptResult{
		name:    name,
		party:   party,
		self:    p.partyID(),
		channel: l.Channel,
		code:    session.Code(l.Channel, l.Root, p.id.Party, l.Secret),
	}
}

// relaysOf is the card's relay list: the party's own relay when it has one.
func relaysOf(cfg config) []string {
	if cfg.Relay == "" {
		return nil
	}
	return []string{cfg.Relay}
}
