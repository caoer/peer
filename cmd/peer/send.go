package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/timeline"
)

// cmdSend encrypts one message for a peer and puts it on the channel in
// decision 5's order (session.Send): encrypt, outbox, commit the session
// state, put, clear. A commit another host beat drops the ciphertext and
// re-encrypts from the fresh state; a put that fails after the commit
// leaves the message in the outbox, where the next send or serve puts it.
func cmdSend(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("send", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	kindFlag := fl.String("kind", session.KindText, "message kind: text task question answer doc file ack, or vnd.<party>.<name>")
	fromFlag := fl.String("from", "", "the sending agent's id on your card (default none: the party itself)")
	textFlag := fl.String("text", "", "the body (default --file, else stdin)")
	fileFlag := fl.String("file", "", "doc and file kinds: the file to attach; other kinds: read the body from this file")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer send [--dir D] [--kind K] [--from AGENT] [--text T | --file F] <name>[/<agent>]")
		return 2
	}
	if *kindFlag == session.KindDoc || *kindFlag == session.KindFile {
		if *fileFlag == "" || *textFlag != "" {
			fmt.Fprintf(stderr, "peer send: a %s message is a file: --file F, and no --text\n", *kindFlag)
			return 2
		}
		return printSent(stdout, stderr, func() (*sendResult, error) {
			return runSendFile(context.Background(), stderr, *dirFlag, fl.Arg(0), *fromFlag, *kindFlag, *fileFlag)
		})
	}
	var body []byte
	switch {
	case *textFlag != "" && *fileFlag != "":
		fmt.Fprintln(stderr, "peer send: --text and --file are one or the other")
		return 2
	case *textFlag != "":
		body = []byte(*textFlag)
	case *fileFlag != "":
		b, err := os.ReadFile(*fileFlag)
		if err != nil {
			fmt.Fprintf(stderr, "peer send: %v\n", err)
			return 1
		}
		body = b
	default:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(stderr, "peer send: stdin: %v\n", err)
			return 1
		}
		body = b
	}
	return printSent(stdout, stderr, func() (*sendResult, error) {
		return runSend(context.Background(), stderr, *dirFlag, fl.Arg(0), *fromFlag, *kindFlag, body)
	})
}

// printSent runs one send and prints its receipt or refusal.
func printSent(stdout, stderr io.Writer, send func() (*sendResult, error)) int {
	res, err := send()
	if err != nil {
		fmt.Fprintf(stderr, "peer send: %v\n", err)
		return 1
	}
	if res.putErr != nil {
		fmt.Fprintf(stderr, "peer send: %s is committed but the relay did not take it (%v); it stays in the outbox and goes out on the next peer send or peer serve\n", res.id, res.putErr)
		return 1
	}
	fmt.Fprintf(stdout, "sent %s to %s (%s, #%d)\n", res.id, res.to, res.kind, res.seq)
	return 0
}

type sendResult struct {
	id, to, kind string
	seq          int64
	putErr       error
}

// sendTries bounds the re-encrypts after another host's commit.
const sendTries = 5

func runSend(ctx context.Context, warn io.Writer, dir, target, fromAgent, kind string, body []byte) (*sendResult, error) {
	name, agent := splitAddr(target)
	if kind == session.KindCard {
		return nil, errors.New("a card goes out with peer card publish, not peer send")
	}
	if !session.ValidKind(kind) {
		return nil, fmt.Errorf("%w %q: a vendor kind is vnd.<party id>.<name>", session.ErrKind, kind)
	}
	// The receiver refuses an address its record cannot carry, so refuse it
	// here: nothing is kept and nothing reaches the peer's spool.
	if agent != "" && !deliver.ValidAgent(agent) {
		return nil, fmt.Errorf("agent %q in %q is not an agent id: letters, digits, dot, dash, underscore, at most 64", agent, target)
	}
	if fromAgent != "" && !deliver.ValidAgent(fromAgent) {
		return nil, fmt.Errorf("--from %q is not an agent id: letters, digits, dot, dash, underscore, at most 64", fromAgent)
	}
	p, pe, ch, err := sendTarget(ctx, dir, name)
	if err != nil {
		return nil, err
	}
	p.timelineRound(warn)
	if err := p.replayOutbox(ctx); err != nil {
		fmt.Fprintf(warn, "peer send: outbox: %v\n", err)
	}
	k, err := p.keys(ctx)
	if err != nil {
		return nil, err
	}
	to := keys.PartyID(ch.Root())
	if agent != "" {
		to += "/" + agent
	}
	from := p.partyID()
	if fromAgent != "" {
		from += "/" + fromAgent
	}
	m, err := session.NewMessage(from, to, kind, body)
	if err != nil {
		return nil, err
	}
	rc := relay.New(pe.Relay, nil)
	for try := 1; ; try++ {
		rcpt, err := session.New(ch, k).Send(ctx, p.outbox, rc, pe.Token, m)
		var putErr *session.PutError
		switch {
		case err == nil:
			p.noteOut(ctx, warn, pe.Channel, m.At)
			p.writeTimeline(ctx, pe.Name, pe.Channel, timeline.Out, rcpt.Seq, m)
			return &sendResult{id: m.ID, to: to, kind: kind, seq: rcpt.Seq}, nil
		case errors.As(err, &putErr):
			p.noteOut(ctx, warn, pe.Channel, m.At)
			p.timelinePending(pe, m)
			return &sendResult{id: m.ID, to: to, kind: kind, putErr: putErr.Err}, nil
		case errors.Is(err, store.ErrConflict) && try < sendTries:
			// Another host advanced the session: re-encrypt from its state.
			if ch, err = p.store.Channel(ctx, pe.Channel); err != nil {
				return nil, err
			}
			if k, err = p.keys(ctx); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
	}
}

// sendTarget is the party and the peer a send goes to, refused when there is
// no such peer or no session with it yet.
func sendTarget(ctx context.Context, dir, name string) (*party, *roster.Peer, *store.Channel, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return nil, nil, nil, err
	}
	pe := r.ByName(name)
	if pe == nil {
		return nil, nil, nil, fmt.Errorf("no peer named %s", name)
	}
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return nil, nil, nil, err
	}
	if has, _ := ch.ContainsSession(ctx, session.Addr); !has {
		if pe.Side == roster.Host {
			return nil, nil, nil, fmt.Errorf("no session with %s yet: they accept the link, then you run peer confirm %s", name, name)
		}
		return nil, nil, nil, fmt.Errorf("no session with %s yet", name)
	}
	return p, pe, ch, nil
}
