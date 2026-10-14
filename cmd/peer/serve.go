package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/seats"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/status"
	"github.com/caoer/peer/internal/store"
)

// cmdServe pulls every channel with a session, decrypts, and delivers
// locally in decision 5's order: decrypt, spool outside the tree, commit the
// session state under CAS, birth the record from the spool. Any number of a
// party's hosts may serve one state: the commit winner alone births the
// record, a loser drops its spool entry and pulls again from the committed
// cursor, a crash after the commit replays the spool on the next start.
func cmdServe(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	deliverFlag := fl.String("deliver", "", "deliver into this directory: inbox/<id>.md and quarantine/<id>.md (default config.json deliver, else <dir>/deliver)")
	once := fl.Bool("once", false, "pull every channel once and exit")
	every := fl.Duration("every", 30*time.Second, "pull interval")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: peer serve [--dir D] [--deliver DIR] [--once] [--every 30s]")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sv, err := openServer(*dirFlag, *deliverFlag, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "peer serve: %v\n", err)
		return 1
	}
	if err := sv.openRoster(*every); err != nil {
		fmt.Fprintf(stderr, "peer serve: %v\n", err)
		return 1
	}
	if err := sv.start(ctx); err != nil {
		fmt.Fprintf(stderr, "peer serve: %v\n", err)
		return 1
	}
	for {
		if err := sv.round(ctx); err != nil {
			if ctx.Err() != nil {
				return 0
			}
			fmt.Fprintf(stderr, "peer serve: %v\n", err)
			if *once {
				return 1
			}
		}
		if *once {
			return 0
		}
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(*every):
		}
	}
}

// server is one host's serve: the party, its spool and delivery directory.
type server struct {
	p     *party
	spool *store.Journal
	dir   string
	out   io.Writer
	// beat is the serve interval and page the roster page, nil without one
	// (status.go).
	beat time.Duration
	page *status.Page
	// seats is the seat map under ucc (ucc.go), read again every round; nil
	// without ucc, when delivery is local into dir.
	seats *seats.Map
	// Test hooks, nil in production: beforeCommit runs once the spool entry
	// is written and before the CAS commit; beforeBirth once the commit
	// landed and before the record is born.
	beforeCommit, beforeBirth func(*store.Entry) error
}

func openServer(dir, deliverTo string, out io.Writer) (*server, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, err
	}
	if deliverTo == "" {
		deliverTo = p.cfg.Deliver
	}
	if deliverTo == "" {
		deliverTo = filepath.Join(dir, deliverDir)
	}
	spool, err := store.OpenJournal(filepath.Join(dir, spoolDir))
	if err != nil {
		return nil, err
	}
	sv := &server{p: p, spool: spool, dir: deliverTo, out: out}
	if err := sv.loadSeats(); err != nil {
		return nil, err
	}
	return sv, nil
}

// errSpool is a spool entry whose bytes are not a message: every replay
// would fail on it the same way.
var errSpool = errors.New("spool entry does not open")

// start finishes the spool births a crash cut (the outbox is every round's
// work, below). An entry that can never be born — its own address, kind or id
// refuses — is dropped with its reason, so one such entry cannot stop
// delivery on every channel.
func (sv *server) start(ctx context.Context) error {
	return sv.p.store.ReplaySpool(ctx, sv.spool, func(e *store.Entry) error {
		sv.withAttachment(e)
		_, err := sv.birth(e)
		if errors.Is(err, deliver.ErrRecord) || errors.Is(err, errSpool) {
			fmt.Fprintf(sv.out, "dropped %s from the spool: %v\n", e.ID, err)
			return nil
		}
		return err
	})
}

// round replays the outbox, then pulls every channel that has a session
// once; one channel's failure does not stop the others. The outbox is a
// round's work, not a start's: under serve --every, a long-lived loop is all
// that runs, and a message whose put failed after its commit goes out on the
// next round, as peer send promises.
func (sv *server) round(ctx context.Context) error {
	if err := sv.loadSeats(); err != nil {
		return err
	}
	if err := sv.p.replayOutbox(ctx); err != nil {
		fmt.Fprintf(sv.out, "outbox: %v\n", err)
	}
	r, err := roster.Load(ctx, sv.p.backend)
	if err != nil {
		return err
	}
	var errs []error
	for _, pe := range r.Peers {
		if !serves(pe) {
			continue
		}
		if err := sv.serveChannel(ctx, pe); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", pe.Name, err))
		}
	}
	sv.writeRoster(ctx)
	return errors.Join(errs...)
}

// serves reports whether a channel has a session to serve: the guest's from
// accept on, the host's from confirm on — before confirm the host's first
// envelope is the guest's card, which confirm alone may open (design §3.4).
func serves(pe roster.Peer) bool {
	return pe.State == roster.Confirmed || (pe.Side == roster.Guest && pe.State == roster.Accepted)
}

// channelServe is one channel's pull: its snapshots, reloaded whenever
// another host's commit shows.
type channelServe struct {
	sv *server
	pe roster.Peer
	rc *relay.Client
	ch *store.Channel
	k  *store.Keys
}

func (sv *server) serveChannel(ctx context.Context, pe roster.Peer) error {
	c := &channelServe{sv: sv, pe: pe, rc: relay.New(pe.Relay, nil)}
	if err := c.load(ctx); err != nil {
		return err
	}
	// asked is the cursor a gap was already pulled again at, so one bad page
	// costs one extra pull and never loops.
	asked := int64(-2)
	for {
		recs, err := c.rc.Pull(ctx, pe.Channel, pe.Token, c.ch.Cursor())
		if err != nil {
			return fmt.Errorf("pull: %w", err)
		}
		if len(recs) == 0 {
			return nil
		}
		// A page that starts past the cursor's next seq would carry the
		// cursor over the envelopes between, which Pull never asks for again
		// — and the ratchet is still holding their message keys. So a gap is
		// asked for once more before it is believed; a gap the relay answers
		// twice is the relay's own and is reported, not hidden.
		if cur := c.ch.Cursor(); recs[0].Seq > cur+1 {
			if asked != cur {
				asked = cur
				fmt.Fprintf(sv.out, "%s: the relay answered #%d with the cursor at #%d; asking again\n", pe.Name, recs[0].Seq, cur)
				continue
			}
			fmt.Fprintf(sv.out, "%s: #%d to #%d are not on the relay; going on from #%d\n", pe.Name, cur+1, recs[0].Seq-1, recs[0].Seq)
		}
		for _, rec := range recs {
			err := c.receive(ctx, rec)
			if errors.Is(err, store.ErrConflict) {
				// Another host committed under this pull: its state and cursor
				// are the truth now. Reload and pull again from there.
				fmt.Fprintf(sv.out, "%s #%d: another host advanced the state; reloading\n", pe.Name, rec.Seq)
				if err := c.load(ctx); err != nil {
					return err
				}
				break
			}
			if errors.Is(err, session.ErrUntrusted) {
				// Parked: the cursor stays before this record, so the channel
				// has it still when a key change can be applied. Nothing
				// behind it is delivered until then, and every round says so.
				fmt.Fprintf(sv.out, "%s: waiting at #%d: %v; run peer card accept when you have verified their new card (U13)\n", pe.Name, rec.Seq, err)
				return nil
			}
			if errors.Is(err, errWait) {
				// Not consumed: the seat's session is not on this root yet
				// (uccBorder). The cursor stays and the next round pulls it again.
				fmt.Fprintf(sv.out, "%s: waiting at #%d: %v\n", pe.Name, rec.Seq, err)
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
}

func (c *channelServe) load(ctx context.Context) (err error) {
	if c.ch, err = c.sv.p.store.Channel(ctx, c.pe.Channel); err != nil {
		return err
	}
	c.k, err = c.sv.p.keys(ctx)
	return err
}

// commit writes the channel under CAS, then the party keys when a PreKey
// message spent a one-time prekey — after, so a crash between leaves a
// spare key, never a session without its key.
func (c *channelServe) commit(ctx context.Context, rec relay.Record) error {
	if err := c.ch.Commit(ctx); err != nil {
		return err
	}
	c.commitKeys(ctx, rec)
	return nil
}

// commitKeys writes the party keys when a PreKey message spent a one-time
// prekey. It runs after the channel commit landed, so its failure costs a
// spare key and nothing else: the spent key stays available, which is what a
// keys conflict already leaves. It is reported, never returned — the message
// whose channel commit landed is this host's to deliver (decision 5: a
// duplicate at most, never a loss).
func (c *channelServe) commitKeys(ctx context.Context, rec relay.Record) {
	if rec.Env.Type != envelope.Prekey {
		return
	}
	err := c.k.Commit(ctx)
	if errors.Is(err, store.ErrConflict) {
		// Another host committed the keys: its record is the truth, and the
		// key this message spent stays a spare there too.
		c.k, err = c.sv.p.keys(ctx)
	}
	if err != nil {
		fmt.Fprintf(c.sv.out, "%s #%d: party keys not committed (%v); the spent one-time prekey stays a spare\n", c.pe.Name, rec.Seq, err)
	}
}

// receive handles one pulled record. A record that does not open — at or
// before the cursor, a replay, malformed bytes, an unknown kind, an address
// that is not this channel's — is skipped with its reason and nothing kept
// but the cursor. A message is spooled, committed and born; a card is the
// session's own business.
func (c *channelServe) receive(ctx context.Context, rec relay.Record) error {
	s := session.New(c.ch, c.k)
	before := c.ch.Cursor()
	m, err := s.Receive(ctx, rec)
	if err == nil {
		err = c.checkAddress(m)
	}
	if err == nil && c.sv.seats != nil && m.Kind != session.KindCard {
		err = c.sv.uccBorder(m)
	}
	// A record the pinned card's keys cannot open is the shape of a peer's
	// key rotation (design §3.2): its new card and everything after it are
	// readable only by the version that applies a key change (U13). Moving
	// the cursor past them would consume that material for good, so the
	// channel waits here instead — serveChannel stops its pull. A seat whose
	// session is not on this root waits the same way (ucc.go).
	if errors.Is(err, session.ErrUntrusted) || errors.Is(err, errWait) {
		return err
	}
	if err != nil {
		if rec.Seq > c.ch.Cursor() {
			c.ch.SetCursor(rec.Seq)
		}
		if c.ch.Cursor() == before {
			return nil
		}
		fmt.Fprintf(c.sv.out, "skip %s #%d: %v\n", c.pe.Name, rec.Seq, err)
		return c.commit(ctx, rec)
	}
	if m.Kind == session.KindCard {
		return c.receiveCard(ctx, s, rec, m)
	}
	plain, err := m.Marshal()
	if err != nil {
		return err
	}
	e := &store.Entry{ID: m.ID, Channel: c.ch.Name(), Seq: rec.Seq, Type: rec.Env.Type.String(), Body: plain}
	if err := c.sv.spool.Add(e); err != nil {
		return err
	}
	if c.sv.beforeCommit != nil {
		if err := c.sv.beforeCommit(e); err != nil {
			c.sv.spool.Remove(e)
			return err
		}
	}
	// Only a conflict says the commit kept nothing: another host's state is
	// the truth, so this entry is this host's to drop and the message comes
	// again from the committed cursor. Any other error may have landed the
	// write — the pages backend answers after the PUT went out — so the entry
	// stays on disk for ReplaySpool's seen check, which births it once.
	if err := c.ch.Commit(ctx); err != nil {
		if errors.Is(err, store.ErrConflict) {
			c.sv.spool.Remove(e)
		}
		return err
	}
	if err := c.sv.spool.MarkCommitted(e); err != nil {
		return err
	}
	// The channel commit landed: cursor and seen id are durable, so nothing
	// after this may cost the message.
	c.commitKeys(ctx, rec)
	if c.sv.beforeBirth != nil {
		if err := c.sv.beforeBirth(e); err != nil {
			return err
		}
	}
	c.sv.withAttachment(e)
	if _, err := c.sv.birth(e); err != nil {
		return err
	}
	c.sv.noteIn(ctx, c.ch.Name(), rec.Seq, m.At, m.Kind)
	return c.sv.spool.Remove(e)
}

// checkAddress is the border, before the spool and the commit: from and to
// are addresses a record can carry, from names the channel's party, to names
// this party, and the id can name the record's file. A message that passes it
// can be born, so a committed spool entry never wedges a later start.
func (c *channelServe) checkAddress(m *session.Message) error {
	if !deliver.ValidAddr(m.From) {
		return fmt.Errorf("from %q is not a protocol address", m.From)
	}
	if !deliver.ValidAddr(m.To) {
		return fmt.Errorf("to %q is not a protocol address", m.To)
	}
	if from, _ := splitAddr(m.From); from != keys.PartyID(c.ch.Root()) {
		return fmt.Errorf("from %q is not the channel's party", m.From)
	}
	if to, _ := splitAddr(m.To); to != c.sv.p.partyID() {
		return fmt.Errorf("to %q is not this party", m.To)
	}
	if !deliver.ValidID(m.ID) {
		return fmt.Errorf("message id %q cannot name a file", m.ID)
	}
	return nil
}

// receiveCard pins a card the peer sent in-session once it is signed by the
// pinned root and lists the identity key the session uses; a card naming
// another key is a key change, reported and not applied (that is U13). A
// guest still waiting for the host's details card (state accepted) answers
// with its own details card and is confirmed.
func (c *channelServe) receiveCard(ctx context.Context, s *session.Session, rec relay.Record, m *session.Message) error {
	pc, signed, root, err := session.PeerCard(m)
	switch {
	case err != nil:
	case !bytes.Equal(root, c.ch.Root()):
		err = errors.New("card: signed by another root than the pinned one")
	case s.CheckIdentity(pc) != nil:
		err = errors.New("card: names an identity key the session does not use; a key change is not applied by this version")
	}
	if err != nil {
		fmt.Fprintf(c.sv.out, "skip %s #%d: %v\n", c.pe.Name, rec.Seq, err)
		return c.commit(ctx, rec)
	}
	c.ch.PinCard(signed)
	if !(c.pe.Side == roster.Guest && c.pe.State == roster.Accepted) {
		if err := c.commit(ctx, rec); err != nil {
			return err
		}
		fmt.Fprintf(c.sv.out, "card from %s pinned\n", c.pe.Name)
		return nil
	}
	// The host's details card: answer with ours (design §3.4, after the
	// pin on both sides). Send commits the channel — the pin, the cursor,
	// the ratchet — before the put. A host without the root key (it lives
	// off the fleet) pins and confirms without answering; its details card
	// goes out with peer card publish.
	answer := ""
	if own, err := c.sv.p.signedCard(c.k.PartyKeys, relaysOf(c.sv.p.cfg), true, time.Now()); err != nil {
		if err := c.commit(ctx, rec); err != nil {
			return err
		}
		answer = fmt.Sprintf("yours was not sent (%v): peer card publish sends it", err)
	} else {
		dm, err := session.CardMessage(c.sv.p.partyID(), keys.PartyID(root), own)
		if err != nil {
			return err
		}
		_, err = s.Send(ctx, c.sv.p.outbox, c.rc, c.pe.Token, dm)
		var putErr *session.PutError
		if errors.As(err, &putErr) {
			answer = fmt.Sprintf("yours did not reach the relay (%v) and stays in the outbox for replay", putErr.Err)
			err = nil
		}
		if err != nil {
			return err
		}
		c.commitKeys(ctx, rec)
	}
	err = roster.Update(ctx, c.sv.p.backend, func(r *roster.Roster) error {
		cur := r.ByName(c.pe.Name)
		if cur == nil || cur.Channel != c.pe.Channel {
			return fmt.Errorf("the roster entry for %s changed under this serve", c.pe.Name)
		}
		cur.State = roster.Confirmed
		return nil
	})
	if err != nil {
		return err
	}
	c.pe.State = roster.Confirmed
	if answer == "" {
		answer = "yours went out"
	}
	fmt.Fprintf(c.sv.out, "confirmed %s: their card with details is pinned, %s\n", c.pe.Name, answer)
	return nil
}

// birth writes a spooled message as its inbox or quarantine record; one
// that is there already stays as it is.
func (sv *server) birth(e *store.Entry) (string, error) {
	m, err := session.UnmarshalMessage(e.Body)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errSpool, err)
	}
	_, agent := splitAddr(m.To)
	dir, place := sv.dir, deliver.Route(m.Kind, sv.p.accepts(agent))
	if sv.seats != nil {
		if dir, place, err = sv.uccPlace(m); err != nil {
			return "", err
		}
	}
	path, born, err := deliver.Write(dir, place, m.ID, deliver.Record{From: m.From, To: m.To, Kind: m.Kind, At: m.At, Body: m.Body})
	if err != nil {
		return "", err
	}
	verb := "delivered"
	switch {
	case !born:
		verb = "already delivered"
	case place == deliver.Quarantine:
		verb = "quarantined"
	}
	fmt.Fprintf(sv.out, "%s %s %s → %s\n", verb, m.Kind, m.ID, path)
	return path, nil
}
