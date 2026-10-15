package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/seats"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/status"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/timeline"
)

// cmdServe pulls every channel with a session, decrypts, and delivers
// locally in decision 5's order: decrypt, spool outside the tree, commit the
// session state under CAS, birth the record from the spool. Any number of a
// party's hosts may serve one state: the commit winner alone births the
// record, a loser drops its spool entry and pulls again from the committed
// cursor, and a birth a crash or an error cut after the commit comes from the
// spool on the next round or start.
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
	return sv.loop(ctx, *every, *once, stderr)
}

// server is one host's serve: the party, its spool and delivery directory.
type server struct {
	p     *party
	spool *store.Journal
	// roomSpool is the room records' spool (roomdeliver.go).
	roomSpool *store.Journal
	dir       string
	out       io.Writer
	// command is a command's server (commandServer): the room records its
	// pulls pass stay in the room spool, committed, and serve births them.
	command bool
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
	// rotationReminded is set once this process has said that the signed
	// prekey is due and the root to announce a new one is elsewhere.
	rotationReminded bool
	// card is the state's card as this round read it (ownCard), nil before
	// the round's first read; cardReminded is set once this process has
	// printed that the card is absent, another identity's or stale.
	card         *roundCard
	cardReminded bool
	// push holds the channels' push sockets under a running serve (push.go);
	// nil under --once.
	push *pusher
	// unanswered is, by channel id, the one-time prekeys of a deposit that
	// failed without the relay's refusal (restock): the relay may hold them,
	// so the channel's next restock puts the same keys again.
	unanswered map[string][]relay.Prekey
}

// errParked is a channel that waits on the human: a card naming a new
// identity key is held on it, and nothing behind it is served until peer keys
// accept or reject answers.
var errParked = errors.New("channel parked on a key change")

func openServer(dir, deliverTo string, out io.Writer) (*server, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, err
	}
	return newServer(p, deliverTo, out)
}

// newServer is the party's serve: its spools and delivery directory.
func newServer(p *party, deliverTo string, out io.Writer) (*server, error) {
	if deliverTo == "" {
		deliverTo = p.cfg.Deliver
	}
	if deliverTo == "" {
		deliverTo = filepath.Join(p.dir, deliverDir)
	}
	spool, err := store.OpenJournal(filepath.Join(p.dir, spoolDir))
	if err != nil {
		return nil, err
	}
	roomSpool, err := store.OpenJournal(filepath.Join(p.dir, roomSpoolDir))
	if err != nil {
		return nil, err
	}
	sv := &server{p: p, spool: spool, roomSpool: roomSpool, dir: deliverTo, out: out, unanswered: map[string][]relay.Prekey{}}
	if err := sv.loadSeats(); err != nil {
		return nil, err
	}
	return sv, nil
}

// commandServer is the server a command's room pull runs under — peer send,
// room add, the membership commands. It does not know the delivery directory
// a running serve was started with (--deliver), so the records its pull
// passes are committed and left in the room spool: serve births them, at its
// next round or start, where it delivers.
func commandServer(p *party, out io.Writer) (*server, error) {
	sv, err := newServer(p, "", out)
	if err != nil {
		return nil, err
	}
	sv.command = true
	return sv, nil
}

// errSpool is a spool entry whose bytes are not a message: every replay
// would fail on it the same way.
var errSpool = errors.New("spool entry does not open")

// start finishes the spool births a crash cut, before the first round.
func (sv *server) start(ctx context.Context) error {
	sv.p.timelineRound(sv.out)
	if err := sv.replaySpool(ctx); err != nil {
		return err
	}
	return sv.replayRoomSpool(ctx)
}

// replaySpool births the spool entries whose commit landed and drops the
// rest (store.ReplaySpool); a room channel message's entry runs its step
// instead (receiveRoom). An entry that can never be born — its own address,
// kind or id refuses — is dropped with its reason, so one such entry cannot
// stop delivery on every channel.
func (sv *server) replaySpool(ctx context.Context) error {
	return sv.p.store.ReplaySpool(ctx, sv.spool, func(e *store.Entry) error {
		if m, err := session.UnmarshalMessage(e.Body); err == nil && session.RoomKind(m.Kind) {
			return sv.replayRoomStep(ctx, e, m)
		}
		plain := e.Body
		sv.withAttachment(e)
		_, err := sv.birth(e)
		if errors.Is(err, deliver.ErrRecord) || errors.Is(err, errSpool) {
			fmt.Fprintf(sv.out, "dropped %s from the spool: %v\n", e.ID, err)
			return nil
		}
		if err == nil {
			sv.timelineSpooled(ctx, e, plain)
		}
		return err
	})
}

// round replays the spool and the outbox, then pulls every channel that has
// a session once; one channel's failure does not stop the others. Both
// replays are a round's work, not a start's: under serve --every, a
// long-lived loop is all that runs. A message whose birth failed after its
// commit — the cursor already past it, so no pull brings it again — is born
// on the next round, and its entry is settled before the pull; a message
// whose put failed after its commit goes out on the next round, as peer send
// promises.
func (sv *server) round(ctx context.Context) error {
	sv.card = nil
	if err := sv.loadSeats(); err != nil {
		return err
	}
	sv.p.timelineRound(sv.out)
	if sv.seats != nil {
		sv.retryServices()
	}
	if err := sv.replaySpool(ctx); err != nil {
		fmt.Fprintf(sv.out, "spool: %v\n", err)
	}
	if err := sv.replayRoomSpool(ctx); err != nil {
		fmt.Fprintf(sv.out, "room spool: %v\n", err)
	}
	if err := sv.p.replayOutbox(ctx); err != nil {
		fmt.Fprintf(sv.out, "outbox: %v\n", err)
	}
	if err := sv.rotate(ctx); err != nil {
		fmt.Fprintf(sv.out, "signed prekey: %v\n", err)
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
	if err := sv.serveRooms(ctx); err != nil {
		errs = append(errs, err)
	}
	sv.writeRoster(ctx)
	return errors.Join(errs...)
}

// rotate replaces the signed prekey when it is older than
// keys.signedPrekeyEvery (design §3.2: serve rotates it, no human). The new
// key is announced by the card, which the root key alone signs: a host
// without root.json says so once and leaves the rotation to peer card
// publish, run where the root is.
func (sv *server) rotate(ctx context.Context) error {
	k, err := sv.p.keys(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	if sv.p.root != nil {
		_, err := rotateIfDue(ctx, sv.p, k, now, sv.out)
		return err
	}
	every, err := sv.p.cfg.signedPrekeyEvery()
	if err != nil {
		return err
	}
	if age := now.Sub(k.PartyKeys.SignedPrekeyIssued()); age >= every && !sv.rotationReminded {
		sv.rotationReminded = true
		fmt.Fprintf(sv.out, "signed prekey %d is %s old, past keys.signedPrekeyEvery %s: run peer card publish where %s is; it rotates and announces the new one\n", k.PartyKeys.SignedPrekey.ID(), age.Round(time.Hour), every, rootFile)
	}
	return nil
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
	if c.parked() {
		return nil
	}
	if err := c.finishConfirm(ctx); err != nil {
		fmt.Fprintf(sv.out, "%s: not confirmed yet: %v\n", pe.Name, err)
	}
	if err := c.announce(ctx); err != nil {
		fmt.Fprintf(sv.out, "%s: card not sent: %v\n", pe.Name, err)
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
			// Caught up: the channel's one-time prekeys are restocked here,
			// where the deposit count is current.
			return c.restock(ctx)
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
			if errors.Is(err, errParked) {
				// The peer's new card is held and the line is printed; nothing
				// behind it is served until the human answers.
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

// parked reports whether the channel waits on the human for a held card,
// and says so every round.
func (c *channelServe) parked() bool {
	held, seq := c.ch.Held()
	if held == nil {
		return false
	}
	pc, err := card.Verify(held, c.ch.Root())
	if err != nil {
		fmt.Fprintf(c.sv.out, "%s: waiting at #%d: the held card does not verify (%v); peer keys reject %s discards it\n", c.pe.Name, seq, err, c.pe.Name)
		return true
	}
	fmt.Fprint(c.sv.out, holdLine(c.pe.Name, pc, seq))
	return true
}

// finishConfirm finishes a guest's answer to the host's details card that an
// earlier round cut short (receiveCard). That answer commits the channel —
// the cursor past the card — and then writes the roster; a crash, a failed
// roster write or a commit whose answer was lost between the two leaves the
// channel accepted, and no later pull brings the card again. A message from
// the host that opened here is what shows it: the host has a session only
// from its own confirm on, and its details card is the first thing it sends
// in it. The guest's details card goes out again — the answer cut short may
// never have reached the relay, and the host pins a repeat as it pinned the
// first — and the roster says confirmed; a failure in either leaves the
// channel accepted for the next round to finish.
func (c *channelServe) finishConfirm(ctx context.Context) error {
	if c.pe.Side != roster.Guest || c.pe.State != roster.Accepted || !c.ch.Received() {
		return nil
	}
	answer := ""
	if own, announced, ok := c.sv.ownCard(ctx); !ok {
		answer = "; yours was not sent (no card on the state): peer card publish puts it there and serve sends it"
	} else {
		if err := c.sv.p.publish(ctx, c.pe, own, announced, c.sv.out); err != nil {
			return err
		}
		if err := c.load(ctx); err != nil {
			return err
		}
	}
	if err := c.confirm(ctx); err != nil {
		return err
	}
	fmt.Fprintf(c.sv.out, "confirmed %s: their messages open here, so their side is confirmed%s\n", c.pe.Name, answer)
	return nil
}

// confirm marks the guest's roster entry confirmed.
func (c *channelServe) confirm(ctx context.Context) error {
	err := roster.Update(ctx, c.sv.p.backend, func(r *roster.Roster) error {
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
	return nil
}

// announce sends this party's card on a confirmed channel whose last card
// carried another signed prekey than the one on the state — after a
// rotation, or never sent. The send commits the channel, so the snapshots
// are reloaded after it.
func (c *channelServe) announce(ctx context.Context) error {
	if c.pe.State != roster.Confirmed {
		return nil
	}
	own, announced, ok := c.sv.ownCard(ctx)
	if !ok || c.ch.Announced() == announced {
		return nil
	}
	if err := c.sv.p.publish(ctx, c.pe, own, announced, c.sv.out); err != nil {
		return err
	}
	return c.load(ctx)
}

// roundCard is the state's details card as one round read it.
type roundCard struct {
	own       *card.Signed
	announced uint32
	err       error
}

// ownCard is the state's details card, read once per round. Absent, or for
// another identity key than this party's, the rule is printed once per
// process and nothing is announced or answered until peer card publish
// runs; a stale signed prekey is a one-line reminder, the card still served.
func (sv *server) ownCard(ctx context.Context) (*card.Signed, uint32, bool) {
	if sv.card == nil {
		own, stale, announced, err := sv.p.ownCard(ctx, true)
		sv.card = &roundCard{own: own, announced: announced, err: err}
		if (err != nil || stale != "") && !sv.cardReminded {
			sv.cardReminded = true
			if err != nil {
				fmt.Fprintf(sv.out, "card: %v\n", err)
			} else {
				fmt.Fprintln(sv.out, stale)
			}
		}
	}
	return sv.card.own, sv.card.announced, sv.card.err == nil
}

// restock deposits one-time prekeys on the channel when the count the relay
// is believed to hold for this side falls below keys.oneTimeMin: up to
// prekeysPerChannel again, the private halves committed before the public
// halves go out (as invite and accept do), and the relay's count answer
// recorded. A deposit the relay refuses (refusedDeposit) stored none of the
// keys and takes them back out of the record. Any other failure — a
// transport error, a timeout, a 5xx — may come after the relay stored them:
// their private halves stay, the count stays as it was, and the channel's
// next restock puts the same keys again (the relay ignores an id it was given
// before). So every key the relay hands out has its private half here, and a
// relay that keeps failing does not fill the record with new keys.
func (c *channelServe) restock(ctx context.Context) error {
	min := c.sv.p.cfg.oneTimeMin()
	if c.ch.Deposited() >= min {
		return nil
	}
	pks := c.retryDeposit(ctx)
	retry := pks != nil
	if !retry {
		var err error
		if pks, err = session.NewPrekeys(ctx, c.k, prekeysPerChannel-c.ch.Deposited()); err != nil {
			return err
		}
		if err := c.k.Commit(ctx); err != nil {
			if errors.Is(err, store.ErrConflict) {
				// Another host committed the keys — its round restocks too.
				c.k, err = c.sv.p.keys(ctx)
			}
			return err
		}
	}
	count, err := c.rc.PutPrekeys(ctx, c.pe.Channel, c.pe.Token, pks)
	if err != nil {
		// A refusal of keys put again says nothing of the put that went
		// unanswered before it: those keys stay too.
		if retry || !refusedDeposit(err) {
			c.sv.unanswered[c.pe.Channel] = pks
			return fmt.Errorf("restock: %w; the relay may hold the %d keys, so they stay in the record and the next restock puts them again", err, len(pks))
		}
		for _, pk := range pks {
			c.k.RemovePreKey(ctx, pk.ID)
		}
		if cerr := c.k.Commit(ctx); cerr != nil {
			return fmt.Errorf("restock: %w; %d undeposited keys stay spares (%v)", err, len(pks), cerr)
		}
		return fmt.Errorf("restock: %w", err)
	}
	delete(c.sv.unanswered, c.pe.Channel)
	for try := 1; ; try++ {
		c.ch.SetDeposited(count)
		err := c.ch.Commit(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			return fmt.Errorf("restock: deposited %d, the relay holds %d, but the count is not recorded: %w", len(pks), count, err)
		}
		if c.ch, err = c.sv.p.store.Channel(ctx, c.pe.Channel); err != nil {
			return err
		}
	}
	fmt.Fprintf(c.sv.out, "%s: deposited %d one-time prekeys; the relay holds %d\n", c.pe.Name, len(pks), count)
	return nil
}

// retryDeposit is the channel's keys from a deposit that went unanswered,
// those the record still holds as they were put — a key spent since, or
// replaced by an identity rotation, is not put again; nil when none remain.
func (c *channelServe) retryDeposit(ctx context.Context) []relay.Prekey {
	var out []relay.Prekey
	for _, pk := range c.sv.unanswered[c.pe.Channel] {
		r, _ := c.k.LoadPreKey(ctx, pk.ID)
		if r != nil && bytes.Equal(r.KeyPair().PublicKey().Serialize(), pk.Pub) {
			out = append(out, pk)
		}
	}
	if out == nil {
		delete(c.sv.unanswered, c.pe.Channel)
	}
	return out
}

// refusedDeposit reports whether a prekey deposit failed on the relay's own
// refusal: a 4xx answer carrying a contract code, after which the relay holds
// none of the keys — it refuses before it stores, or rolls the store back
// (too_large).
func refusedDeposit(err error) bool {
	var re *relay.Error
	return errors.As(err, &re) && re.Code != "" && re.Status/100 == 4
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
	prekeys := len(c.k.PartyKeys.Prekeys)
	m, err := s.Receive(ctx, rec)
	if err == nil && rec.Env.Type == envelope.Prekey && len(c.k.PartyKeys.Prekeys) < prekeys {
		// The message spent one of the keys deposited on this channel.
		c.ch.SpendDeposit()
	}
	if err == nil {
		err = c.checkAddress(m)
	}
	if err == nil && c.sv.seats != nil && m.Kind != session.KindCard && !session.RoomKind(m.Kind) {
		err = c.sv.uccBorder(m)
	}
	// A record built under an identity key the pinned card does not list is
	// what a peer's key change looks like from here (design §3.2): its new
	// card comes first, in the new session. Read without trusting, verified
	// against the pinned root, held for the human; anything else under an
	// unlisted key is refused.
	if errors.Is(err, session.ErrUntrusted) {
		return c.probeKeyChange(ctx, rec, err)
	}
	// A seat whose session is not on this root waits, the cursor before the
	// record — serveChannel stops its pull (ucc.go).
	if errors.Is(err, errWait) {
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
		if err := c.receiveCard(ctx, s, rec, m); err != nil {
			return err
		}
		c.sv.p.writeTimeline(ctx, c.pe.Name, c.ch.Name(), timeline.In, rec.Seq, m)
		return nil
	}
	if session.RoomKind(m.Kind) {
		return c.receiveRoom(ctx, rec, m)
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
	// stays on disk for the next round's ReplaySpool seen check, which births
	// it once when the write landed and drops it when it did not.
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
	c.sv.p.writeTimeline(ctx, c.pe.Name, c.ch.Name(), timeline.In, rec.Seq, m)
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

// probeKeyChange reads a record the pinned card's keys refuse. A PreKey
// record whose message is the peer's card, signed by the pinned root, naming
// the identity key the record came under and superseding the pinned card, is
// held for the human and the channel waits before it: the cursor stays, so
// the record is there when peer keys accept has pinned the card and serve
// builds the session from it. Any other such record is refused and the cursor
// moves past it: a card that does not verify, a message that is not a card, a
// key the card does not name, an older card played again. The relay is
// untrusted and can put any PreKey record on a channel, so nothing it can
// forge or replay may stop the channel — only a root signature on a newer
// card holds it.
func (c *channelServe) probeKeyChange(ctx context.Context, rec relay.Record, cause error) error {
	refuse := func(why string) error {
		c.ch.SetCursor(rec.Seq)
		fmt.Fprintf(c.sv.out, "skip %s #%d: %s; refused\n", c.pe.Name, rec.Seq, why)
		return c.ch.Commit(ctx)
	}
	if rec.Env.Type != envelope.Prekey {
		return refuse(cause.Error())
	}
	// A throwaway snapshot that admits any key reads the record; it is never
	// committed, so the one-time prekey it spends stays in the record.
	probe, err := c.sv.p.store.Channel(ctx, c.pe.Channel)
	if err != nil {
		return err
	}
	probe.AdmitAnyIdentity()
	pk, err := c.sv.p.keys(ctx)
	if err != nil {
		return err
	}
	m, err := session.New(probe, pk).Receive(ctx, rec)
	if err != nil {
		return refuse(fmt.Sprintf("under an identity key the card does not list, and it does not open: %v", err))
	}
	if m.Kind != session.KindCard {
		return refuse(fmt.Sprintf("a %s under an identity key the card does not list; a key change begins with the new card", m.Kind))
	}
	pc, signed, root, err := session.PeerCard(m)
	if err != nil {
		return refuse(fmt.Sprintf("a card under a new identity key: %v", err))
	}
	if !bytes.Equal(root, c.ch.Root()) {
		return refuse("a card under a new identity key, signed by another root than the pinned one")
	}
	key, err := session.CurrentKey(pc)
	if err != nil {
		return refuse(fmt.Sprintf("a card under a new identity key: %v", err))
	}
	if got := prekeyIdentityText(rec.Env); got != key.Identity {
		return refuse("a card under a new identity key that does not name the key the record came under")
	}
	if err := supersedes(c.ch.Card(), pc); err != nil {
		return refuse(fmt.Sprintf("a card under a new identity key that does not supersede the pinned one: %v", err))
	}
	c.ch.Hold(signed, rec.Seq)
	if err := c.ch.Commit(ctx); err != nil {
		return err
	}
	fmt.Fprint(c.sv.out, holdLine(c.pe.Name, pc, rec.Seq))
	return errParked
}

// keyChange reports whether a card the peer sent in-session changes the
// identity key the session runs under: its current key is another, or it
// gives the session's key an until, past or future by this host's clock, so a
// rotation from a sender whose clock runs ahead reaches the human too (design
// §3.2: 先提示人再生效). Retirement by the clock is IsTrustedIdentity's.
func keyChange(ch *store.Channel, c *card.Card) bool {
	got, ok := ch.RemoteIdentity(session.Addr)
	if !ok {
		return true
	}
	inUse := func(k *card.Key) bool {
		raw, err := keys.ParseCurve(k.Identity)
		return err == nil && raw == got
	}
	cur, err := session.CurrentKey(c)
	if err != nil || !inUse(cur) {
		return true
	}
	for i := range c.Keys {
		if c.Keys[i].Until != nil && inUse(&c.Keys[i]) {
			return true
		}
	}
	return false
}

// receiveCard reads a card the peer sent in-session. Signed by the pinned
// root and naming the session's identity key as its current key, it
// refreshes the pin when it is not older than the pinned card — agents,
// relays, details, signed prekey, no human (design §3.3). Naming another
// current key, or giving the one in use an until (keyChange), it is a key
// change: skipped when it does not supersede the pinned card, else held for
// the human and the channel waits
// (§3.2: 先提示人再生效). A guest still waiting for the host's details card
// (state accepted) answers with its own details card and is confirmed.
func (c *channelServe) receiveCard(ctx context.Context, s *session.Session, rec relay.Record, m *session.Message) error {
	pc, signed, root, err := session.PeerCard(m)
	switch {
	case err != nil:
	case !bytes.Equal(root, c.ch.Root()):
		err = errors.New("card: signed by another root than the pinned one")
	}
	if err != nil {
		fmt.Fprintf(c.sv.out, "skip %s #%d: %v\n", c.pe.Name, rec.Seq, err)
		return c.commit(ctx, rec)
	}
	if keyChange(c.ch, pc) {
		if err := supersedes(c.ch.Card(), pc); err != nil {
			fmt.Fprintf(c.sv.out, "skip %s #%d: a card naming a new identity key that does not supersede the pinned one: %v\n", c.pe.Name, rec.Seq, err)
			return c.commit(ctx, rec)
		}
		c.ch.Hold(signed, rec.Seq)
		if err := c.commit(ctx, rec); err != nil {
			return err
		}
		fmt.Fprint(c.sv.out, holdLine(c.pe.Name, pc, rec.Seq))
		return errParked
	}
	if pinned := c.ch.Card(); pinned != nil {
		var old card.Card
		if err := json.Unmarshal(pinned.Body, &old); err == nil && pc.Issued.Before(old.Issued) {
			fmt.Fprintf(c.sv.out, "skip %s #%d: card issued %s is older than the pinned one (%s)\n", c.pe.Name, rec.Seq, pc.Issued.Format(time.RFC3339), old.Issued.Format(time.RFC3339))
			return c.commit(ctx, rec)
		}
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
	// goes out with peer card publish. Anything that cuts this short once the
	// commit landed is finished by the next round's finishConfirm.
	answer := ""
	if own, announced, ok := c.sv.ownCard(ctx); !ok {
		if err := c.commit(ctx, rec); err != nil {
			return err
		}
		answer = "yours was not sent (no card on the state): peer card publish puts it there and serve sends it"
	} else {
		dm, err := session.CardMessage(c.sv.p.partyID(), keys.PartyID(root), own)
		if err != nil {
			return err
		}
		c.ch.SetAnnounced(announced)
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
	if err := c.confirm(ctx); err != nil {
		return err
	}
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
		if row, ok := sv.serviceRow(m); ok {
			return "", sv.toService(row, m, e.Body, "")
		}
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
