package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/sealed"
	"github.com/caoer/peer/internal/store"
)

// cmdRoom runs the room commands: create, add, members.
func cmdRoom(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: peer room create|add|members [flags] ...")
		return 2
	}
	switch args[0] {
	case "create":
		return cmdRoomCreate(args[1:], stdout, stderr)
	case "add":
		return cmdRoomAdd(args[1:], stdout, stderr)
	case "members":
		return cmdRoomMembers(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "peer room: unknown command %q (create, add, members)\n", args[0])
	return 2
}

func cmdRoomCreate(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("room create", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	relayFlag := fl.String("relay", "", "relay base, e.g. https://example.com/peer (default config.json relay)")
	loginFlag := fl.String("login", "", "ccc-pages owner login <user>:<token> (default config.json login)")
	addFlag := fl.String("add", string(room.AddAdmins), "who may add a member, fixed for the room's life: admins or members")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer room create [--dir D] [--relay URL] [--login USER:TOKEN] [--add admins|members] <name>")
		return 2
	}
	if err := runRoomCreate(context.Background(), *dirFlag, *relayFlag, *loginFlag, room.Add(*addFlag), fl.Arg(0), stdout); err != nil {
		fmt.Fprintf(stderr, "peer room create: %v\n", err)
		return 1
	}
	return 0
}

func cmdRoomAdd(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("room add", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	readFlag := fl.Bool("read", false, "add a read member: it pulls the room and puts nothing")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 2 || fl.Arg(0) == "" || fl.Arg(1) == "" {
		fmt.Fprintln(stderr, "usage: peer room add [--dir D] [--read] <room> <peer>")
		return 2
	}
	role := relay.RoleWrite
	if *readFlag {
		role = relay.RoleRead
	}
	if err := runRoomAdd(context.Background(), *dirFlag, fl.Arg(0), fl.Arg(1), role, stdout); err != nil {
		fmt.Fprintf(stderr, "peer room add: %v\n", err)
		return 1
	}
	return 0
}

func cmdRoomMembers(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("room members", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer room members [--dir D] <room>")
		return 2
	}
	if err := runRoomMembers(context.Background(), *dirFlag, fl.Arg(0), stdout); err != nil {
		fmt.Fprintf(stderr, "peer room members: %v\n", err)
		return 1
	}
	return 0
}

// runRoomCreate opens a room on the relay, births its state with this party
// at idx 0 and the add setting, and puts record #0: a roster record carrying
// add and the creator's entry, folded and committed before the put.
func runRoomCreate(ctx context.Context, dir, relayBase, login string, add room.Add, name string, out io.Writer) error {
	if add != room.AddAdmins && add != room.AddMembers {
		return fmt.Errorf("--add %q: admins or members", add)
	}
	dir, err := peerDir(dir)
	if err != nil {
		return err
	}
	p, err := openParty(dir)
	if err != nil {
		return err
	}
	if relayBase == "" {
		relayBase = p.cfg.Relay
	}
	if login == "" {
		login = p.cfg.Login
	}
	if relayBase == "" || login == "" {
		return fmt.Errorf("the relay and its owner login are needed: --relay and --login, or relay and login in %s", configFile)
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return err
	}
	if l.byName(name) != nil {
		return fmt.Errorf("a room named %s exists already; pick another name", name)
	}
	own, _, _, err := p.ownCard(ctx, false)
	if err != nil {
		return err
	}
	keysOwn, err := room.GenerateKeys()
	if err != nil {
		return err
	}
	rc := relay.New(relayBase, nil)
	created, err := rc.CreateRoom(ctx, login, string(add))
	if err != nil {
		return fmt.Errorf("create room: %w", err)
	}
	st, err := room.New(p.backend, created.ID, 0, add, keysOwn)
	if err != nil {
		return err
	}
	st.ObserveMembership(created.Membership)
	now := time.Now()
	rcard, err := st.OwnCard(now).Signed(p.id)
	if err != nil {
		return err
	}
	self := room.Entry{Idx: 0, Party: p.partyID(), Card: room.PartyCard{Body: own.Body, Sig: own.Sig}, RoomCard: rcard}
	body, err := json.Marshal(room.RosterBody{Add: add, Members: []room.Entry{self}})
	if err != nil {
		return err
	}
	m, err := newRoomMessage(p.partyID(), created.ID, room.KindRoster, body)
	if err != nil {
		return err
	}
	res := st.Fold(room.Verified{Seq: -1, Idx: 0, Kind: room.KindRoster, Body: body, At: m.At}, nil)
	if !res.Folded() || len(res.Joined) != 1 {
		return fmt.Errorf("record #0 does not fold: %s%s", res.Dropped, strings.Join(res.Refused, "; "))
	}
	ctr := st.NextCounter()
	if err := st.Commit(ctx); err != nil {
		return fmt.Errorf("room state: %w", err)
	}
	ref := roomRef{Name: name, ID: created.ID, Relay: relayBase, Stage: stageJoined, Token: created.AdminToken, Idx: 0, From: 0}
	err = updateRooms(ctx, p.backend, func(l *roomList) error {
		if l.byName(name) != nil {
			return fmt.Errorf("a room named %s exists already; pick another name", name)
		}
		l.Rooms = append(l.Rooms, ref)
		return nil
	})
	if err != nil {
		return err
	}
	c := &roomConn{p: p, ref: ref, rc: rc, st: st, out: out}
	seq, err := c.send(ctx, m, ctr)
	if err != nil {
		fmt.Fprintf(out, "created room %s (%s), add: %s; record #0 did not reach the relay (%v): peer serve puts it\n", name, created.ID, add, err)
		return nil
	}
	fmt.Fprintf(out, "created room %s (%s), add: %s; you are idx 0, its admin (record #%d)\n", name, created.ID, add, seq)
	return nil
}

// runRoomAdd starts an add (plan decision 1, the adder's order): over the
// confirmed channel to the peer it sends room-invite, and the rest — mint on
// room-accept, room-seat, the roster record on room-join, room-token — runs
// in serve as the peer's answers arrive. An add whose roster record landed
// but whose token never left is finished here by sending the token again.
func runRoomAdd(ctx context.Context, dir, roomName, peerName, role string, out io.Writer) error {
	dir, err := peerDir(dir)
	if err != nil {
		return err
	}
	p, err := openParty(dir)
	if err != nil {
		return err
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return err
	}
	ref := l.byName(roomName)
	if ref == nil {
		return fmt.Errorf("no room named %s", roomName)
	}
	if ref.Stage != stageJoined {
		return fmt.Errorf("room %s: you are not in it yet (%s)", ref.Name, ref.Stage)
	}
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return err
	}
	pe := r.ByName(peerName)
	if pe == nil {
		return fmt.Errorf("no peer named %s", peerName)
	}
	if pe.State != roster.Confirmed {
		return fmt.Errorf("%s is not a confirmed channel (%s): a room-invite goes only over a channel whose code was checked", peerName, pe.State)
	}
	c, err := p.openRoom(ctx, *ref, out)
	if err != nil {
		return err
	}
	if err := c.pull(ctx); err != nil {
		fmt.Fprintf(out, "room %s: not at head (%v); the invite carries the roster as this host holds it\n", ref.Name, err)
	}
	st := c.st
	if !st.IsAdmin(st.Idx()) && st.Add() != room.AddMembers {
		return fmt.Errorf("room %s: its add setting is admins and you are not in its admin set", ref.Name)
	}
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return err
	}
	party := keys.PartyID(ch.Root())
	if pa := ref.add(pe.Channel); pa != nil && pa.Stage == addRostered {
		// The roster record landed and the token did not leave: send it now.
		if err := p.sendOnChannel(ctx, *pe, kindRoomToken, roomTokenMessage(ref.ID, pa), out); err != nil {
			return err
		}
		if err := dropPendingAdd(ctx, p.backend, ref.ID, pe.Channel); err != nil {
			return err
		}
		fmt.Fprintf(out, "room %s: sent %s the token for idx %d again\n", ref.Name, peerName, pa.Idx)
		return nil
	}
	for _, m := range st.Members() {
		if m.Party == party {
			return fmt.Errorf("room %s: %s is in it already, at idx %d", ref.Name, peerName, m.Idx)
		}
	}
	err = updateRooms(ctx, p.backend, func(l *roomList) error {
		cur := l.byID(ref.ID)
		if cur == nil {
			return fmt.Errorf("room %s left the rooms record under this command", ref.Name)
		}
		cur.dropAdd(pe.Channel)
		cur.Adds = append(cur.Adds, pendingAdd{Peer: peerName, Channel: pe.Channel, Role: role, Stage: addInvited})
		return nil
	})
	if err != nil {
		return err
	}
	inv := roomInvite{Room: ref.ID, Relay: ref.Relay, Add: st.Add(), Admins: st.Admins()}
	for _, m := range st.Members() {
		inv.Roster = append(inv.Roster, m.Entry)
	}
	if err := p.sendOnChannel(ctx, *pe, kindRoomInvite, inv, out); err != nil {
		return err
	}
	fmt.Fprintf(out, "invited %s to room %s (%s); their serve accepts, and yours finishes the add: mint, seat, roster, token\n", peerName, ref.Name, role)
	return nil
}

// runRoomMembers prints the room's folded roster, each entry marked: you,
// matches your channel (a confirmed channel pins its root), or vouched by the
// admin (rule 4) — and the adds in flight.
func runRoomMembers(ctx context.Context, dir, name string, out io.Writer) error {
	dir, err := peerDir(dir)
	if err != nil {
		return err
	}
	p, err := openParty(dir)
	if err != nil {
		return err
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return err
	}
	ref := l.byName(name)
	if ref == nil {
		return fmt.Errorf("no room named %s", name)
	}
	if ref.Stage == stageInvited {
		fmt.Fprintf(out, "room %s (%s): invited; waiting for the adder's seat\n", ref.Name, ref.ID)
		return nil
	}
	st, err := room.Load(ctx, p.backend, ref.ID)
	if err != nil {
		return err
	}
	_, names, err := p.channelRoots(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "room %s (%s)  add: %s  you: idx %d\n", ref.Name, ref.ID, st.Add(), st.Idx())
	if ref.Stage == stageSeated {
		fmt.Fprintln(out, "  invited: seated, waiting for the room token (the adder posts the roster record, then sends it)")
	}
	for _, m := range st.Members() {
		var marks []string
		switch n, ok := names[m.Party]; {
		case m.Idx == st.Idx():
			marks = append(marks, "you")
		case ok:
			marks = append(marks, "matches your channel "+n)
		default:
			marks = append(marks, "vouched by the admin")
		}
		if st.IsAdmin(m.Idx) {
			marks = append(marks, "admin")
		}
		fmt.Fprintf(out, "  %d  %s  %s\n", m.Idx, m.Party, strings.Join(marks, ", "))
	}
	for _, a := range ref.Adds {
		switch a.Stage {
		case addInvited:
			fmt.Fprintf(out, "  adding %s: invited, waiting for their accept\n", a.Peer)
		case addSeated:
			fmt.Fprintf(out, "  adding %s: idx %d minted, waiting for their room card\n", a.Peer, a.Idx)
		case addRostered:
			fmt.Fprintf(out, "  adding %s: idx %d in the roster, token not sent: peer room add %s %s sends it\n", a.Peer, a.Idx, ref.Name, a.Peer)
		}
	}
	return nil
}

// roomMessage is a room record's plaintext (contract § Sealed record): v1's
// message plus group, to absent or the subset's party ids.
type roomMessage struct {
	V     int       `json:"v"`
	ID    string    `json:"id"`
	From  string    `json:"from"`
	To    []string  `json:"to,omitempty"`
	Kind  string    `json:"kind"`
	At    time.Time `json:"at"`
	Body  []byte    `json:"body"`
	Group string    `json:"group"`
}

func newRoomMessage(from, roomID, kind string, body []byte) (*roomMessage, error) {
	var r [16]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	return &roomMessage{
		V: 1, ID: base64.RawURLEncoding.EncodeToString(r[:]), From: from, Kind: kind,
		At: time.Now().UTC().Truncate(time.Millisecond), Body: body, Group: roomID,
	}, nil
}

func parseRoomMessage(b []byte) (*roomMessage, error) {
	var m roomMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("message: %w", err)
	}
	switch {
	case m.V != 1:
		return nil, fmt.Errorf("message version %d, want 1", m.V)
	case !deliver.ValidID(m.ID):
		return nil, fmt.Errorf("message id %q", m.ID)
	case m.Kind == "":
		return nil, errors.New("message has no kind")
	case !deliver.ValidAddr(m.From):
		return nil, fmt.Errorf("from %q is not a protocol address", m.From)
	}
	return &m, nil
}

// roomConn is one room opened for a command or a serve round: its rooms
// record entry, the relay, the state as loaded, and the confirmed channels
// the fold cross-checks entries against (rule 4).
type roomConn struct {
	p   *party
	ref roomRef
	rc  *relay.Client
	st  *room.State
	ch  room.Channels
	out io.Writer
	// sv delivers each opened record of a v1 kind (roomdeliver.go): serve's
	// own, or one a command's pull opens on first use — a pull that passes a
	// record delivers it, whoever runs it.
	sv *server
	// pending is the spool entries the next Commit settles.
	pending []*store.Entry
}

func (p *party) openRoom(ctx context.Context, ref roomRef, out io.Writer) (*roomConn, error) {
	st, err := room.Load(ctx, p.backend, ref.ID)
	if err != nil {
		return nil, err
	}
	ch, _, err := p.channelRoots(ctx)
	if err != nil {
		return nil, err
	}
	return &roomConn{p: p, ref: ref, rc: relay.New(ref.Relay, nil), st: st, ch: ch, out: out}, nil
}

func (c *roomConn) reload(ctx context.Context) (err error) {
	c.st, err = room.Load(ctx, c.p.backend, c.ref.ID)
	return err
}

func (c *roomConn) say(seq int64, format string, args ...any) {
	fmt.Fprintf(c.out, "room %s #%d: %s\n", c.ref.Name, seq, fmt.Sprintf(format, args...))
}

// pull reads the room to head in the contract's receiver order, folding the
// membership records, spooling the rest, and committing the state after each
// record, then birthing what the Commit carried; another host's commit
// reloads the state and the pull goes on from its cursor. A record whose
// delivery waits (errWait) stops the pull before it, the state as committed.
func (c *roomConn) pull(ctx context.Context) error {
	if c.sv == nil {
		sv, err := newServer(c.p, "", c.out)
		if err != nil {
			return err
		}
		c.sv = sv
	}
	for {
		page, err := c.rc.PullRoom(ctx, c.ref.ID, c.ref.Token, c.st.Cursor())
		if err != nil {
			return fmt.Errorf("room %s: pull: %w", c.ref.Name, err)
		}
		fresh := page.Membership > c.st.Membership()
		c.st.ObserveMembership(page.Membership)
		if len(page.Records) == 0 {
			if !fresh {
				return nil
			}
			if err := c.st.Commit(ctx); err != nil {
				if errors.Is(err, store.ErrConflict) {
					if err := c.reload(ctx); err != nil {
						return err
					}
					continue
				}
				return err
			}
			return nil
		}
		for _, rec := range page.Records {
			if rec.Seq <= c.st.Cursor() {
				continue
			}
			if err := c.receive(rec); err != nil {
				// Nothing of this record is kept: its seen id and counter
				// go with the state as loaded.
				c.dropPending()
				if rerr := c.reload(ctx); rerr != nil {
					return rerr
				}
				if errors.Is(err, errWait) {
					return fmt.Errorf("room %s: waiting at #%d: %w", c.ref.Name, rec.Seq, err)
				}
				return err
			}
			c.st.SetCursor(rec.Seq)
			if err := c.beforeCommit(); err != nil {
				c.dropPending()
				return err
			}
			if err := c.st.Commit(ctx); err != nil {
				if !errors.Is(err, store.ErrConflict) {
					// The write may have landed: the entries stay for the
					// next replay's seen check.
					c.pending = nil
					return err
				}
				c.dropPending()
				c.say(rec.Seq, "another host advanced the state; reloading")
				if err := c.reload(ctx); err != nil {
					return err
				}
				break
			}
			if err := c.settle(); err != nil {
				return err
			}
		}
	}
}

// receive reads one pulled record in the contract's order: the relay's idx
// and the header's agree; the signature verifies under the roster's key for
// that idx; the writer's counter (rule 10, reported, reading goes on); this
// party's stanza, opened with the current seal key, then the retired ones,
// against kh; the message's from is the roster's party at idx; dedupe by id.
// A membership record folds; a record of any other kind is delivered
// (deliverRecord, roomdeliver.go).
func (c *roomConn) receive(rec relay.RoomRecord) error {
	if rec.Err != nil {
		c.skip(rec.Seq, "%v", rec.Err)
		return nil
	}
	r, err := sealed.Parse(rec.Body)
	if err != nil {
		c.skip(rec.Seq, "%v", err)
		return nil
	}
	h := r.Header
	if h.Room != c.ref.ID {
		c.skip(rec.Seq, "sealed for room %s", h.Room)
		return nil
	}
	if int(h.Idx) != rec.Idx {
		c.skip(rec.Seq, "the relay names writer idx %d and the record idx %d", rec.Idx, h.Idx)
		return nil
	}
	w := c.st.Member(h.Idx)
	if w == nil {
		c.skip(rec.Seq, "from idx %d, which the roster does not hold", h.Idx)
		return nil
	}
	if err := r.Verify(w.Sign()); err != nil {
		c.skip(rec.Seq, "from idx %d: %v", h.Idx, err)
		return nil
	}
	// Rule 10 in one order (format review m4): a writer's first record is in
	// order whatever it carries; CheckCtr names a gap or a step back after it.
	last, ok := c.st.Counter(h.Idx)
	if inOrder := c.st.CheckCounter(h.Idx, h.Ctr); ok && !inOrder {
		c.skip(rec.Seq, "idx %d: %v", h.Idx, sealed.CheckCtr(last, h.Ctr))
	}
	keys := append([]*ecdh.PrivateKey{c.st.SealKey()}, c.st.RetiredSealKeys()...)
	plain, err := r.Open(c.st.Idx(), keys...)
	switch {
	case errors.Is(err, sealed.ErrNoStanza):
		return nil // a subset, a record sealed before this party was in
	case errors.Is(err, sealed.ErrStanza):
		c.st.NoteReported() // a retired key gone: counted, not said (error map)
		return nil
	case errors.Is(err, sealed.ErrKeyCommit):
		c.skip(rec.Seq, "mis-keyed record from idx %d, refused: %v", h.Idx, err)
		return nil
	case err != nil:
		c.skip(rec.Seq, "from idx %d: %v", h.Idx, err)
		return nil
	}
	m, err := parseRoomMessage(plain)
	if err != nil {
		c.skip(rec.Seq, "from idx %d: %v", h.Idx, err)
		return nil
	}
	if m.Group != c.ref.ID {
		c.skip(rec.Seq, "from idx %d: the message names group %q", h.Idx, m.Group)
		return nil
	}
	if party, _ := splitAddr(m.From); party != w.Party {
		c.skip(rec.Seq, "from %s, and the roster holds %s at idx %d", m.From, w.Party, h.Idx)
		return nil
	}
	if c.st.Seen(m.ID) {
		return nil
	}
	c.st.MarkSeen(m.ID, rec.Seq)
	if room.MembershipKind(m.Kind) {
		c.report(rec.Seq, c.st.Fold(room.Verified{Seq: rec.Seq, Idx: h.Idx, Kind: m.Kind, Body: m.Body, At: h.At}, c.ch))
		return nil
	}
	return c.deliverRecord(rec.Seq, m)
}

// skip reports a record serve sets aside, or reads on past, and counts it in
// the room state's reported count.
func (c *roomConn) skip(seq int64, format string, args ...any) {
	c.st.NoteReported()
	c.say(seq, format, args...)
}

// beforeCommit runs serve's test hook on each entry the Commit will carry.
func (c *roomConn) beforeCommit() error {
	if c.sv.beforeCommit == nil {
		return nil
	}
	for _, e := range c.pending {
		if err := c.sv.beforeCommit(e); err != nil {
			return err
		}
	}
	return nil
}

// report tells the human what a fold did and what it set aside, and counts
// both in the room state's dropped count (rules 7 and 4).
func (c *roomConn) report(seq int64, res room.Result) {
	if !res.Folded() {
		c.st.NoteDropped(1)
		c.say(seq, "dropped: %s", res.Dropped)
		return
	}
	c.st.NoteDropped(len(res.Refused))
	for _, r := range res.Refused {
		c.say(seq, "refused %s", r)
	}
	for _, idx := range res.Joined {
		if m := c.st.Member(idx); m != nil {
			c.say(seq, "idx %d joined: %s", idx, m.Party)
		}
	}
	for _, idx := range res.Left {
		c.say(seq, "idx %d left", idx)
	}
	for _, idx := range res.Admitted {
		c.say(seq, "idx %d is an admin", idx)
	}
}

// postMembership puts a membership record of this party's: to head first,
// then the record folded into the state and committed with its counter
// before the put (contract: own records never come back from the relay),
// then through the room outbox, sealed to the roster as it now stands and
// put. An entry the fold refuses refuses the record, nothing committed: the
// cap comes back with the member count. An error wrapping errQueued says the
// record is committed and waits in the room outbox.
func (c *roomConn) postMembership(ctx context.Context, kind string, body []byte) (int64, room.Result, error) {
	for try := 1; ; try++ {
		if err := c.pull(ctx); err != nil && !errors.Is(err, errWait) {
			return 0, room.Result{}, err
		}
		m, err := newRoomMessage(c.p.partyID(), c.ref.ID, kind, body)
		if err != nil {
			return 0, room.Result{}, err
		}
		res := c.st.Fold(room.Verified{Seq: -1, Idx: c.st.Idx(), Kind: kind, Body: body, At: m.At}, c.ch)
		if !res.Folded() {
			return 0, res, fmt.Errorf("room %s: %s", c.ref.Name, res.Dropped)
		}
		if len(res.Refused) > 0 {
			why := strings.Join(res.Refused, "; ")
			if strings.Contains(why, "would pass") {
				return 0, res, fmt.Errorf("room %s has %d members and its record would pass %d bytes sealed: %s", c.ref.Name, len(c.st.Members()), room.MaxSealed, why)
			}
			return 0, res, fmt.Errorf("room %s: %s", c.ref.Name, why)
		}
		ctr := c.st.NextCounter()
		if err := c.st.Commit(ctx); err != nil {
			if errors.Is(err, store.ErrConflict) && try < sendTries {
				if err := c.reload(ctx); err != nil {
					return 0, res, err
				}
				continue
			}
			if errors.Is(err, room.ErrCap) {
				return 0, res, fmt.Errorf("room %s has %d members: %w", c.ref.Name, len(c.st.Members()), err)
			}
			return 0, res, err
		}
		seq, err := c.send(ctx, m, ctr)
		return seq, res, err
	}
}

// putTries bounds the re-seals after a 409 stale_membership.
const putTries = 3

// channelRoots reads the confirmed channels' pins: rule 4's lookup from an
// identity key to the root the channel pins for it, and each pinned root's
// peer name for room members.
func (p *party) channelRoots(ctx context.Context) (room.Channels, map[string]string, error) {
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return nil, nil, err
	}
	ids := map[[32]byte]ed25519.PublicKey{}
	names := map[string]string{}
	for _, pe := range r.Peers {
		if pe.State != roster.Confirmed {
			continue
		}
		ch, err := p.store.Channel(ctx, pe.Channel)
		if err != nil {
			return nil, nil, err
		}
		root, signed := ch.Root(), ch.Card()
		if root == nil || signed == nil {
			continue
		}
		pc, err := card.Verify(signed, root)
		if err != nil {
			continue
		}
		names[keys.PartyID(root)] = pe.Name
		for i := range pc.Keys {
			if raw, err := keys.ParseCurve(pc.Keys[i].Identity); err == nil {
				ids[raw] = root
			}
		}
	}
	return func(id [32]byte) (ed25519.PublicKey, bool) {
		root, ok := ids[id]
		return root, ok
	}, names, nil
}
