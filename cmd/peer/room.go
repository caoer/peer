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
	"math"
	"slices"
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

// cmdRoom runs the room commands: create, add, members, remove, leave,
// handover, close, rotate, link, follow, inspect.
func cmdRoom(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: peer room create|add|members|remove|leave|handover|close|rotate|link|follow|inspect [flags] ...")
		return 2
	}
	switch args[0] {
	case "create":
		return cmdRoomCreate(args[1:], stdout, stderr)
	case "add":
		return cmdRoomAdd(args[1:], stdout, stderr)
	case "members":
		return cmdRoomMembers(args[1:], stdout, stderr)
	case "remove", "leave", "handover", "close", "rotate":
		return cmdRoomMember(args[0], args[1:], stdout, stderr)
	case "link":
		return cmdRoomLink(args[1:], stdout, stderr)
	case "follow":
		return cmdRoomFollow(args[1:], stdout, stderr)
	case "inspect":
		return cmdRoomInspect(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "peer room: unknown command %q (create, add, members, remove, leave, handover, close, rotate, link, follow, inspect)\n", args[0])
	return 2
}

func cmdRoomCreate(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("room create", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	relayFlag := fl.String("relay", "", "relay base, e.g. https://example.com/peer (default config.json relay)")
	loginFlag := fl.String("login", "", "ccc-pages owner login <user>:<token> (default config.json login)")
	addFlag := fl.String("add", string(room.AddAdmins), "who may add a member, fixed for the room's life: admins or members")
	feedFlag := fl.Bool("feed", false, "a feed: you alone write, members read, and a link lets anyone with it read")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer room create [--dir D] [--relay URL] [--login USER:TOKEN] [--add admins|members] [--feed] <name>")
		return 2
	}
	if err := runRoomCreate(context.Background(), *dirFlag, *relayFlag, *loginFlag, room.Add(*addFlag), *feedFlag, fl.Arg(0), stdout); err != nil {
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
// add and the creator's entry, folded and committed before the put. A feed
// mints its link's read token first and keeps the link in the state.
func runRoomCreate(ctx context.Context, dir, relayBase, login string, add room.Add, feed bool, name string, out io.Writer) error {
	if add != room.AddAdmins && add != room.AddMembers {
		return fmt.Errorf("--add %q: admins or members", add)
	}
	if feed && add != room.AddAdmins {
		return errors.New("a feed has one writer: --feed takes --add admins")
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
	if feed {
		link, err := mintLink(ctx, rc, created.ID, created.AdminToken, st)
		if err == nil {
			err = st.SetLink(link)
		}
		if err != nil {
			return fmt.Errorf("room %s (%s) is created and its feed link is not: %w", name, created.ID, err)
		}
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
	} else {
		fmt.Fprintf(out, "created room %s (%s), add: %s; you are idx 0, its admin (record #%d)\n", name, created.ID, add, seq)
	}
	if feed {
		f, err := feedLink(ref, st)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "feed link (anyone with it reads; peer room link --rotate cuts them off):\n%s\n", f)
	}
	return nil
}

// runRoomAdd starts an add (plan decision 1, the adder's order): over the
// confirmed channel to the peer it sends room-invite, and the rest — mint on
// room-accept, room-seat, the roster record on room-join, room-token — runs
// in serve as the peer's answers arrive. An add whose roster record landed
// but whose token never left is finished here by sending the token again;
// one whose seat went out and whose roster record has not landed sends the
// seat again, and the newcomer's room-join brings the rest; one minted and
// not yet checked waits for serve. A minted idx is never dropped: nothing is
// minted twice for one add.
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
	if ref.Read {
		// The relay mints for an admin token or, under add: members, a write
		// token; an invite from a read member would carry the roster to the
		// peer and then fail at the mint every time.
		return fmt.Errorf("room %s: you read in it and cannot add; its admin adds, or a write member when its add setting is members", ref.Name)
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
	if st.Feed() && role != relay.RoleRead {
		return fmt.Errorf("room %s is a feed: you alone write in it, and a member reads (peer room add --read)", ref.Name)
	}
	ch, err := p.store.Channel(ctx, pe.Channel)
	if err != nil {
		return err
	}
	party := keys.PartyID(ch.Root())
	switch pa := ref.add(pe.Channel); {
	case pa != nil && pa.Stage == addRostered:
		// The roster record landed and the token did not leave: send it now.
		if err := p.sendOnChannel(ctx, *pe, kindRoomToken, roomTokenMessage(ref.ID, pa), out); err != nil {
			return err
		}
		if err := dropPendingAdd(ctx, p.backend, ref.ID, pe.Channel); err != nil {
			return err
		}
		fmt.Fprintf(out, "room %s: sent %s the token for idx %d again\n", ref.Name, peerName, pa.Idx)
		return nil
	case pa != nil && pa.Stage == addSeated:
		// The idx is minted and the roster record has not landed: the seat
		// goes again, and the newcomer, seated at that idx, answers with its
		// room-join. A fresh invite here would drop the minted idx, which the
		// seated newcomer refuses anyway.
		if err := p.sendOnChannel(ctx, *pe, kindRoomSeat, roomSeat{Room: ref.ID, Idx: pa.Idx}, out); err != nil {
			return err
		}
		fmt.Fprintf(out, "room %s: %s holds idx %d; sent its seat again — its room-join brings the roster record, then the token\n", ref.Name, peerName, pa.Idx)
		return nil
	case pa != nil && pa.Stage == addMinted:
		// The idx is minted and serve has not checked the invite against the
		// room at the newcomer's from: serve sends the seat, or a fresh invite
		// when the room changed. A fresh invite from here would drop the idx.
		fmt.Fprintf(out, "room %s: %s holds idx %d; your serve sends its seat once the invite is checked against the room below #%d\n", ref.Name, peerName, pa.Idx, pa.From)
		return nil
	}
	for _, m := range st.Members() {
		if m.Party == party {
			return fmt.Errorf("room %s: %s is in it already, at idx %d", ref.Name, peerName, m.Idx)
		}
	}
	inv, sum, err := c.invite()
	if err != nil {
		return err
	}
	err = updateRooms(ctx, p.backend, func(l *roomList) error {
		cur := l.byID(ref.ID)
		if cur == nil {
			return fmt.Errorf("room %s left the rooms record under this command", ref.Name)
		}
		cur.dropAdd(pe.Channel)
		cur.Adds = append(cur.Adds, pendingAdd{Peer: peerName, Channel: pe.Channel, Role: role, Stage: addInvited, Invite: sum})
		return nil
	})
	if err != nil {
		return err
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
	if ref.Stage.gone() {
		fmt.Fprintf(out, "room %s (%s): %s\n", ref.Name, ref.ID, ref.Stage)
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
		case addMinted:
			fmt.Fprintf(out, "  adding %s: idx %d minted, its seat waits on the invite's check against the room below #%d\n", a.Peer, a.Idx, a.From)
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
	// names is each confirmed channel's peer name by party id (channelRoots).
	names map[string]string
	out   io.Writer
	// sv delivers each opened record of a v1 kind (roomdeliver.go): serve's
	// own, which births it, or the command's server a command's pull opens on
	// first use, which commits it to the room spool for serve to birth.
	sv *server
	// pending is the spool entries the next Commit settles.
	pending []*store.Entry
}

func (p *party) openRoom(ctx context.Context, ref roomRef, out io.Writer) (*roomConn, error) {
	st, err := room.Load(ctx, p.backend, ref.ID)
	if err != nil {
		return nil, err
	}
	ch, names, err := p.channelRoots(ctx)
	if err != nil {
		return nil, err
	}
	return &roomConn{p: p, ref: ref, rc: relay.New(ref.Relay, nil), st: st, ch: ch, names: names, out: out}, nil
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
// reloads the state and the pull goes on from its cursor. The relay's
// membership version is taken at head alone. A record whose delivery waits
// on a seat's session stops nothing: it is committed with the cursor and
// waits in the room spool (roomdeliver.go).
func (c *roomConn) pull(ctx context.Context) error { return c.pullBelow(ctx, math.MaxInt64) }

// pullBelow is pull stopped at the first record at seq below or past: the
// fold brought to the room a newcomer reading from below starts at
// (onRoomAccept's invite check). Stopped short of head, it takes no version.
func (c *roomConn) pullBelow(ctx context.Context, below int64) error {
	if c.sv == nil {
		sv, err := commandServer(c.p, c.out)
		if err != nil {
			return err
		}
		c.sv = sv
	}
	for {
		page, err := c.rc.PullRoom(ctx, c.ref.ID, c.ref.Token, c.st.Cursor())
		if errors.Is(err, relay.ErrRevoked) {
			// Removed by an admin, or the room closed: pulls stop here.
			return c.gone(ctx, stageRemoved)
		}
		if err != nil {
			return fmt.Errorf("room %s: pull: %w", c.ref.Name, err)
		}
		if len(page.Records) == 0 {
			// At head every record past the cursor is folded, and the
			// relay's membership version is the fold's. A page's version is
			// never taken before its records fold — a removal in it bumped
			// it — so a put never carries a version ahead of the fold: a pull
			// cut short puts at the folded one, takes the 409 and pulls again.
			if page.Membership <= c.st.Membership() {
				return nil
			}
			c.st.ObserveMembership(page.Membership)
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
			if rec.Seq >= below {
				return nil
			}
			if err := c.receive(rec); err != nil {
				// Nothing of this record is kept: its seen id and counter
				// go with the state as loaded.
				c.dropPending()
				if rerr := c.reload(ctx); rerr != nil {
					return rerr
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
		// The relay's at, never the header's: a key's retirement is read at
		// the moment the relay stored the record, not at the writer's word.
		res := c.st.Fold(room.Verified{Seq: rec.Seq, Idx: h.Idx, Kind: m.Kind, Body: m.Body, At: rec.At}, c.ch)
		c.report(rec.Seq, res)
		if slices.Contains(res.Updated, c.st.Idx()) {
			// An admin's roster entry carrying this party's own card — a
			// read member's rotation, an identity change — is where the
			// replaced seal key's roomcard landed (rule 3).
			c.st.Posted(rec.Seq)
		}
		if res.Folded() && (m.Kind == room.KindRoster || m.Kind == room.KindLeave) {
			// The membership notice reaches the agents as one record of
			// kind roster (contract § Kinds); handover and roomcard fold alone.
			return c.deliverRecord(rec.Seq, c.notice(m, res))
		}
		return nil
	}
	return c.deliverRecord(rec.Seq, m)
}

// notice is the roster delivery record for a folded roster or leave record:
// the record's id, writer and time, kind roster, to nobody (the whole room),
// and a body in plain words — who joined, renewed its card or left, by idx
// and party (with the peer name where this host holds its channel), and the
// members as they now stand.
func (c *roomConn) notice(m *roomMessage, res room.Result) *roomMessage {
	who := func(idx uint16, party string) string {
		s := fmt.Sprintf("idx %d %s", idx, party)
		switch {
		case idx == c.st.Idx():
			s += " (you)"
		case c.names[party] != "":
			s += " (" + c.names[party] + ")"
		}
		return s
	}
	var lines []string
	for _, idx := range res.Joined {
		if mem := c.st.Member(idx); mem != nil {
			lines = append(lines, who(idx, mem.Party)+" joined")
		}
	}
	for _, idx := range res.Updated {
		if mem := c.st.Member(idx); mem != nil {
			lines = append(lines, who(idx, mem.Party)+" renewed its room card")
		}
	}
	for _, idx := range res.Left {
		lines = append(lines, fmt.Sprintf("idx %d left", idx))
	}
	var members []string
	for _, mem := range c.st.Members() {
		members = append(members, who(mem.Idx, mem.Party))
	}
	lines = append(lines, fmt.Sprintf("members of room %s now: %s", c.ref.ID, strings.Join(members, ", ")))
	return &roomMessage{V: 1, ID: m.ID, From: m.From, Kind: deliver.KindRoster, At: m.At, Body: []byte(strings.Join(lines, "\n")), Group: c.ref.ID}
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

// membershipPost is one membership record to put: its kind and body, whether
// the put bumps the membership version (a removal record), and prep, which
// runs on the state at head before the fold — the rotation's key swap — and
// returns the body to post, or done when the state at head says the post is
// moot (another host rotated first).
type membershipPost struct {
	kind string
	body []byte
	bump bool
	prep func(st *room.State) (body []byte, done bool, err error)
}

// errMoot is a post the state at head made unnecessary.
var errMoot = errors.New("nothing to post")

// postMembership puts a membership record of this party's: to head first,
// then the record folded into the state and committed with its counter
// before the put (contract: own records never come back from the relay),
// then through the room outbox, sealed to the roster as it now stands and
// put. An entry the fold refuses refuses the record, nothing committed: the
// cap comes back with the member count. An error wrapping errQueued says the
// record is committed and waits in the room outbox.
func (c *roomConn) postMembership(ctx context.Context, kind string, body []byte) (int64, room.Result, error) {
	return c.post(ctx, membershipPost{kind: kind, body: body})
}

// post is postMembership with the record's bump flag and prep step.
func (c *roomConn) post(ctx context.Context, mp membershipPost) (int64, room.Result, error) {
	kind := mp.kind
	for try := 1; ; try++ {
		if err := c.pull(ctx); err != nil {
			return 0, room.Result{}, err
		}
		body := mp.body
		if mp.prep != nil {
			var done bool
			var err error
			if body, done, err = mp.prep(c.st); err != nil {
				return 0, room.Result{}, err
			}
			if done {
				return 0, room.Result{}, errMoot
			}
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
		if kind == room.KindRoster && len(res.Joined)+len(res.Updated)+len(res.Left) == 0 {
			// The fold at head already holds what this record says — a join
			// replayed after its record landed, a removal another admin
			// posted first: no ctr to spend, no notice for every member.
			return 0, res, errMoot
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
		seq, err := c.sendEntry(ctx, m, ctr, mp.bump)
		return seq, res, err
	}
}

// gone takes this party out of the room: the rooms record marks the stage —
// left, removed or closed — and forgets the token, the room state is
// dropped (its keys with it), and this host's waiting records for the room
// go with it. It returns errGone, which serve prints and goes on from.
func (c *roomConn) gone(ctx context.Context, stage roomStage) error {
	err := updateRooms(ctx, c.p.backend, func(l *roomList) error {
		if r := l.byID(c.ref.ID); r != nil && !r.Stage.gone() {
			r.Stage, r.Token, r.Adds, r.Removals, r.Handovers = stage, "", nil, nil, nil
		}
		return nil
	})
	if err != nil {
		return err
	}
	for try := 1; ; try++ {
		err := c.st.Drop(ctx)
		if err == nil || !errors.Is(err, store.ErrConflict) || try >= sendTries {
			if err != nil {
				fmt.Fprintf(c.out, "room %s: the room state is not dropped: %v\n", c.ref.Name, err)
			}
			break
		}
		if err := c.reload(ctx); err != nil {
			break
		}
	}
	c.ref.Stage, c.ref.Token = stage, ""
	if l, err := loadRooms(ctx, c.p.backend); err == nil {
		c.p.dropLeftRooms(l, io.Discard)
	}
	return fmt.Errorf("room %s: %w: %s", c.ref.Name, errGone, stage)
}

// errGone is a room this party is out of: pulls stop, the state is dropped.
var errGone = errors.New("you are out of the room")

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
