package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/caoer/peer/internal/invite"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/sealed"
	"github.com/caoer/peer/internal/store"
)

// A feed is a room with one writer (design B § 1, § 6): its owner's state
// holds a link — a multi-use read token, a link key, the owner's idx — and
// every whole-room record of a v1 kind it seals carries a stanza to the link
// key at idx 65535 (roomConn.recipients). Anyone with the link reads: the
// link holder pulls with the read token, opens the link stanza, verifies
// every record under the owner's room signing key the link names, and keeps
// nothing beyond the link and its cursor. A new link revokes the old read
// token on the relay, so every old holder is cut off.

func cmdRoomLink(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("room link", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	rotateFlag := fl.Bool("rotate", false, "make a new link: the old one's holders are cut off")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer room link [--dir D] [--rotate] <room>")
		return 2
	}
	if err := runRoomLink(context.Background(), *dirFlag, fl.Arg(0), *rotateFlag, stdout); err != nil {
		fmt.Fprintf(stderr, "peer room link: %v\n", err)
		return 1
	}
	return 0
}

func cmdRoomFollow(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("room follow", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	nameFlag := fl.String("name", "", "the feed's local name (default the first 8 hex of its id)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer room follow [--dir D] [--name N] <feed link>")
		return 2
	}
	if err := runRoomFollow(context.Background(), *dirFlag, *nameFlag, fl.Arg(0), stdout); err != nil {
		fmt.Fprintf(stderr, "peer room follow: %v\n", err)
		return 1
	}
	return 0
}

// mintLink mints a feed link's read token with an admin token and draws its
// link key; the owner is this state's idx. The caller sets it on the state.
func mintLink(ctx context.Context, rc *relay.Client, id, token string, st *room.State) (room.Link, error) {
	minted, err := rc.AddMember(ctx, id, token, relay.RoleRead)
	if err != nil {
		return room.Link{}, fmt.Errorf("mint the link's read token: %w", err)
	}
	st.ObserveMembership(minted.Membership)
	key := make([]byte, room.LinkKeySize)
	if _, err := rand.Read(key); err != nil {
		return room.Link{}, err
	}
	return room.Link{Key: key, Token: minted.Token, Idx: uint16(minted.Idx), Owner: st.Idx()}, nil
}

// feedLink is the link as the owner's state holds it, naming the owner's
// room signing key from the roster.
func feedLink(ref roomRef, st *room.State) (invite.Feed, error) {
	l := st.Link()
	if l == nil {
		return invite.Feed{}, fmt.Errorf("room %s is not a feed: it has no link (peer room create --feed)", ref.Name)
	}
	owner := st.Member(l.Owner)
	if owner == nil {
		return invite.Feed{}, fmt.Errorf("room %s: the link's owner, idx %d, is out of the room: peer room link --rotate makes one naming you", ref.Name, l.Owner)
	}
	f := invite.Feed{Relay: ref.Relay, Room: ref.ID, Token: l.Token, Key: l.Key, Owner: owner.Sign()}
	return f, f.Check()
}

// runRoomLink prints a feed's link; --rotate makes a new one first (a new
// read token and link key, this party the owner) and revokes the old token.
func runRoomLink(ctx context.Context, dir, name string, rotate bool, out io.Writer) error {
	c, err := openJoined(ctx, dir, name, out)
	if err != nil {
		return err
	}
	if !c.st.Feed() {
		return fmt.Errorf("room %s is not a feed: it has no link (peer room create --feed)", c.ref.Name)
	}
	if err := c.requireAdmin("the link"); err != nil {
		return err
	}
	if rotate {
		if err := c.rotateLink(ctx); err != nil {
			return err
		}
	}
	c.finishLinkRevokes(ctx)
	f, err := feedLink(c.ref, c.st)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, f)
	return nil
}

// rotateLink mints the next link and commits it with the old link's idx
// queued for its revoke; another host's commit in between is reloaded and
// its link queued too, so no read token but the new one stays live.
func (c *roomConn) rotateLink(ctx context.Context) error {
	next, err := mintLink(ctx, c.rc, c.ref.ID, c.ref.Token, c.st)
	if err != nil {
		return fmt.Errorf("room %s: %w", c.ref.Name, err)
	}
	for try := 1; ; try++ {
		if old := c.st.Link(); old != nil && old.Idx != next.Idx {
			next.Revoke = append(old.Revoke, old.Idx)
		}
		if err := c.st.SetLink(next); err != nil {
			return err
		}
		err := c.st.Commit(ctx)
		if err == nil {
			fmt.Fprintf(c.out, "room %s: a new link (read idx %d); the old one is revoked next\n", c.ref.Name, next.Idx)
			return nil
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			return fmt.Errorf("room %s: the new link is minted at idx %d and not kept: %w", c.ref.Name, next.Idx, err)
		}
		if err := c.reload(ctx); err != nil {
			return err
		}
		next.Revoke = nil
	}
}

// finishLinkRevokes revokes the read tokens of the feed's earlier links
// (the relay's revoke is idempotent) and drops each revoked idx from the
// state; one the relay did not answer stays for the next round.
func (c *roomConn) finishLinkRevokes(ctx context.Context) {
	l := c.st.Link()
	if l == nil || len(l.Revoke) == 0 {
		return
	}
	var done []uint16
	for _, idx := range l.Revoke {
		v, err := c.rc.RemoveMember(ctx, c.ref.ID, c.ref.Token, int(idx))
		if err != nil {
			fmt.Fprintf(c.out, "room %s: the old link (read idx %d) is not revoked yet: %v\n", c.ref.Name, idx, err)
			continue
		}
		c.st.ObserveMembership(v)
		done = append(done, idx)
	}
	if len(done) == 0 {
		return
	}
	for try := 1; ; try++ {
		cur := c.st.Link()
		if cur == nil {
			return
		}
		cur.Revoke = slices.DeleteFunc(cur.Revoke, func(i uint16) bool { return slices.Contains(done, i) })
		if err := c.st.SetLink(*cur); err != nil {
			return
		}
		err := c.st.Commit(ctx)
		if err == nil {
			fmt.Fprintf(c.out, "room %s: the old link (read idx %v) is revoked; its holders are cut off\n", c.ref.Name, done)
			return
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			fmt.Fprintf(c.out, "room %s: the old link is revoked and the state does not say so yet: %v\n", c.ref.Name, err)
			return
		}
		if err := c.reload(ctx); err != nil {
			return
		}
	}
}

// closeLink is close's end of a feed's link: the current link's idx is
// queued for its revoke as a rotation queues the old one, then every queued
// revoke runs; one the relay did not answer stays queued for serve and the
// next close, and refuses the close.
func (c *roomConn) closeLink(ctx context.Context) error {
	for try := 1; ; try++ {
		l := c.st.Link()
		if l == nil || slices.Contains(l.Revoke, l.Idx) {
			break
		}
		l.Revoke = append(l.Revoke, l.Idx)
		if err := c.st.SetLink(*l); err != nil {
			return err
		}
		err := c.st.Commit(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			return fmt.Errorf("the link's revoke (read idx %d) is not queued: %w", l.Idx, err)
		}
		if err := c.reload(ctx); err != nil {
			return err
		}
	}
	c.finishLinkRevokes(ctx)
	if l := c.st.Link(); l != nil && len(l.Revoke) > 0 {
		return fmt.Errorf("the revoke of the link (read idx %v) did not land", l.Revoke)
	}
	return nil
}

// runRoomFollow reads a feed from its link alone: on a peer directory with
// no party it makes one (peer init), keeps the link and a cursor in the
// rooms record, and pulls the feed to head, delivering its records as room
// records; serve reads on. Following the new link of a feed this party was
// cut from reads on from its cursor.
func runRoomFollow(ctx context.Context, dir, name, link string, out io.Writer) error {
	f, err := invite.ParseFeed(link)
	if err != nil {
		return err
	}
	if dir, err = peerDir(dir); err != nil {
		return err
	}
	switch _, err := os.Stat(filepath.Join(dir, identityFile)); {
	case errors.Is(err, fs.ErrNotExist):
		party, err := initDir(dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "party %s in %s, made to hold the feed\n", party, dir)
	case err != nil:
		return err
	}
	p, err := openParty(dir)
	if err != nil {
		return err
	}
	var ref roomRef
	err = updateRooms(ctx, p.backend, func(l *roomList) error {
		r := l.byID(f.Room)
		switch {
		case r == nil:
			n := name
			if n == "" {
				n = newRoomName(l, f.Room)
			} else if l.byName(n) != nil {
				return fmt.Errorf("a room named %s exists already; pick another name", n)
			}
			l.Rooms = append(l.Rooms, roomRef{Name: n, ID: f.Room})
			r = &l.Rooms[len(l.Rooms)-1]
		case !r.Stage.followed() && !r.Stage.gone():
			return fmt.Errorf("room %s (%s): you are in it (%s) and read it as a member", r.Name, r.ID, r.Stage)
		}
		cursor := int64(-1)
		if r.Feed != nil {
			cursor = r.Feed.Cursor
		}
		*r = roomRef{Name: r.Name, ID: f.Room, Relay: f.Relay, Stage: stageFollowing, Token: f.Token,
			Feed: &followedFeed{Key: f.Key, Owner: f.Owner, Cursor: cursor}}
		ref = *r
		return nil
	})
	if err != nil {
		return err
	}
	sv, err := newServer(p, "", out)
	if err != nil {
		return err
	}
	fc, err := sv.openFeed(ref)
	if err != nil {
		return err
	}
	n, err := fc.pull(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "following feed %s (%s): %d records delivered; peer serve reads on\n", ref.Name, ref.ID, n)
	return nil
}

// feedConn is a followed feed opened for a pull: the link's stanza key and
// owner key, and the spool entries the next cursor commit settles.
type feedConn struct {
	sv      *server
	ref     roomRef
	rc      *relay.Client
	key     *ecdh.PrivateKey
	owner   ed25519.PublicKey
	pending []*store.Entry
}

func (sv *server) openFeed(ref roomRef) (*feedConn, error) {
	if ref.Feed == nil || len(ref.Feed.Owner) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("feed %s: the rooms record holds no link", ref.Name)
	}
	key, err := room.LinkSealKey(ref.Feed.Key, ref.ID)
	if err != nil {
		return nil, fmt.Errorf("feed %s: %w", ref.Name, err)
	}
	return &feedConn{sv: sv, ref: ref, rc: relay.New(ref.Relay, nil), key: key, owner: ed25519.PublicKey(ref.Feed.Owner)}, nil
}

func (c *feedConn) say(seq int64, format string, args ...any) {
	fmt.Fprintf(c.sv.out, "feed %s #%d: %s\n", c.ref.Name, seq, fmt.Sprintf(format, args...))
}

// pull reads the feed to head: each record opened, delivered through the
// room spool, and the cursor committed in the rooms record before the
// birth; another host's commit reloads the cursor. A revoked token marks
// the feed cut and answers errGone. It returns how many records it
// delivered.
func (c *feedConn) pull(ctx context.Context) (int, error) {
	n := 0
	for {
		l, err := loadRooms(ctx, c.sv.p.backend)
		if err != nil {
			return n, err
		}
		r := l.byID(c.ref.ID)
		if r == nil || r.Stage != stageFollowing || r.Token != c.ref.Token || r.Feed == nil {
			return n, nil // another command took the entry over
		}
		page, err := c.rc.PullRoom(ctx, c.ref.ID, c.ref.Token, r.Feed.Cursor)
		if errors.Is(err, relay.ErrRevoked) {
			r.Stage, r.Token = stageCut, ""
			if err := l.commit(ctx); err != nil {
				if errors.Is(err, store.ErrConflict) {
					continue
				}
				return n, err
			}
			return n, fmt.Errorf("feed %s: %w: its owner made a new link or closed the feed, and this one is revoked; peer room follow <the new link>", c.ref.Name, errGone)
		}
		if err != nil {
			return n, fmt.Errorf("feed %s: pull: %w", c.ref.Name, err)
		}
		if len(page.Records) == 0 {
			return n, nil
		}
		for _, rec := range page.Records {
			if rec.Seq <= r.Feed.Cursor {
				continue
			}
			if err := c.receive(rec); err != nil {
				c.sv.dropSpool(c.pending)
				c.pending = nil
				return n, err
			}
			r.Feed.Cursor = rec.Seq
			if err := l.commit(ctx); err != nil {
				c.sv.dropSpool(c.pending)
				c.pending = nil
				if !errors.Is(err, store.ErrConflict) {
					return n, err
				}
				c.say(rec.Seq, "another host advanced the cursor; reloading")
				break
			}
			pending := c.pending
			c.pending = nil
			n += len(pending)
			if err := c.sv.settleSpool(pending, c.ref.Name); err != nil {
				return n, err
			}
		}
	}
}

// receive reads one record as a link holder: the relay's idx and the
// header's agree; the signature verifies under the owner's key the link
// names; the link stanza opens with the link's key, against kh; the message
// names this room. A record with no link stanza — a membership record, a
// subset, a record from before the link — is passed over; a record of a v1
// kind is delivered as a room record.
func (c *feedConn) receive(rec relay.RoomRecord) error {
	if rec.Err != nil {
		c.say(rec.Seq, "%v", rec.Err)
		return nil
	}
	r, err := sealed.Parse(rec.Body)
	if err != nil {
		c.say(rec.Seq, "%v", err)
		return nil
	}
	h := r.Header
	switch {
	case h.Room != c.ref.ID:
		c.say(rec.Seq, "sealed for room %s", h.Room)
		return nil
	case int(h.Idx) != rec.Idx:
		c.say(rec.Seq, "the relay names writer idx %d and the record idx %d", rec.Idx, h.Idx)
		return nil
	}
	if err := r.Verify(c.owner); err != nil {
		c.say(rec.Seq, "from idx %d, not signed by the feed's owner: %v", h.Idx, err)
		return nil
	}
	plain, err := r.Open(relay.FeedIdx, c.key)
	switch {
	case errors.Is(err, sealed.ErrNoStanza):
		return nil
	case err != nil:
		c.say(rec.Seq, "from idx %d: %v", h.Idx, err)
		return nil
	}
	m, err := parseRoomMessage(plain)
	if err != nil {
		c.say(rec.Seq, "from idx %d: %v", h.Idx, err)
		return nil
	}
	if m.Group != c.ref.ID {
		c.say(rec.Seq, "from idx %d: the message names group %q", h.Idx, m.Group)
		return nil
	}
	if room.MembershipKind(m.Kind) {
		return nil
	}
	e, err := c.sv.spoolRoom(c.ref, rec.Seq, m, c.say)
	if e != nil {
		c.pending = append(c.pending, e)
	}
	return err
}

// serveFeed is serve's round for a followed feed.
func (sv *server) serveFeed(ctx context.Context, ref roomRef) error {
	fc, err := sv.openFeed(ref)
	if err != nil {
		return err
	}
	switch _, err := fc.pull(ctx); {
	case errors.Is(err, errGone):
		fmt.Fprintf(sv.out, "%v\n", err)
	case err != nil:
		return err
	}
	return nil
}
