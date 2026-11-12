package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/store"
)

// pushConfig is config.json's push: how a running serve uses the relay's
// WebSocket push (wire contract § WebSocket push).
type pushConfig struct {
	// PullEvery is how many pushed frames serve takes on a channel or a room
	// before it pulls it anyway, so a lost frame with nothing behind it to
	// show the gap is read before the next round; default 10.
	PullEvery int `json:"pullEvery,omitempty"`
}

const defaultPullEvery = 10

// pullEvery is the frame count the config names, or the default.
func (c config) pullEvery() int {
	if c.Push.PullEvery <= 0 {
		return defaultPullEvery
	}
	return c.Push.PullEvery
}

// The reconnect backoff: doubling from backoffMin to backoffMax, jittered,
// and back to backoffMin after a socket that stayed open past backoffMax.
var (
	backoffMin = time.Second
	backoffMax = time.Minute
)

// loop is serve's life after start: a round every interval, and between
// rounds, unless once, the state page's live socket and the push socket of
// every served channel and every room — each frame taken as a pulled row or
// record is, and the channel or room pulled after every push.pullEvery
// frames and on every connect the relay does not resume (a channel's socket
// opened at its cursor carries the catch-up itself). A relay that never
// answers the upgrade leaves the rounds' pull as it was.
func (sv *server) loop(ctx context.Context, every time.Duration, once bool, stderr io.Writer) int {
	defer sv.p.feedStop()
	if !once {
		// The state page's live socket: the rounds and every push event read
		// the roster and channel records from its pushes, not from the page.
		if w, ok := sv.p.backend.(store.Watcher); ok {
			wctx, stop := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				w.Watch(wctx, sv.out)
			}()
			defer func() {
				stop()
				<-done
			}()
		}
		sv.push = newPusher(ctx, sv)
		defer sv.push.stop()
	}
	for {
		if err := sv.round(ctx); err != nil {
			if ctx.Err() != nil {
				return 0
			}
			fmt.Fprintf(stderr, "peer serve: %v\n", err)
			if once {
				return 1
			}
		}
		if once || !sv.wait(ctx, every) {
			return 0
		}
	}
}

// wait takes pushed frames until the next round is due; false when serve
// is stopping. Every event is handled here, on serve's one goroutine, as
// the rounds are: the sockets' goroutines only read.
func (sv *server) wait(ctx context.Context, every time.Duration) bool {
	sv.push.track(ctx)
	t := time.NewTimer(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		case ev := <-sv.push.events:
			sv.push.handle(ctx, ev)
		}
	}
}

// pusher holds a push socket per served channel and per room this party
// is in (roompush.go).
type pusher struct {
	sv     *server
	ctx    context.Context
	events chan pushEvent
	socks  map[pushKey]*pushSocket
	wg     sync.WaitGroup
}

// pushKey names one socket: a channel's by its id, or a room's.
type pushKey struct {
	room bool
	id   string
}

type pushSocket struct {
	cancel context.CancelFunc
	// token is the room token the socket was opened with: a room whose
	// token changes is opened again under the new one.
	token string
	// name is the channel's roster name when it was opened, for the lines
	// an event that reads nothing prints.
	name string
	// frames is how many frames were taken since the channel or room was
	// last pulled.
	frames int
	// open is set from the socket's open to its close; atHead says the last
	// pull of the channel or room, on any path, read the relay to its end;
	// seen is the highest seq a frame carried. The three together say the
	// socket has kept the channel or room current (rests).
	open   bool
	atHead bool
	seen   int64
}

// rests reports whether a round may leave the channel or room k unpulled:
// its socket is open, its last pull read to the relay's end, and cursor is
// at or past every frame the socket carried — a frame left untaken (a held
// card, a seat not yet on the root, a failed step) keeps the round pulling.
// The open's pull and every gap are pulled by the socket's own path; what
// the round would read is already here. nil under --once.
func (ps *pusher) rests(k pushKey, cursor int64) bool {
	if ps == nil {
		return false
	}
	s := ps.socks[k]
	return s != nil && s.open && s.atHead && cursor >= s.seen
}

// pulled records whether a pull of k read the relay to its end.
func (ps *pusher) pulled(k pushKey, atHead bool) {
	if ps == nil {
		return
	}
	if s := ps.socks[k]; s != nil {
		s.atHead = atHead
	}
}

// note tracks the socket's state from the event about to be handled.
func (s *pushSocket) note(ev pushEvent) {
	switch ev.kind {
	case pushOpen:
		s.open = true
	case pushClosed, pushDown, pushGone:
		s.open = false
	case pushFrame:
		seq := ev.rec.Seq
		if ev.key.room {
			seq = ev.roomRec.Seq
		}
		s.seen = max(s.seen, seq)
	}
}

type pushKind int

const (
	pushOpen   pushKind = iota // the socket is open: pull first, unless resumed
	pushFrame                  // one envelope or room record pushed
	pushSynced                 // a resumed socket's catch-up is done
	pushClosed                 // the socket closed; reconnecting
	pushDown                   // the upgrade failed, first of a streak; trying again
	pushGone                   // the relay refused the token, channel or room: no more reconnects
)

type pushEvent struct {
	kind pushKind
	key  pushKey
	// resumed: on pushOpen, the socket carries the catch-up from the cursor
	// and ends it with pushSynced; more: on pushSynced, a pull page remains.
	resumed, more bool
	rec           relay.Record
	roomRec       relay.RoomRecord
	err           error
}

// pushStream is one open socket: next blocks for the event its next frame
// carries.
type pushStream struct {
	next    func(context.Context) (pushEvent, error)
	close   func() error
	resumed bool
}

func newPusher(ctx context.Context, sv *server) *pusher {
	return &pusher{sv: sv, ctx: ctx, events: make(chan pushEvent, 64), socks: map[pushKey]*pushSocket{}}
}

// stop closes every socket and waits for their goroutines.
func (ps *pusher) stop() {
	for _, s := range ps.socks {
		s.cancel()
	}
	ps.wg.Wait()
}

// track opens a socket for every served channel and every room without one
// and closes those no longer served, by the roster and the rooms record as
// they are now.
func (ps *pusher) track(ctx context.Context) {
	ps.trackChannels(ctx)
	ps.trackRooms(ctx)
}

func (ps *pusher) trackChannels(ctx context.Context) {
	r, err := roster.Load(ctx, ps.sv.p.backend)
	if err != nil {
		fmt.Fprintf(ps.sv.out, "push: %v\n", err)
		return
	}
	served := map[string]roster.Peer{}
	for _, pe := range r.Peers {
		if serves(pe) {
			served[pe.Channel] = pe
		}
	}
	for k, s := range ps.socks {
		if _, ok := served[k.id]; !ok && !k.room {
			s.cancel()
			delete(ps.socks, k)
		}
	}
	for id, pe := range served {
		k := pushKey{id: id}
		if ps.socks[k] != nil {
			continue
		}
		rc := relay.New(pe.Relay, nil)
		ps.open(k, "", pe.Name, func(ctx context.Context) (*pushStream, error) {
			// Opened at the channel's cursor, the socket brings what was put
			// since (wire § Push, resume); a cursor that cannot be read opens it
			// as before, and the open pulls.
			var s *relay.Socket
			var err error
			if ch, cerr := ps.sv.p.store.Channel(ctx, pe.Channel); cerr == nil {
				s, err = rc.Resume(ctx, pe.Channel, pe.Token, ch.Cursor())
			} else {
				s, err = rc.Subscribe(ctx, pe.Channel, pe.Token)
			}
			if err != nil {
				return nil, err
			}
			return &pushStream{
				next: func(ctx context.Context) (pushEvent, error) {
					rec, err := s.Next(ctx)
					if rec.Synced {
						return pushEvent{kind: pushSynced, more: rec.More}, err
					}
					return pushEvent{rec: rec}, err
				},
				close:   s.Close,
				resumed: s.Resumed(),
			}, nil
		}, func(err error) bool {
			return errors.Is(err, relay.ErrBadToken) || errors.Is(err, relay.ErrNoSuchChannel)
		})
	}
}

// open starts the goroutine that holds socket k.
func (ps *pusher) open(k pushKey, token, name string, dial func(context.Context) (*pushStream, error), final func(error) bool) {
	sctx, cancel := context.WithCancel(ps.ctx)
	ps.socks[k] = &pushSocket{cancel: cancel, token: token, name: name, seen: -1}
	ps.wg.Add(1)
	go func() {
		defer ps.wg.Done()
		ps.hold(sctx, k, dial, final)
	}()
}

// hold keeps one socket open until ctx ends or the relay refuses it for
// good (final), reconnecting with backoff after every close.
func (ps *pusher) hold(ctx context.Context, k pushKey, dial func(context.Context) (*pushStream, error), final func(error) bool) {
	backoff, down := backoffMin, false
	for ctx.Err() == nil {
		s, err := dial(ctx)
		if err == nil {
			down = false
			opened := time.Now()
			if ps.emit(ctx, pushEvent{kind: pushOpen, key: k, resumed: s.resumed}) {
				err = ps.read(ctx, s, k)
			}
			s.close()
			if time.Since(opened) > backoffMax {
				backoff = backoffMin
			}
		}
		switch {
		case ctx.Err() != nil:
			return
		case err != nil && final(err):
			ps.emit(ctx, pushEvent{kind: pushGone, key: k, err: err})
			return
		case err == nil:
		case down:
		default:
			kind := pushClosed
			if s == nil {
				kind, down = pushDown, true
			}
			ps.emit(ctx, pushEvent{kind: kind, key: k, err: err})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff/2 + rand.N(backoff/2+1)):
		}
		backoff = min(2*backoff, backoffMax)
	}
}

// read passes the socket's frames on until it fails or closes.
func (ps *pusher) read(ctx context.Context, s *pushStream, k pushKey) error {
	for {
		ev, err := s.next(ctx)
		if err != nil {
			return err
		}
		if ev.kind != pushSynced {
			ev.kind = pushFrame
		}
		ev.key = k
		if !ps.emit(ctx, ev) {
			return ctx.Err()
		}
	}
}

func (ps *pusher) emit(ctx context.Context, ev pushEvent) bool {
	select {
	case ps.events <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// handle acts on one socket event — a room's in handleRoom. A close, a
// failed upgrade, a resumed open and a catch-up with no page left read
// nothing; a frame is taken by the pulled row's path with the channel's
// roster entry as it is now, and an open the relay does not resume, a
// catch-up that left a page, and every push.pullEvery frames pull the
// channel.
func (ps *pusher) handle(ctx context.Context, ev pushEvent) {
	s := ps.socks[ev.key]
	if s == nil {
		return
	}
	s.note(ev)
	if ev.key.room {
		ps.handleRoom(ctx, ev, s)
		return
	}
	out := ps.sv.out
	switch ev.kind {
	case pushDown:
		fmt.Fprintf(out, "%s: no push socket (%v); pulling every round until one opens\n", s.name, ev.err)
		return
	case pushGone:
		fmt.Fprintf(out, "%s: the relay refused the push socket (%v); pulling every round\n", s.name, ev.err)
		return
	case pushClosed:
		fmt.Fprintf(out, "%s: push socket closed (%v); reconnecting\n", s.name, ev.err)
		return
	case pushOpen:
		s.frames = 0
		if ev.resumed {
			// The catch-up arrives as frames, then pushSynced.
			fmt.Fprintf(out, "%s: push socket open, resuming\n", s.name)
			return
		}
	case pushSynced:
		if !ev.more {
			// The socket carried every envelope past the cursor it opened at:
			// the channel is read to the relay's end, as a pull to [] leaves it.
			fmt.Fprintf(out, "%s: push socket caught up\n", s.name)
			ps.pulled(ev.key, true)
			return
		}
	}
	r, err := roster.Load(ctx, ps.sv.p.backend)
	if err != nil {
		fmt.Fprintf(out, "push: %v\n", err)
		return
	}
	pe := r.ByChannel(ev.key.id)
	if pe == nil || !serves(*pe) {
		return
	}
	switch ev.kind {
	case pushOpen:
		fmt.Fprintf(out, "%s: push socket open\n", pe.Name)
		err = ps.sv.serveChannel(ctx, *pe)
	case pushSynced:
		// A page is left past the catch-up: a pull reads it.
		s.frames = 0
		err = ps.sv.serveChannel(ctx, *pe)
	case pushFrame:
		s.frames++
		var pulled bool
		pulled, err = ps.sv.pushed(ctx, *pe, ev.rec)
		if err == nil && !pulled && s.frames >= ps.sv.p.cfg.pullEvery() {
			pulled, err = true, ps.sv.serveChannel(ctx, *pe)
		}
		if pulled {
			s.frames = 0
		}
	}
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(out, "%s: %v\n", pe.Name, err)
	}
}

// pushed takes one pushed frame by the path a pulled row takes and reports
// whether the channel was pulled instead. A frame at or before the cursor
// is a duplicate, dropped; one past the cursor's next seq is a gap, and the
// channel is pulled; so is a frame whose commit another host beat. A
// parked channel takes nothing: the round says why.
func (sv *server) pushed(ctx context.Context, pe roster.Peer, rec relay.Record) (bool, error) {
	c := &channelServe{sv: sv, pe: pe, rc: relay.New(pe.Relay, nil)}
	if err := c.load(ctx); err != nil {
		return false, err
	}
	if held, _ := c.ch.Held(); held != nil {
		return false, nil
	}
	switch cur := c.ch.Cursor(); {
	case rec.Seq <= cur:
		return false, nil
	case rec.Seq > cur+1:
		return true, sv.serveChannel(ctx, pe)
	}
	err := c.receive(ctx, rec)
	switch {
	case errors.Is(err, store.ErrConflict):
		fmt.Fprintf(sv.out, "%s #%d: another host advanced the state; reloading\n", pe.Name, rec.Seq)
		return true, sv.serveChannel(ctx, pe)
	case errors.Is(err, errParked):
		return false, nil
	case errors.Is(err, errWait):
		fmt.Fprintf(sv.out, "%s: waiting at #%d: %v\n", pe.Name, rec.Seq, err)
		return false, nil
	}
	return false, err
}
