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
	// PullEvery is how many pushed frames serve takes on a channel before it
	// pulls that channel anyway, so a lost frame with nothing behind it to
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
// rounds, unless once, every served channel's push socket — each frame
// taken as a pulled row is, the channel pulled on every connect and after
// every push.pullEvery frames. A relay that never answers the upgrade
// leaves the rounds' pull as it was.
func (sv *server) loop(ctx context.Context, every time.Duration, once bool, stderr io.Writer) int {
	if !once {
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

// pusher holds a push socket per served channel.
type pusher struct {
	sv     *server
	ctx    context.Context
	events chan pushEvent
	socks  map[string]*pushSocket // by channel id
	wg     sync.WaitGroup
}

type pushSocket struct {
	cancel context.CancelFunc
	// frames is how many frames were taken since the channel was last pulled.
	frames int
}

type pushKind int

const (
	pushOpen   pushKind = iota // the socket is open: pull first
	pushFrame                  // one envelope pushed
	pushClosed                 // the socket closed; reconnecting
	pushDown                   // the upgrade failed, first of a streak; trying again
	pushGone                   // the relay refused the channel's token or channel: no more reconnects
)

type pushEvent struct {
	kind    pushKind
	channel string
	rec     relay.Record
	err     error
}

func newPusher(ctx context.Context, sv *server) *pusher {
	return &pusher{sv: sv, ctx: ctx, events: make(chan pushEvent, 64), socks: map[string]*pushSocket{}}
}

// stop closes every socket and waits for their goroutines.
func (ps *pusher) stop() {
	for _, s := range ps.socks {
		s.cancel()
	}
	ps.wg.Wait()
}

// track opens a socket for every served channel without one and closes
// those no longer served, by the roster as it is now.
func (ps *pusher) track(ctx context.Context) {
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
	for id, s := range ps.socks {
		if _, ok := served[id]; !ok {
			s.cancel()
			delete(ps.socks, id)
		}
	}
	for id, pe := range served {
		if ps.socks[id] != nil {
			continue
		}
		sctx, cancel := context.WithCancel(ps.ctx)
		ps.socks[id] = &pushSocket{cancel: cancel}
		ps.wg.Add(1)
		go func() {
			defer ps.wg.Done()
			ps.hold(sctx, pe)
		}()
	}
}

// hold keeps one channel's socket open until ctx ends or the relay refuses
// it for good, reconnecting with backoff after every close.
func (ps *pusher) hold(ctx context.Context, pe roster.Peer) {
	rc := relay.New(pe.Relay, nil)
	backoff, down := backoffMin, false
	for ctx.Err() == nil {
		s, err := rc.Subscribe(ctx, pe.Channel, pe.Token)
		if err == nil {
			down = false
			opened := time.Now()
			if ps.emit(ctx, pushEvent{kind: pushOpen, channel: pe.Channel}) {
				err = ps.read(ctx, s, pe.Channel)
			}
			s.Close()
			if time.Since(opened) > backoffMax {
				backoff = backoffMin
			}
		}
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, relay.ErrBadToken) || errors.Is(err, relay.ErrNoSuchChannel):
			ps.emit(ctx, pushEvent{kind: pushGone, channel: pe.Channel, err: err})
			return
		case err == nil:
		case down:
		default:
			kind := pushClosed
			if s == nil {
				kind, down = pushDown, true
			}
			ps.emit(ctx, pushEvent{kind: kind, channel: pe.Channel, err: err})
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
func (ps *pusher) read(ctx context.Context, s *relay.Socket, channel string) error {
	for {
		rec, err := s.Next(ctx)
		if err != nil {
			return err
		}
		if !ps.emit(ctx, pushEvent{kind: pushFrame, channel: channel, rec: rec}) {
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

// handle acts on one socket event, with the channel's roster entry as it is
// now: a frame is taken by the pulled row's path, an open or every
// push.pullEvery frames pulls the channel.
func (ps *pusher) handle(ctx context.Context, ev pushEvent) {
	s := ps.socks[ev.channel]
	if s == nil {
		return
	}
	r, err := roster.Load(ctx, ps.sv.p.backend)
	if err != nil {
		fmt.Fprintf(ps.sv.out, "push: %v\n", err)
		return
	}
	pe := r.ByChannel(ev.channel)
	if pe == nil || !serves(*pe) {
		return
	}
	out := ps.sv.out
	switch ev.kind {
	case pushDown:
		fmt.Fprintf(out, "%s: no push socket (%v); pulling every round until one opens\n", pe.Name, ev.err)
	case pushGone:
		fmt.Fprintf(out, "%s: the relay refused the push socket (%v); pulling every round\n", pe.Name, ev.err)
	case pushClosed:
		fmt.Fprintf(out, "%s: push socket closed (%v); reconnecting\n", pe.Name, ev.err)
	case pushOpen:
		fmt.Fprintf(out, "%s: push socket open\n", pe.Name)
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
