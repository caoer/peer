package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages"
)

// stateSock is a running serve's socket in the peer directory. It holds the
// state page's records as serve's live socket keeps them — sealed, as the
// page holds them — for this host's commands, so they read serve and not
// the page. A connection sends one request line and is answered with
// stateCopy lines:
//
//	{"op":"copy"}   one copy, then the connection closes (status)
//	{"op":"watch"}  a copy once serve's live socket is synced, then one after
//	                every change of the records, until either side closes (wait)
const stateSock = "serve.sock"

// stateRequest is a connection's request line.
type stateRequest struct {
	Op string `json:"op"`
}

// stateCopy is one answer line: Synced false (copy only) while serve's live
// socket is down or catching up, when its records are not the page.
type stateCopy struct {
	Synced bool `json:"synced"`
	pages.Snapshot
}

// stateIOTimeout bounds a request line, a copy's write and a copy's read.
const stateIOTimeout = 5 * time.Second

// stateReadLimit bounds one copy line read by a command.
const stateReadLimit = 256 << 20

// statePage is the party's state page, nil when its state is not a page.
func statePage(b store.Backend) *pages.Backend {
	pb, _ := store.Inner(b).(*pages.Backend)
	return pb
}

// serveStateCopy answers stateSock until the returned stop is called; a
// state that is not a page, a socket another serve answers, or one that
// cannot be made leaves status reading the page and wait refusing.
func (sv *server) serveStateCopy() (stop func()) {
	pb := statePage(sv.p.backend)
	if pb == nil {
		return func() {}
	}
	path := filepath.Join(sv.p.dir, stateSock)
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		fmt.Fprintf(sv.out, "state copy: another serve answers %s; this one does not\n", path)
		return func() {}
	}
	// No one answers: a socket file left by a serve that died.
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintf(sv.out, "state copy: %v; commands read the state page\n", err)
		return func() {}
	}
	os.Chmod(path, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				answerState(ctx, pb, c)
			}()
		}
	}()
	return func() {
		cancel()
		l.Close() // unlinks the socket file
		wg.Wait()
	}
}

// answerState answers one connection's request.
func answerState(ctx context.Context, pb *pages.Backend, c net.Conn) {
	c.SetReadDeadline(time.Now().Add(stateIOTimeout))
	r := bufio.NewReader(io.LimitReader(c, 4096))
	line, err := r.ReadBytes('\n')
	var req stateRequest
	if err != nil || json.Unmarshal(line, &req) != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	send := func(sc stateCopy) bool {
		c.SetWriteDeadline(time.Now().Add(stateIOTimeout))
		return json.NewEncoder(c).Encode(sc) == nil
	}
	switch req.Op {
	case "copy":
		snap, ok := pb.Snapshot()
		send(stateCopy{Synced: ok, Snapshot: snap})
	case "watch":
		// The peer closing its end is the watch's end: any byte or EOF.
		gone := make(chan struct{})
		go func() {
			io.Copy(io.Discard, r)
			io.Copy(io.Discard, c)
			close(gone)
		}()
		for {
			changed := pb.Changed()
			if snap, ok := pb.Snapshot(); ok && !send(stateCopy{Synced: true, Snapshot: snap}) {
				return
			}
			select {
			case <-changed:
			case <-gone:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

// dialState sends op to the serve answering stateSock in dir.
func dialState(dir, op string) (net.Conn, error) {
	path := filepath.Join(dir, stateSock)
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(stateRequest{Op: op})
	c.SetWriteDeadline(time.Now().Add(stateIOTimeout))
	if _, err := c.Write(append(b, '\n')); err != nil {
		c.Close()
		return nil, err
	}
	c.SetWriteDeadline(time.Time{})
	return c, nil
}

// holdState gives a read-only command the state page's records at once:
// serve's copy when a serve on this directory answers synced, else one
// values list of the page. Load then answers from them; failing both, Load
// reads the page record by record.
func (p *party) holdState(ctx context.Context) {
	pb := statePage(p.backend)
	if pb == nil {
		return
	}
	if snap, ok := readStateCopy(p.dir); ok {
		pb.Hold(snap)
		return
	}
	if snap, err := pb.ReadAll(ctx); err == nil {
		pb.Hold(snap)
	}
}

// readStateCopy asks the serve on dir for its copy; ok false when none
// answers or its copy is not synced.
func readStateCopy(dir string) (pages.Snapshot, bool) {
	c, err := dialState(dir, "copy")
	if err != nil {
		return pages.Snapshot{}, false
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(stateIOTimeout))
	var sc stateCopy
	if err := json.NewDecoder(io.LimitReader(c, stateReadLimit)).Decode(&sc); err != nil || !sc.Synced || sc.Recs == nil {
		return pages.Snapshot{}, false
	}
	return sc.Snapshot, true
}

// errNoServe is a wait with no serve to hold on.
var errNoServe = errors.New("no serve answers")

// watchState holds a watch on the serve on dir and calls each with every
// copy it sends, until each returns true (nil), ctx ends (ctx.Err()) or the
// serve goes away (an error naming it). No serve answering is errNoServe.
func watchState(ctx context.Context, dir string, each func(pages.Snapshot) (bool, error)) error {
	c, err := dialState(dir, "watch")
	if err != nil {
		return fmt.Errorf("%w on %s (%v): wait holds on a running peer serve", errNoServe, filepath.Join(dir, stateSock), err)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	dec := json.NewDecoder(bufio.NewReader(c))
	for {
		var sc stateCopy
		if err := dec.Decode(&sc); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("serve went away (%v)", err)
		}
		if !sc.Synced || sc.Recs == nil {
			continue
		}
		done, err := each(sc.Snapshot)
		if err != nil || done {
			return err
		}
	}
}
