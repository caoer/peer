// Package feed is the host side of a party's reader feed (plan-delivery
// § Identifiers, Feed socket and Feed frames): one source socket per serving
// host on GET /feed/<party id>, over which the host's sent and received
// timeline records reach the party's reader pages live, and a viewer's
// connect asks the host to replay what it holds.
//
// The Object stores nothing: a record a viewer missed is gone unless a host
// replays it. So the client keeps every record it sent until the Object acks
// it, sends the unacked ones again after a reconnect, and answers a replay
// request from the caller's own records.
package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	// PingEvery is the keepalive, as the relay's: Cloudflare drops a socket
	// silent for about 100 s, and the Object answers each ping with a pong.
	PingEvery = 30 * time.Second
	// idleAfter is how long a socket may carry nothing, pong included,
	// before it is taken as dead.
	idleAfter = 3 * PingEvery
	// helloTimeout bounds the Object's answer to the hello.
	helloTimeout = 10 * time.Second
	// maxFrame bounds one frame from the Object: an ack or a replay request.
	maxFrame = 64 << 10
	// closeBadToken is the Object's close for a hello it refuses: the source
	// secret is not this feed's, after which the client stops reconnecting.
	closeBadToken websocket.StatusCode = 4401
)

// The reconnect backoff: doubling from backoffMin to backoffMax, jittered,
// and back to backoffMin after a socket that stayed open past backoffMax.
var (
	backoffMin = time.Second
	backoffMax = time.Minute
)

// ErrRefused is the Object's word that the source secret is not this feed's:
// the client stops; a serve dials again with the feed record's secret at its
// next round.
var ErrRefused = errors.New("feed: the source secret is not this feed's")

// Replay is the Object's word that a viewer connected: who to replay to, the
// hash of its reader token, and the reader key its page holds, when any.
type Replay struct {
	Viewer string `json:"viewer"`
	Reader string `json:"reader"`
	Key    string `json:"key,omitempty"`
}

// Options are a client's callbacks and environment; every field may be zero.
type Options struct {
	// Replay answers a viewer's connect: it hands send every record the host
	// holds for the viewer, in order, and returns the party's current reader
	// keys, which the client sends as replay_done. Nil replays nothing and
	// ends the replay at once.
	Replay func(ctx context.Context, r Replay, send func(rec json.RawMessage) error) (readers []string, err error)
	// Key takes a viewer's reader key and the hash of its token, when the
	// viewer's hello carried a key.
	Key func(key, reader string)
	// HTTPClient makes the socket's upgrade; nil is http.DefaultClient.
	HTTPClient *http.Client
	// Log takes the client's lines; nil discards them.
	Log io.Writer
}

// Client is one host's source socket on a party's feed. Dial starts it;
// Send queues a record; Flush waits for the acks; Close ends it.
type Client struct {
	url, party, secret, host string
	opt                      Options

	mu      sync.Mutex
	cond    *sync.Cond
	conn    *websocket.Conn // the socket after its hello, nil while down
	pending []frame         // sent and not yet acked, in Send order
	refused bool            // the Object closed the hello with closeBadToken
	closed  bool

	ctx  context.Context // the client's life; Flush ends with it
	stop context.CancelFunc
	done chan struct{}
}

// frame is one record as it was sent, kept until its ack.
type frame struct {
	n     int64
	bytes []byte
}

// Dial starts a client on the feed of party at url (the worker base, e.g.
// https://peer.0xtau.com), saying hello as host with the source secret. It
// returns at once; the socket is opened, and reopened after every close with
// backoff, until ctx ends, Close is called or the Object refuses the secret.
func Dial(ctx context.Context, url, party, secret, host string, opt Options) *Client {
	if opt.HTTPClient == nil {
		opt.HTTPClient = http.DefaultClient
	}
	if opt.Log == nil {
		opt.Log = io.Discard
	}
	cctx, stop := context.WithCancel(ctx)
	c := &Client{url: strings.TrimSuffix(url, "/"), party: party, secret: secret, host: host, opt: opt, ctx: cctx, stop: stop, done: make(chan struct{})}
	c.cond = sync.NewCond(&c.mu)
	go func() {
		defer close(c.done)
		c.hold(cctx)
	}()
	go func() {
		<-cctx.Done()
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	}()
	return c
}

// Send queues record rec under number n, which the Object acks back. It never
// blocks on the socket: a record sent while the socket is down goes out when
// it is up again, and one the Object has not acked is sent again after a
// reconnect. n is the caller's; the Object acks what it was given.
func (c *Client) Send(rec json.RawMessage, n int64) {
	b, err := json.Marshal(struct {
		Rec json.RawMessage `json:"rec"`
		N   int64           `json:"n"`
	}{rec, n})
	if err != nil {
		fmt.Fprintf(c.opt.Log, "feed: record %d: %v\n", n, err)
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.pending = append(c.pending, frame{n: n, bytes: b})
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		// A write that fails here is the read loop's to notice: the frame
		// stays pending for the next socket.
		write(conn, b)
	}
}

// write puts one frame on conn, bounded so a stalled socket holds no caller.
func write(conn *websocket.Conn, b []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), PingEvery)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, b)
}

// Refused reports whether the Object refused the secret: the client has
// stopped, and a new one takes the feed record's current secret.
func (c *Client) Refused() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refused
}

// Pending is how many sent records the Object has not acked.
func (c *Client) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// Flush waits until every sent record is acked. It returns ctx's error when
// ctx ends first, ErrRefused when the Object refused the secret, and an error
// when the client itself ended — Close, or the context Dial was given.
func (c *Client) Flush(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	defer stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.pending) > 0 {
		if c.refused {
			return ErrRefused
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.closed || c.ctx.Err() != nil {
			return errors.New("feed: client closed")
		}
		c.cond.Wait()
	}
	return nil
}

// Close ends the client: the socket closes and nothing more is sent. The
// records not yet acked are dropped; the feed stores nothing, and the
// caller's own records serve the replay.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	c.stop()
	<-c.done
	return nil
}

// hold keeps the socket open until ctx ends or the Object refuses the
// secret, reconnecting with backoff after every close. The first failure of
// a streak is logged, the rest are not.
func (c *Client) hold(ctx context.Context) {
	backoff, down := backoffMin, false
	for ctx.Err() == nil {
		conn, err := c.dial(ctx)
		if err == nil {
			down = false
			opened := time.Now()
			c.attach(conn)
			err = c.read(ctx, conn)
			c.detach(conn)
			conn.CloseNow()
			if time.Since(opened) > backoffMax {
				backoff = backoffMin
			}
		}
		switch {
		case ctx.Err() != nil:
			return
		case websocket.CloseStatus(err) == closeBadToken:
			fmt.Fprintf(c.opt.Log, "feed: %s: the source secret is not this feed's; peer serve dials again with the feed record's secret at its next round\n", c.url)
			c.mu.Lock()
			c.refused = true
			c.cond.Broadcast()
			c.mu.Unlock()
			return
		case !down:
			down = true
			fmt.Fprintf(c.opt.Log, "feed: %s: %v; reconnecting\n", c.url, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff/2 + rand.N(backoff/2+1)):
		}
		backoff = min(2*backoff, backoffMax)
	}
}

// dial opens the socket and says hello; the Object's ok is the connection.
func (c *Client) dial(ctx context.Context) (*websocket.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	conn, _, err := websocket.Dial(dctx, c.url+"/feed/"+c.party, &websocket.DialOptions{HTTPClient: c.opt.HTTPClient, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(maxFrame)
	hello, _ := json.Marshal(struct {
		Hello  string `json:"hello"`
		Secret string `json:"secret"`
		Host   string `json:"host"`
	}{"source", c.secret, c.host})
	if err := conn.Write(dctx, websocket.MessageText, hello); err != nil {
		conn.CloseNow()
		return nil, err
	}
	_, b, err := conn.Read(dctx)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	var ok struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(b, &ok) != nil || !ok.OK {
		conn.CloseNow()
		return nil, fmt.Errorf("the hello was answered %q", b)
	}
	return conn, nil
}

// attach makes conn the socket and sends every pending frame on it. A Send
// from here on writes to conn itself; the frames pending before are these.
func (c *Client) attach(conn *websocket.Conn) {
	c.mu.Lock()
	c.conn = conn
	resend := make([]frame, len(c.pending))
	copy(resend, c.pending)
	c.mu.Unlock()
	for _, f := range resend {
		if write(conn, f.bytes) != nil {
			return
		}
	}
}

func (c *Client) detach(conn *websocket.Conn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.mu.Unlock()
}

// ack drops the pending frame numbered n.
func (c *Client) ack(n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, f := range c.pending {
		if f.n == n {
			c.pending = append(c.pending[:i], c.pending[i+1:]...)
			c.cond.Broadcast()
			return
		}
	}
}

// read takes the Object's frames until the socket fails or closes: acks,
// replay requests, pongs. It pings every PingEvery meanwhile.
func (c *Client) read(ctx context.Context, conn *websocket.Conn) error {
	kctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		t := time.NewTicker(PingEvery)
		defer t.Stop()
		for {
			select {
			case <-kctx.Done():
				return
			case <-t.C:
				if conn.Write(kctx, websocket.MessageText, []byte("ping")) != nil {
					conn.CloseNow()
					return
				}
			}
		}
	}()
	var replays sync.WaitGroup
	defer replays.Wait()
	for {
		rctx, cancel := context.WithTimeout(ctx, idleAfter)
		typ, b, err := conn.Read(rctx)
		cancel()
		if err != nil {
			return err
		}
		if typ != websocket.MessageText || string(b) == "pong" {
			continue
		}
		var f struct {
			Ack    *int64  `json:"ack"`
			Replay *Replay `json:"replay"`
		}
		if json.Unmarshal(b, &f) != nil {
			continue
		}
		if f.Ack != nil {
			c.ack(*f.Ack)
		}
		if f.Replay != nil {
			replays.Add(1)
			go func(r Replay) {
				defer replays.Done()
				c.replay(kctx, conn, r)
			}(*f.Replay)
		}
	}
}

// replay answers one viewer's connect: its key to the Key callback, the
// caller's records to the viewer, then replay_done with the readers.
func (c *Client) replay(ctx context.Context, conn *websocket.Conn, r Replay) {
	if c.opt.Key != nil && r.Key != "" {
		c.opt.Key(r.Key, r.Reader)
	}
	var readers []string
	if c.opt.Replay != nil {
		send := func(rec json.RawMessage) error {
			b, err := json.Marshal(struct {
				Rec json.RawMessage `json:"rec"`
				To  string          `json:"to"`
			}{rec, r.Viewer})
			if err != nil {
				return err
			}
			return conn.Write(ctx, websocket.MessageText, b)
		}
		var err error
		if readers, err = c.opt.Replay(ctx, r, send); err != nil {
			fmt.Fprintf(c.opt.Log, "feed: replay to viewer %s: %v\n", r.Viewer, err)
		}
	}
	if readers == nil {
		readers = []string{}
	}
	done, _ := json.Marshal(struct {
		ReplayDone string   `json:"replay_done"`
		Readers    []string `json:"readers"`
	}{r.Viewer, readers})
	if err := conn.Write(ctx, websocket.MessageText, done); err != nil && ctx.Err() == nil {
		fmt.Fprintf(c.opt.Log, "feed: replay to viewer %s: %v\n", r.Viewer, err)
	}
}
