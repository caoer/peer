package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/caoer/peer/internal/envelope"
)

// Push frames (wire contract § WebSocket push).
const (
	// maxFrame bounds one pushed frame: a row whose body is a whole
	// envelope.MaxBody in base64, and its JSON around it.
	maxFrame = 2 << 20
	// closeBadToken and closeNoSuchChannel are the relay's two closes after
	// which a client stops reconnecting.
	closeBadToken      websocket.StatusCode = 4401
	closeNoSuchChannel websocket.StatusCode = 4404
	// PingEvery is the keepalive: Cloudflare drops a socket silent for
	// about 100 s, and the relay answers each ping with a pong.
	PingEvery = 30 * time.Second
	// idleAfter is how long a socket may carry nothing, pong included,
	// before it is taken as dead.
	idleAfter = 3 * PingEvery
)

// ErrNoPush means the relay answered the upgrade with something other than
// a socket or a contract refusal — a relay without push. The pull is
// unaffected.
var ErrNoPush = errors.New("relay: no WebSocket push on this relay")

// Socket is one side's WebSocket on a channel's envelopes route: every
// envelope the other side puts while it is open arrives as a frame. It
// pings every PingEvery until it is closed.
type Socket struct {
	conn *websocket.Conn
	stop context.CancelFunc
	// resumed: the relay answered the upgrade's after (x-peer-resume), so the
	// socket carries the catch-up and then a Synced record.
	resumed bool
}

// Resumed reports whether the socket carries the catch-up from the cursor it
// was opened at, ended by a Synced record. False on a socket opened without
// one and on a relay from before resume: its client pulls the catch-up.
func (s *Socket) Resumed() bool { return s.resumed }

// Subscribe opens the push socket on channel id with this side's token. A
// refusal before the upgrade is an *Error (bad_token, no_such_channel,
// rate_limited, too_many_sockets); an answer that is not an upgrade is
// ErrNoPush.
func (c *Client) Subscribe(ctx context.Context, id, token string) (*Socket, error) {
	if err := checkIDs(id, token); err != nil {
		return nil, err
	}
	return c.dial(ctx, "/c/"+id+"/envelopes", token)
}

// Resume opens the push socket as Subscribe does, asking the relay to send
// first every envelope after seq after (-1 for all), one pull page, then a
// Synced record (Socket.Resumed says whether it will).
func (c *Client) Resume(ctx context.Context, id, token string, after int64) (*Socket, error) {
	if err := checkIDs(id, token); err != nil {
		return nil, err
	}
	if after < -1 {
		return nil, fmt.Errorf("relay: after %d is below -1", after)
	}
	return c.dial(ctx, "/c/"+id+"/envelopes?after="+strconv.FormatInt(after, 10), token)
}

// dial opens a push socket on path with token; Subscribe's refusals.
func (c *Client) dial(ctx context.Context, path, token string) (*Socket, error) {
	conn, resp, err := websocket.Dial(ctx, c.base+path, &websocket.DialOptions{
		HTTPClient:      c.http,
		HTTPHeader:      http.Header{"Authorization": {"Bearer " + token}},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp == nil || resp.StatusCode == http.StatusSwitchingProtocols {
			return nil, err
		}
		var b []byte
		if resp.Body != nil {
			b, _ = io.ReadAll(resp.Body)
		}
		if e := answerError(resp.StatusCode, b).(*Error); e.Code != "" {
			return nil, e
		}
		return nil, fmt.Errorf("%w: the upgrade answered %d", ErrNoPush, resp.StatusCode)
	}
	conn.SetReadLimit(maxFrame)
	kctx, stop := context.WithCancel(context.Background())
	s := &Socket{conn: conn, stop: stop, resumed: resp != nil && resp.Header.Get("X-Peer-Resume") == "1"}
	go s.keepalive(kctx)
	return s, nil
}

func (s *Socket) keepalive(ctx context.Context) {
	t := time.NewTicker(PingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.conn.Write(ctx, websocket.MessageText, []byte("ping")) != nil {
				s.conn.CloseNow()
				return
			}
		}
	}
}

// Next returns the next pushed envelope, validated as a pulled row is: a
// malformed envelope comes back with Err set and its seq. The relay's pong
// is skipped. A close the relay sends for good — 4401, 4404 — is
// ErrBadToken or ErrNoSuchChannel; any other close or failure, or a socket
// that carried nothing for three pings, is returned as it is and the
// caller reconnects. A resumed socket's `synced` frame is a Record with
// Synced set, Seq the last catch-up row and More when a pull page remains.
// A frame without a seq breaks the contract (ErrAnswer): nothing in it can
// be placed.
func (s *Socket) Next(ctx context.Context) (Record, error) {
	b, err := s.next(ctx)
	switch websocket.CloseStatus(err) {
	case closeBadToken:
		return Record{}, ErrBadToken
	case closeNoSuchChannel:
		return Record{}, ErrNoSuchChannel
	}
	if err != nil {
		return Record{}, err
	}
	var r wireRow
	if err := json.Unmarshal(b, &r); err != nil {
		return Record{}, fmt.Errorf("%w: frame: %v", ErrAnswer, err)
	}
	if s.resumed && r.Synced != nil {
		if *r.Synced < -1 {
			return Record{}, fmt.Errorf("%w: synced %d", ErrAnswer, *r.Synced)
		}
		return Record{Seq: *r.Synced, Synced: true, More: r.More}, nil
	}
	if r.Seq == nil || *r.Seq < 0 {
		return Record{}, fmt.Errorf("%w: frame without a seq", ErrAnswer)
	}
	return r.record(), nil
}

// next returns the next text frame that is not a pong. A read that sees
// nothing for idleAfter fails; a close comes back as the read's error.
func (s *Socket) next(ctx context.Context) ([]byte, error) {
	for {
		rctx, cancel := context.WithTimeout(ctx, idleAfter)
		typ, b, err := s.conn.Read(rctx)
		cancel()
		if err != nil {
			return nil, err
		}
		if typ != websocket.MessageText {
			return nil, fmt.Errorf("%w: a binary frame", ErrAnswer)
		}
		if string(b) != "pong" {
			return b, nil
		}
	}
}

// Close closes the socket from this side, without waiting on the relay.
func (s *Socket) Close() error {
	s.stop()
	return s.conn.CloseNow()
}

// wireRow is one envelope as the relay answers it, in a pull page or a frame.
type wireRow struct {
	Seq  *int64 `json:"seq"`
	Type string `json:"type"`
	Body string `json:"body"`
	At   *int64 `json:"at"`
	// Synced and More are a resumed socket's end of catch-up.
	Synced *int64 `json:"synced"`
	More   bool   `json:"more"`
}

// record is the row as a Record; its seq is present and checked by the
// caller.
func (r wireRow) record() Record {
	rec := Record{Seq: *r.Seq}
	if r.At != nil {
		rec.At = time.UnixMilli(*r.At)
	}
	rec.Env, rec.Err = envelope.FromWire(r.Type, r.Body)
	if rec.Err == nil && r.At == nil {
		rec.Err = fmt.Errorf("%w: no at", ErrAnswer)
		rec.Env = envelope.Envelope{}
	}
	return rec
}
