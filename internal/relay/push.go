package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
}

// Subscribe opens the push socket on channel id with this side's token. A
// refusal before the upgrade is an *Error (bad_token, no_such_channel,
// rate_limited, too_many_sockets); an answer that is not an upgrade is
// ErrNoPush.
func (c *Client) Subscribe(ctx context.Context, id, token string) (*Socket, error) {
	if err := checkIDs(id, token); err != nil {
		return nil, err
	}
	conn, resp, err := websocket.Dial(ctx, c.base+"/c/"+id+"/envelopes", &websocket.DialOptions{
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
	s := &Socket{conn: conn, stop: stop}
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
// caller reconnects. A frame without a seq breaks the contract
// (ErrAnswer): nothing in it can be placed.
func (s *Socket) Next(ctx context.Context) (Record, error) {
	for {
		rctx, cancel := context.WithTimeout(ctx, idleAfter)
		typ, b, err := s.conn.Read(rctx)
		cancel()
		switch websocket.CloseStatus(err) {
		case closeBadToken:
			return Record{}, ErrBadToken
		case closeNoSuchChannel:
			return Record{}, ErrNoSuchChannel
		}
		if err != nil {
			return Record{}, err
		}
		if typ != websocket.MessageText {
			return Record{}, fmt.Errorf("%w: a binary frame", ErrAnswer)
		}
		if string(b) == "pong" {
			continue
		}
		var r wireRow
		if err := json.Unmarshal(b, &r); err != nil {
			return Record{}, fmt.Errorf("%w: frame: %v", ErrAnswer, err)
		}
		if r.Seq == nil || *r.Seq < 0 {
			return Record{}, fmt.Errorf("%w: frame without a seq", ErrAnswer)
		}
		return r.record(), nil
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
