package pages

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/caoer/peer/internal/httpx"
)

// The page's live socket (ccc-pages src/live.ts, `GET /d/<slug>` upgraded):
// a `hello` snapshot of every record, or after a reconnect with `have` only
// the changes since; then every committed change as it lands. While it is
// synced, Load answers from what it pushed and reads the page only for a
// record the socket sent as a `ref` (too large to inline) or one a Store
// found changed under it; the socket costs an upgrade per admission (30
// minutes) and nothing per change. Down, Load reads the page as before.
const (
	livePing       = `{"type":"ping"}`
	livePong       = `{"type":"pong"}`
	livePingEvery  = 30 * time.Second
	liveIdleAfter  = 3 * livePingEvery
	liveReadLimit  = 8 << 20
	liveCloseReset = websocket.StatusCode(4409) // resync: reconnect with no cursor
	liveCloseGone  = websocket.StatusCode(4404) // the page is deleted
	liveCloseAuth  = websocket.StatusCode(4401) // admission ended: reconnect at once
)

// The reconnect backoff, doubling and jittered, reset by a socket that synced.
var (
	liveBackoffMin = time.Second
	liveBackoffMax = time.Minute
)

// live is what the socket has pushed. Guarded by Backend.mu.
type live struct {
	synced   bool // the socket is open and caught up: recs are the page
	complete bool // the snapshot held every record: a key not in recs is absent
	epoch    string
	seq      int64
	recs     map[string]*liveRec
}

type liveRec struct {
	data []byte
	v    int64
	ref  bool // not held here: Load reads the page
}

// liveFrame is every frame the client reads; fields by type.
type liveFrame struct {
	Type   string                     `json:"type"`
	Epoch  *string                    `json:"epoch"`
	Seq    int64                      `json:"seq"`
	Prev   int64                      `json:"prev"`
	From   int64                      `json:"from"`
	Floors map[string]*string         `json:"floors"`
	Keys   map[string]liveFrameRecord `json:"keys"`
	Key    string                     `json:"key"`
	liveFrameRecord
}

type liveFrameRecord struct {
	V      int64           `json:"v"`
	Schema string          `json:"schema"`
	Value  json.RawMessage `json:"value"`
	Ref    bool            `json:"ref"`
}

// rec is the frame's record as held: its bytes when inline and a peer
// store record, a ref otherwise (Load reads the page and says why).
func (f liveFrameRecord) rec() *liveRec {
	if f.Ref || f.Schema != Schema || len(f.Value) == 0 {
		return &liveRec{v: f.V, ref: true}
	}
	var s string
	if json.Unmarshal(f.Value, &s) != nil {
		return &liveRec{v: f.V, ref: true}
	}
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return &liveRec{v: f.V, ref: true}
	}
	return &liveRec{data: data, v: f.V}
}

// errLiveHole is a change whose prev this client does not hold: reconnect
// from the last change it does.
var errLiveHole = errors.New("a change arrived out of order")

// Watch holds the page's live socket until ctx ends, reconnecting with
// backoff; out gets a line when it opens after being down and when it
// drops. Load answers from it while it is synced.
func (b *Backend) Watch(ctx context.Context, out io.Writer) {
	b.mu.Lock()
	b.live = &live{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.live = nil
		b.mu.Unlock()
	}()
	backoff, quiet := liveBackoffMin, true
	for ctx.Err() == nil {
		synced, err := b.watchOnce(ctx, out, quiet)
		if ctx.Err() != nil {
			return
		}
		code := websocket.CloseStatus(err)
		b.mu.Lock()
		b.live.synced = false
		if code == liveCloseReset {
			b.live.epoch = ""
		}
		b.mu.Unlock()
		if code == liveCloseGone {
			fmt.Fprintf(out, "state page: live socket closed: the page is gone (%v); reading the page\n", err)
			return
		}
		if synced {
			backoff = liveBackoffMin
		}
		// An admission that ended reconnects at once and says nothing: it is
		// the socket's normal half-hourly renewal.
		if code == liveCloseAuth && synced {
			quiet = true
			continue
		}
		fmt.Fprintf(out, "state page: live socket down (%v); reading the page until it reopens\n", err)
		quiet = false
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff/2 + rand.N(backoff/2+1)):
		}
		backoff = min(2*backoff, liveBackoffMax)
	}
}

// watchOnce is one socket's life: whether it reached synced, and why it
// ended.
func (b *Backend) watchOnce(ctx context.Context, out io.Writer, quiet bool) (bool, error) {
	u := "ws" + strings.TrimPrefix(b.base, "http") + "/d/" + b.slug
	b.mu.Lock()
	if b.live.epoch != "" {
		u += "?have=" + b.live.epoch + "." + strconv.FormatInt(b.live.seq, 10)
	}
	b.mu.Unlock()
	hc := b.client
	if hc.Timeout != 0 {
		// The client's timeout would end the socket; the dial is bounded by
		// ctx and the reads by liveIdleAfter.
		c := *hc
		c.Timeout = 0
		if c.Transport == nil {
			c.Transport = httpx.Transport
		}
		hc = &c
	}
	dctx, cancel := context.WithTimeout(ctx, Timeout)
	conn, resp, err := websocket.Dial(dctx, u, &websocket.DialOptions{
		HTTPClient:      hc,
		HTTPHeader:      http.Header{"Authorization": {"Bearer " + b.bearer}},
		CompressionMode: websocket.CompressionDisabled,
	})
	cancel()
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			return false, fmt.Errorf("the upgrade answered %d", resp.StatusCode)
		}
		return false, err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(liveReadLimit)
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		t := time.NewTicker(livePingEvery)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				if conn.Write(sctx, websocket.MessageText, []byte(livePing)) != nil {
					conn.CloseNow()
					return
				}
			}
		}
	}()
	synced := false
	for {
		rctx, cancel := context.WithTimeout(sctx, liveIdleAfter)
		typ, raw, err := conn.Read(rctx)
		cancel()
		if err != nil {
			return synced, err
		}
		if typ != websocket.MessageText || string(raw) == livePong {
			continue
		}
		var f liveFrame
		if err := json.Unmarshal(raw, &f); err != nil {
			return synced, fmt.Errorf("a frame is not JSON: %v", err)
		}
		now, err := b.apply(f)
		if err != nil {
			conn.Close(websocket.StatusNormalClosure, "resume")
			return synced, err
		}
		if now && !synced {
			synced = true
			if !quiet {
				fmt.Fprintln(out, "state page: live socket open; records come from its pushes")
			}
		}
	}
}

// apply takes one frame into the held records and reports whether the
// socket is synced after it.
func (b *Backend) apply(f liveFrame) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.live
	switch f.Type {
	case "hello":
		if f.Epoch == nil {
			// A store with no change yet has no epoch; there is nothing to
			// resume, and nothing held.
			l.epoch = ""
		} else {
			l.epoch = *f.Epoch
		}
		l.seq, l.complete, l.recs = f.Seq, len(f.Floors) == 0, map[string]*liveRec{}
		for k, r := range f.Keys {
			l.recs[k] = r.rec()
		}
		l.synced = true
	case "welcome":
		if f.Epoch == nil || *f.Epoch != l.epoch || f.Seq < l.seq {
			l.epoch = ""
			return false, fmt.Errorf("welcome at %v.%d does not continue %s.%d", f.Epoch, f.Seq, l.epoch, l.seq)
		}
	case "synced":
		l.seq, l.synced = f.Seq, true
	case "put", "del":
		if f.Prev != l.seq {
			return false, fmt.Errorf("%w: %s %s #%d after #%d, held #%d", errLiveHole, f.Type, f.Key, f.Seq, f.Prev, l.seq)
		}
		l.seq = f.Seq
		if f.Type == "del" {
			delete(l.recs, f.Key)
		} else if cur := l.recs[f.Key]; cur == nil || f.V >= cur.v {
			l.recs[f.Key] = f.rec()
		}
	case "seq":
		if f.From != l.seq+1 {
			return false, fmt.Errorf("%w: seq #%d-#%d, held #%d", errLiveHole, f.From, f.Seq, l.seq)
		}
		l.seq = f.Seq
	}
	return l.synced, nil
}

// cached is key's record as the synced socket holds it; ok false when the
// page must be read.
func (b *Backend) cached(key string) (data []byte, v int64, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.live
	if l == nil || !l.synced {
		return nil, 0, false
	}
	r := l.recs[key]
	switch {
	case r == nil:
		return nil, 0, l.complete
	case r.ref:
		return nil, 0, false
	}
	return append([]byte(nil), r.data...), r.v, true
}

// remember holds a record read from or written to the page, unless the
// socket already holds a later version.
func (b *Backend) remember(key string, data []byte, v int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.live
	if l == nil || !l.synced || v == 0 {
		return
	}
	if cur := l.recs[key]; cur == nil || v > cur.v || (v == cur.v && cur.ref) {
		l.recs[key] = &liveRec{data: append([]byte(nil), data...), v: v}
	}
}

// forget makes the next Load of key read the page: a Store found another
// version there than the one held.
func (b *Backend) forget(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if l := b.live; l != nil && l.recs != nil {
		v := int64(0)
		if cur := l.recs[key]; cur != nil {
			v = cur.v
		}
		l.recs[key] = &liveRec{v: v, ref: true}
	}
}

// Live reports whether Load answers from the live socket now.
func (b *Backend) Live() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.live != nil && b.live.synced
}

// The live state hangs off Backend; declared here with the code that uses it.
type liveHolder struct {
	mu   sync.Mutex
	live *live
}
