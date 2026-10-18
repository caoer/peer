package relay

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caoer/peer/internal/httpx"
)

// silentProxy forwards TCP to target until silence: from then on every
// connection open at that moment swallows its bytes both ways and never
// closes — a path that died under a pooled connection. Later connections
// forward normally.
type silentProxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	open   []*atomic.Bool
}

func newSilentProxy(t *testing.T, target string) *silentProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &silentProxy{ln: ln, target: target}
	t.Cleanup(func() { ln.Close() })
	go p.serve()
	return p
}

func (p *silentProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", p.target)
		if err != nil {
			c.Close()
			continue
		}
		dead := new(atomic.Bool)
		p.mu.Lock()
		p.open = append(p.open, dead)
		p.mu.Unlock()
		go pipe(c, up, dead)
		go pipe(up, c, dead)
	}
}

func pipe(dst io.Writer, src io.Reader, dead *atomic.Bool) {
	b := make([]byte, 32<<10)
	for {
		n, err := src.Read(b)
		if n > 0 && !dead.Load() {
			if _, werr := dst.Write(b[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *silentProxy) silence() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, d := range p.open {
		d.Store(true)
	}
	return len(p.open)
}

func (p *silentProxy) conns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.open)
}

// A pooled HTTP/2 connection to the relay that goes silent is dropped, and
// a request after it reaches the relay on a fresh connection.
func TestDeadConnectionRedials(t *testing.T) {
	var proto atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto.Store(int32(r.ProtoMajor))
		w.Write([]byte("landing"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	p := newSilentProxy(t, srv.Listener.Addr().String())
	tlsConf := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr := httpx.NewTransport(tlsConf, 100*time.Millisecond, 200*time.Millisecond)
	defer tr.CloseIdleConnections()
	c := New("https://"+p.ln.Addr().String()+"/peer", &http.Client{Transport: tr})
	id := "0123456789abcdef0123456789abcdef"

	land := func(d time.Duration) error {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		_, err := c.Landing(ctx, id)
		return err
	}
	if err := land(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if proto.Load() != 2 {
		t.Fatalf("relay spoke HTTP/%d, want HTTP/2", proto.Load())
	}
	if n := p.silence(); n != 1 {
		t.Fatalf("%d connections before silence, want 1", n)
	}

	// Each try waits 1 s; the pool must stop handing out the silent
	// connection well inside 5 s.
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := land(time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still failing on the silent connection: %v", err)
		}
	}
	if n := p.conns(); n < 2 {
		t.Fatalf("%d connections, want a fresh one", n)
	}
}
