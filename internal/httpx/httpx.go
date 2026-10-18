// Package httpx is the transport every client of the relay and the ccc-pages
// service runs on.
//
// A pooled HTTP/2 connection whose path died (a NAT entry dropped, the
// network changed) reads nothing and errors nothing: every request on it
// waits out its timeout, and the pool hands the same connection to the next
// one, so a long-running serve gets nothing through until it restarts.
// Transport pings a connection that has read nothing for ReadIdle and
// closes it when the ping goes unanswered for PingTimeout; the next request
// dials afresh.
package httpx

import (
	"crypto/tls"
	"net/http"
	"time"
)

const (
	ReadIdle    = 15 * time.Second
	PingTimeout = 10 * time.Second
)

// Transport is the shared transport: one connection pool for the process.
var Transport = NewTransport(nil, ReadIdle, PingTimeout)

// NewTransport is the default transport with HTTP/2 health pings; a nil
// tlsConf keeps the system roots.
func NewTransport(tlsConf *tls.Config, readIdle, pingTimeout time.Duration) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConf != nil {
		t.TLSClientConfig = tlsConf
	}
	t.HTTP2 = &http.HTTP2Config{SendPingTimeout: readIdle, PingTimeout: pingTimeout}
	return t
}
