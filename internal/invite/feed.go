package invite

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/caoer/peer/internal/relay"
)

// LinkKeySize is a feed link key's length in bytes.
const LinkKeySize = 32

// Feed is the second form of link (contract § Sealed record, Feed link):
//
//	https://<host>/peer/f/<room id>#v1.<readToken>.<linkKey>.<ownerSign>
//
// The fragment carries the feed's multi-use read token, the link key the
// link stanza's X25519 key derives from, and the owner's room signing key,
// the key a holder verifies every record under. It does not expire: a new
// link cuts every old holder off.
type Feed struct {
	Relay string            // relay base, e.g. https://example.com/peer
	Room  string            // room id
	Token string            // the read token
	Key   []byte            // LinkKeySize bytes
	Owner ed25519.PublicKey // the owner's room signing key
}

// String renders the feed link.
func (f Feed) String() string {
	return fmt.Sprintf("%s/f/%s#%s.%s.%s.%s", strings.TrimRight(f.Relay, "/"), f.Room, version, f.Token,
		base64.RawURLEncoding.EncodeToString(f.Key), base64.RawURLEncoding.EncodeToString(f.Owner))
}

// ParseFeed reads a feed link and refuses anything else: a v1 invite link,
// a link whose fragment is not v1.<readToken>.<linkKey>.<ownerSign>, a key
// of the wrong size.
func ParseFeed(s string) (Feed, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return Feed{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return Feed{}, fmt.Errorf("%w: want http(s)://host/…/f/<id>#…, no query", ErrMalformed)
	}
	i := strings.LastIndex(u.Path, "/f/")
	if i < 0 {
		return Feed{}, fmt.Errorf("%w: no /f/<id> in path: not a feed link", ErrMalformed)
	}
	base := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path[:i]}
	parts := strings.Split(u.Fragment, ".")
	if len(parts) != 4 || parts[0] != version {
		return Feed{}, fmt.Errorf("%w: fragment is not %s.<readToken>.<linkKey>.<ownerSign>", ErrMalformed, version)
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(key) != LinkKeySize {
		return Feed{}, fmt.Errorf("%w: link key", ErrMalformed)
	}
	owner, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(owner) != ed25519.PublicKeySize {
		return Feed{}, fmt.Errorf("%w: owner key", ErrMalformed)
	}
	f := Feed{Relay: base.String(), Room: u.Path[i+len("/f/"):], Token: parts[1], Key: key, Owner: ed25519.PublicKey(owner)}
	if err := f.Check(); err != nil {
		return Feed{}, err
	}
	return f, nil
}

// Check refuses a feed link with a bad room id, token, key or relay base.
func (f Feed) Check() error {
	switch {
	case !relay.ValidRoomID(f.Room):
		return fmt.Errorf("%w: room id", ErrMalformed)
	case !relay.ValidToken(f.Token):
		return fmt.Errorf("%w: token", ErrMalformed)
	case len(f.Key) != LinkKeySize:
		return fmt.Errorf("%w: link key is %d bytes", ErrMalformed, len(f.Key))
	case len(f.Owner) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: owner key is %d bytes", ErrMalformed, len(f.Owner))
	case !strings.HasPrefix(f.Relay, "https://") && !strings.HasPrefix(f.Relay, "http://"):
		return fmt.Errorf("%w: relay base %q", ErrMalformed, f.Relay)
	}
	return nil
}
