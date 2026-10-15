// Package invite formats and parses the invite link
//
//	https://<host>/peer/i/<channel id>#v1.<token>.<rootpub>.<exp>.<secret>
//
// (design §4). The fragment never reaches a server; it carries the one-time
// invite token, the inviter's Ed25519 root public key (base64url, no
// padding), the expiry (unix seconds) and the link secret: 16 random bytes
// the relay never sees, which the guest proves at accept and which binds the
// verification code to this invite. A link is valid for 72 h.
package invite

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caoer/peer/internal/relay"
)

// Validity is how long a new link stays valid.
const Validity = 72 * time.Hour

// SecretSize is the link secret's length in bytes.
const SecretSize = 16

const version = "v1"

var (
	ErrMalformed = errors.New("invite: malformed link")
	ErrExpired   = errors.New("invite: link expired")
)

// Link is a parsed invite.
type Link struct {
	Relay   string            // relay base, e.g. https://example.com/peer
	Channel string            // channel id
	Token   string            // one-time invite token
	Root    ed25519.PublicKey // inviter's root key, pinned on accept
	Expires time.Time         // whole seconds
	Secret  []byte            // SecretSize bytes, known to the two CLIs alone
}

// NewSecret draws a link secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, SecretSize)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// New makes a link that expires Validity after now.
func New(relayBase, channel, token string, root ed25519.PublicKey, secret []byte, now time.Time) (Link, error) {
	l := Link{
		Relay:   strings.TrimRight(relayBase, "/"),
		Channel: channel,
		Token:   token,
		Root:    root,
		Expires: now.Add(Validity).Truncate(time.Second),
		Secret:  secret,
	}
	if err := l.check(); err != nil {
		return Link{}, err
	}
	return l, nil
}

// String renders the link.
func (l Link) String() string {
	return fmt.Sprintf("%s/i/%s#%s.%s.%s.%d.%s", l.Relay, l.Channel, version, l.Token,
		base64.RawURLEncoding.EncodeToString(l.Root), l.Expires.Unix(),
		base64.RawURLEncoding.EncodeToString(l.Secret))
}

// Parse reads a link and refuses it when it is malformed or expired at now.
func Parse(s string, now time.Time) (Link, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return Link{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return Link{}, fmt.Errorf("%w: want http(s)://host/…/i/<id>#…, no query", ErrMalformed)
	}
	i := strings.LastIndex(u.Path, "/i/")
	if i < 0 {
		return Link{}, fmt.Errorf("%w: no /i/<id> in path", ErrMalformed)
	}
	channel := u.Path[i+len("/i/"):]
	base := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path[:i]}

	parts := strings.Split(u.Fragment, ".")
	if len(parts) != 5 || parts[0] != version {
		return Link{}, fmt.Errorf("%w: fragment is not %s.<token>.<rootpub>.<exp>.<secret>", ErrMalformed, version)
	}
	root, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(root) != ed25519.PublicKeySize {
		return Link{}, fmt.Errorf("%w: root key", ErrMalformed)
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || exp <= 0 || strconv.FormatInt(exp, 10) != parts[3] {
		return Link{}, fmt.Errorf("%w: expiry", ErrMalformed)
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(secret) != SecretSize {
		return Link{}, fmt.Errorf("%w: secret", ErrMalformed)
	}
	l := Link{
		Relay:   base.String(),
		Channel: channel,
		Token:   parts[1],
		Root:    ed25519.PublicKey(root),
		Expires: time.Unix(exp, 0),
		Secret:  secret,
	}
	if err := l.check(); err != nil {
		return Link{}, err
	}
	if !now.Before(l.Expires) {
		return Link{}, fmt.Errorf("%w at %s", ErrExpired, l.Expires.UTC().Format(time.RFC3339))
	}
	return l, nil
}

func (l Link) check() error {
	if !relay.ValidChannelID(l.Channel) {
		return fmt.Errorf("%w: channel id", ErrMalformed)
	}
	if !relay.ValidToken(l.Token) {
		return fmt.Errorf("%w: token", ErrMalformed)
	}
	if len(l.Root) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: root key is %d bytes", ErrMalformed, len(l.Root))
	}
	if len(l.Secret) != SecretSize {
		return fmt.Errorf("%w: secret is %d bytes", ErrMalformed, len(l.Secret))
	}
	if !strings.HasPrefix(l.Relay, "https://") && !strings.HasPrefix(l.Relay, "http://") {
		return fmt.Errorf("%w: relay base %q", ErrMalformed, l.Relay)
	}
	return nil
}
