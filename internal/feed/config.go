package feed

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.mau.fi/libsignal/ecc"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
)

// The feed config is what the Object holds for a party (plan-delivery
// § Identifiers, Feed config): the hashes of the source secret and of each
// reader token — never a secret, never the card. Any machine of the party
// writes it. The request carries the party's root-signed public card in
// X-Peer-Card and the identity key's signature in X-Peer-Signature: the card
// is the delegation (decision 33) — the root signs the card and nothing
// else, and the identity key, on every machine of the party, signs the
// config — so no root act configures a feed and the worker keeps no login.

// Config is the body of PUT /feed/<party id>/config and the answer to GET.
type Config struct {
	V       int      `json:"v"`
	Party   string   `json:"party"`
	At      string   `json:"at"`
	Source  string   `json:"source"`
	Readers []string `json:"readers"`
}

const (
	// ConfigVersion is Config.V.
	ConfigVersion = 1
	// CardHeader carries the root-signed public card, SignatureHeader the
	// identity key's signature; AtHeader is what a GET's signature covers.
	CardHeader      = "X-Peer-Card"
	SignatureHeader = "X-Peer-Signature"
	AtHeader        = "X-Peer-At"
	// AtFormat is a config's at and an X-Peer-At value: RFC 3339 UTC with
	// milliseconds, so two writes of one party a moment apart still order.
	AtFormat = "2006-01-02T15:04:05.000Z"
	// secretBytes is a source secret's or a reader token's size: 32 random
	// bytes, 43 characters of base64url.
	secretBytes = 32
	// maxAnswer bounds the Object's answer.
	maxAnswer = 64 << 10
)

var b64 = base64.RawURLEncoding

// NewSecret mints a source secret or a reader token.
func NewSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// Hash is a secret or token as the Object stores it.
func Hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(h[:])
}

// At formats t as a config's at.
func At(t time.Time) string { return t.UTC().Format(AtFormat) }

// Delegation is one machine's hand on the party's feed config: the
// root-signed public card, as X-Peer-Card carries it, and the identity key
// that signs under it.
type Delegation struct {
	card string
	key  ecc.ECPrivateKeyable
}

// NewDelegation is id's delegation under the party's public card.
func NewDelegation(public *card.Signed, id *keys.Identity) *Delegation {
	return &Delegation{card: CardHeaderValue(public), key: id.KeyPair.PrivateKey()}
}

// CardHeaderValue is a signed card as X-Peer-Card carries it: base64url, no
// padding, of the root's signature then the card bytes — the envelope #0 form.
func CardHeaderValue(s *card.Signed) string {
	return b64.EncodeToString(append(append([]byte(nil), s.Sig...), s.Body...))
}

// Card is the X-Peer-Card value.
func (d *Delegation) Card() string { return d.card }

// Sign is the identity key's XEdDSA signature over msg (ecc.CalculateSignature,
// as a room card's) as X-Peer-Signature carries it: base64url, no padding.
func (d *Delegation) Sign(msg []byte) string {
	sig := ecc.CalculateSignature(d.key, msg)
	return b64.EncodeToString(sig[:])
}

// Errors a caller can match.
var (
	// ErrStale is the Object's 409 on a PUT: it holds a config as new or
	// newer — another machine of the party wrote one; reload the record and
	// PUT again.
	ErrStale = errors.New("feed config: the worker holds a newer config")
	// ErrNoConfig is the Object's 404 on a GET: no config is set up.
	ErrNoConfig = errors.New("feed config: the worker holds no config for this party")
)

// Refusal is the Object's word on a request it did not take.
type Refusal struct {
	Status  int
	Code    string
	Message string
}

func (r *Refusal) Error() string {
	if r.Message == "" {
		return fmt.Sprintf("feed config: the worker answered %d %s", r.Status, r.Code)
	}
	return fmt.Sprintf("feed config: the worker answered %d %s: %s", r.Status, r.Code, r.Message)
}

// PutConfig writes c as the party's config on the feed at url (the worker
// base) under d. Readers nil is sent as an empty list.
func PutConfig(ctx context.Context, client *http.Client, url, party string, c *Config, d *Delegation) error {
	cc := *c
	if cc.Readers == nil {
		cc.Readers = []string{}
	}
	body, err := json.Marshal(cc)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, configURL(url, party), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CardHeader, d.card)
	req.Header.Set(SignatureHeader, d.Sign(body))
	_, err = do(client, req)
	return err
}

// GetConfig reads the config the Object holds, the request signed over at.
func GetConfig(ctx context.Context, client *http.Client, url, party string, at time.Time, d *Delegation) (*Config, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL(url, party), nil)
	if err != nil {
		return nil, err
	}
	a := At(at)
	req.Header.Set(CardHeader, d.card)
	req.Header.Set(AtHeader, a)
	req.Header.Set(SignatureHeader, d.Sign([]byte(a)))
	b, err := do(client, req)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("feed config: the worker's answer does not read: %v", err)
	}
	return &c, nil
}

func configURL(url, party string) string {
	return strings.TrimSuffix(url, "/") + "/feed/" + party + "/config"
}

// do runs one request: a 2xx returns the body, a refusal its words.
func do(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if resp.StatusCode/100 == 2 {
		return b, nil
	}
	var r struct{ Error, Code string }
	json.Unmarshal(b, &r)
	switch {
	case resp.StatusCode == http.StatusConflict:
		return nil, ErrStale
	case resp.StatusCode == http.StatusNotFound && r.Code == "no_config":
		return nil, ErrNoConfig
	}
	return nil, &Refusal{Status: resp.StatusCode, Code: r.Code, Message: r.Error}
}
