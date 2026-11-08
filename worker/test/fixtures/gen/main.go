// Command gen writes the card fixtures worker/test/sign.spec.ts and
// worker/test/feed.spec.ts verify: for two throwaway parties, the root-signed
// public card as X-Peer-Card carries it (signature ‖ card bytes, base64url),
// feed configs signed by the identity key (XEdDSA, ecc.CalculateSignature as
// peer feed setup signs), a GET's X-Peer-At signature, and the refusal cases
// — the same body signed by the root key, a signature over empty bytes.
//
//	go run ./worker/test/fixtures/gen            (from the repo root)
//
// It writes worker/test/fixtures/card-cases.json. With -shared it also writes
// worker/test/fixtures/config-signed.json in the shape cmd/peer/feed_test.go
// -update writes, as a stand-in until that test's file replaces it.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"go.mau.fi/libsignal/ecc"
)

// The source secret and reader tokens feed.spec.ts opens sockets with.
var (
	secret = "src_" + strings.Repeat("7", 43)
	tokenA = "tok_" + strings.Repeat("a", 43)
	tokenB = "tok_" + strings.Repeat("b", 43)
)

var b64 = base64.RawURLEncoding

type party struct {
	root *keys.Root
	id   *keys.Identity
	ID   string
	Card string
}

type signed struct {
	Body      string `json:"body"`
	Signature string `json:"signature"`
}

type read struct {
	At             string `json:"at"`
	Signature      string `json:"signature"`
	EmptySignature string `json:"emptySignature"`
}

type partyOut struct {
	Party      string            `json:"party"`
	Card       string            `json:"card"`
	Configs    map[string]signed `json:"configs"`
	Read       read              `json:"read"`
	RootSigned signed            `json:"rootSigned"`
}

type shared struct {
	Party       string `json:"party"`
	Body        string `json:"body"`
	Card        string `json:"card"`
	Signature   string `json:"signature"`
	At          string `json:"at"`
	AtSignature string `json:"atSignature"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func newParty(issued time.Time) party {
	root, err := keys.GenerateRoot()
	must(err)
	id, err := keys.GenerateIdentity(root.Public())
	must(err)
	pk, err := keys.GeneratePartyKeys(id, 1)
	must(err)
	c := card.New(id, pk, []card.Agent{{ID: "advisor", Accepts: []string{"text"}}}, []string{"https://peer.0xtau.com/peer"}, issued)
	s, err := card.Sign(c, root)
	must(err)
	packed := append(append([]byte{}, s.Sig...), s.Body...)
	return party{root: root, id: id, ID: c.Party, Card: b64.EncodeToString(packed)}
}

func (p party) sign(msg []byte) string {
	sig := ecc.CalculateSignature(p.id.KeyPair.PrivateKey(), msg)
	return b64.EncodeToString(sig[:])
}

func (p party) rootSign(msg []byte) string { return b64.EncodeToString(ed25519.Sign(p.root.Key, msg)) }

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// The PUT body as peer feed setup marshals it, in this key order.
func body(party, at string, readers []string) string {
	b, err := json.Marshal(struct {
		V       int      `json:"v"`
		Party   string   `json:"party"`
		At      string   `json:"at"`
		Source  string   `json:"source"`
		Readers []string `json:"readers"`
	}{1, party, at, hash(secret), readers})
	must(err)
	return string(b)
}

func (p party) out() partyOut {
	initial := body(p.ID, "2026-11-08T16:00:00Z", []string{hash(tokenA), hash(tokenB)})
	update := body(p.ID, "2026-11-08T16:01:00Z", []string{hash(tokenA)})
	at := "2026-11-08T16:00:30Z"
	return partyOut{
		Party: p.ID,
		Card:  p.Card,
		Configs: map[string]signed{
			"initial": {initial, p.sign([]byte(initial))},
			"update":  {update, p.sign([]byte(update))},
		},
		Read:       read{at, p.sign([]byte(at)), p.sign(nil)},
		RootSigned: signed{initial, p.rootSign([]byte(initial))},
	}
}

func write(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(path, append(b, '\n'), 0o644))
	fmt.Println("wrote", path)
}

func main() {
	dir := flag.String("out", "worker/test/fixtures", "the fixtures directory")
	sharedToo := flag.Bool("shared", false, "also write config-signed.json (cmd/peer/feed_test.go -update owns it)")
	flag.Parse()
	issued := time.Date(2026, 11, 8, 15, 0, 0, 0, time.UTC)
	p1, p2 := newParty(issued), newParty(issued)
	write(filepath.Join(*dir, "card-cases.json"), map[string]partyOut{"p1": p1.out(), "p2": p2.out()})
	if *sharedToo {
		o := p1.out()
		write(filepath.Join(*dir, "config-signed.json"), shared{
			Party: o.Party, Body: o.Configs["initial"].Body, Card: o.Card, Signature: o.Configs["initial"].Signature,
			At: o.Read.At, AtSignature: o.Read.Signature,
		})
	}
}
