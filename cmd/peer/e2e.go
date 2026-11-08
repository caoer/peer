package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/e2e"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/room"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
)

// keygenNote is in peer e2e keygen --help, and every keygen prints it.
const keygenNote = `The secret stays with the human: keep it on your own machine and never on a
serving host. A host that holds it can read every message encrypted to it.
`

func e2eUsage(w io.Writer) {
	fmt.Fprint(w, `usage: peer e2e keygen
       peer e2e publish [--dir D] [<public key>]
       peer e2e revoke [--dir D] <public key>
       peer e2e decrypt --key <secret key> [file]
`)
}

// publishNote is in peer e2e publish --help: where a key comes from.
const publishNote = `The secret never leaves the browser or the person. A key born on the reader
page waits in the state record readers-pending, which publish with no argument
folds into details.readers; a key from peer e2e keygen is published by its
public half. Both append: a party's card lists every key it receives on.
`

// cmdE2E is message-level encryption on top of the channel: keys a human
// holds, published on the card, and a decrypt that runs where the secret is.
func cmdE2E(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		e2eUsage(stderr)
		return 2
	}
	switch args[0] {
	case "keygen":
		return cmdE2EKeygen(args[1:], stdout, stderr)
	case "publish":
		return cmdE2EPublish(args[1:], stdout, stderr)
	case "revoke":
		return cmdE2ERevoke(args[1:], stdout, stderr)
	case "decrypt":
		return cmdE2EDecrypt(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		e2eUsage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "peer e2e: unknown command %q\n", args[0])
	e2eUsage(stderr)
	return 2
}

// parseFlags parses fl, a --help being a success.
func parseFlags(fl *flag.FlagSet, args []string) (code int, done bool) {
	switch err := fl.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return 0, true
	case err != nil:
		return 2, true
	}
	return 0, false
}

func cmdE2EKeygen(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("e2e keygen", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: peer e2e keygen\n\nPrints a new key pair: the public key, for peer e2e publish, then the secret key.\n\n%s", keygenNote)
	}
	if code, done := parseFlags(fl, args); done {
		return code
	}
	if fl.NArg() != 0 {
		fl.Usage()
		return 2
	}
	pub, secret, err := e2e.GenerateKey()
	if err != nil {
		fmt.Fprintf(stderr, "peer e2e keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n%s\n", pub, secret)
	fmt.Fprint(stderr, keygenNote)
	return 0
}

func cmdE2EPublish(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("e2e publish", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: peer e2e publish [--dir D] [<public key>]\n\nAdds the public key — or, with none, every key waiting in readers-pending — to\nthis party's config.json details.readers, signs the card and sends it on every\nconfirmed channel. Run it where root.json is; the secret key is not needed and\ndoes not belong here.\n\n%s", publishNote)
	}
	if code, done := parseFlags(fl, args); done {
		return code
	}
	if fl.NArg() > 1 {
		fl.Usage()
		return 2
	}
	var err error
	if fl.NArg() == 1 {
		err = runE2EPublish(context.Background(), *dirFlag, fl.Arg(0), stdout)
	} else {
		err = runE2EFold(context.Background(), *dirFlag, stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "peer e2e publish: %v\n", err)
		return 1
	}
	return 0
}

func cmdE2ERevoke(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("e2e revoke", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	fl.Usage = func() {
		fmt.Fprintln(stderr, "usage: peer e2e revoke [--dir D] <public key>\n\nTakes the public key off this party's config.json details.readers, signs the\ncard and sends it on every confirmed channel. Run it where root.json is.")
	}
	if code, done := parseFlags(fl, args); done {
		return code
	}
	if fl.NArg() != 1 {
		fl.Usage()
		return 2
	}
	if err := runE2ERevoke(context.Background(), *dirFlag, fl.Arg(0), stdout); err != nil {
		fmt.Fprintf(stderr, "peer e2e revoke: %v\n", err)
		return 1
	}
	return 0
}

// rootParty opens the party under dir for a command that signs the card.
func rootParty(dir string) (string, *party, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return "", nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return "", nil, err
	}
	if p.root == nil {
		return "", nil, errNoRoot(dir)
	}
	return dir, p, nil
}

// runE2EPublish adds pub to details.readers in config.json, every other key
// of the file left as it is, and publishes the card it now describes.
func runE2EPublish(ctx context.Context, dir, pub string, out io.Writer) error {
	if _, err := e2e.ParsePublic(pub); err != nil {
		return err
	}
	dir, _, err := rootParty(dir)
	if err != nil {
		return err
	}
	if err := writeE2EDetails(filepath.Join(dir, configFile), func(keys []string) []string { return mergeKeys(keys, []string{pub}) }); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s details.readers names %s\n", configFile, pub)
	return runCardPublish(ctx, dir, out)
}

// runE2EFold adds every key waiting in readers-pending to details.readers,
// publishes the card, and takes those keys out of the record; one added
// meanwhile stays for the next publish.
func runE2EFold(ctx context.Context, dir string, out io.Writer) error {
	dir, p, err := rootParty(dir)
	if err != nil {
		return err
	}
	rec, _, err := p.loadPendingReaders(ctx)
	if err != nil {
		return err
	}
	if len(rec.Keys) == 0 {
		fmt.Fprintln(out, "no reader key pending; the card is as it was")
		return nil
	}
	var pubs []string
	for _, k := range rec.Keys {
		if _, err := e2e.ParsePublic(k.Key); err != nil {
			return fmt.Errorf("%s: %w", readersPendingKey, err)
		}
		pubs = append(pubs, k.Key)
	}
	if err := writeE2EDetails(filepath.Join(dir, configFile), func(keys []string) []string { return mergeKeys(keys, pubs) }); err != nil {
		return err
	}
	for _, k := range rec.Keys {
		fmt.Fprintf(out, "%s details.readers takes %s (reader %s, %s)\n", configFile, k.Key, tail(k.Reader), k.At)
	}
	if err := runCardPublish(ctx, dir, out); err != nil {
		return err
	}
	if err := p.dropPendingReaders(ctx, pubs); err != nil {
		return fmt.Errorf("the card is published; %s not cleared: %w", readersPendingKey, err)
	}
	return nil
}

// runE2ERevoke takes pub off details.readers and publishes the card.
func runE2ERevoke(ctx context.Context, dir, pub string, out io.Writer) error {
	if _, err := e2e.ParsePublic(pub); err != nil {
		return err
	}
	dir, _, err := rootParty(dir)
	if err != nil {
		return err
	}
	found := false
	err = writeE2EDetails(filepath.Join(dir, configFile), func(keys []string) []string {
		var kept []string
		for _, k := range keys {
			if k == pub {
				found = true
				continue
			}
			kept = append(kept, k)
		}
		return kept
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s is not in %s details.readers", pub, configFile)
	}
	fmt.Fprintf(out, "%s details.readers no longer names %s\n", configFile, pub)
	return runCardPublish(ctx, dir, out)
}

// writeE2EDetails rewrites config.json details.readers with edit's keys —
// the member is removed when none remain — every other key of the file left
// as it is.
func writeE2EDetails(path string, edit func(keys []string) []string) error {
	top := map[string]json.RawMessage{}
	mode := fs.FileMode(0o600)
	switch b, err := os.ReadFile(path); {
	case err == nil:
		if err := json.Unmarshal(b, &top); err != nil {
			return fmt.Errorf("%s: %w", configFile, err)
		}
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		mode = st.Mode().Perm()
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	details := map[string]json.RawMessage{}
	if raw := top["details"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &details); err != nil || details == nil {
			return fmt.Errorf("%s: details is not an object", configFile)
		}
	}
	var keys []string
	if raw := details[e2e.DetailsMember]; len(raw) > 0 {
		var d e2e.Details
		if err := json.Unmarshal(raw, &d); err != nil {
			return fmt.Errorf("%s: details.%s: %w", configFile, e2e.DetailsMember, err)
		}
		keys = d.Keys
	}
	keys = edit(keys)
	var err error
	if len(keys) == 0 {
		delete(details, e2e.DetailsMember)
	} else if details[e2e.DetailsMember], err = json.Marshal(e2e.Details{V: e2e.Version, Suite: e2e.Suite, Keys: keys}); err != nil {
		return err
	}
	if top["details"], err = json.Marshal(details); err != nil {
		return err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(top); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func cmdE2EDecrypt(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("e2e decrypt", flag.ContinueOnError)
	fl.SetOutput(stderr)
	keyFlag := fl.String("key", "", "the secret key, x25519-secret:…")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: peer e2e decrypt --key <secret key> [file]\n\nPrints the plaintext of an inbox record or a bare envelope, from file or stdin.\n\n%s", keygenNote)
	}
	if code, done := parseFlags(fl, args); done {
		return code
	}
	if *keyFlag == "" || fl.NArg() > 1 {
		fl.Usage()
		return 2
	}
	var b []byte
	var err error
	if fl.NArg() == 1 {
		b, err = os.ReadFile(fl.Arg(0))
	} else {
		b, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(stderr, "peer e2e decrypt: %v\n", err)
		return 1
	}
	plain, err := e2e.Open(recordBody(b), *keyFlag)
	if err != nil {
		fmt.Fprintf(stderr, "peer e2e decrypt: %v\n", err)
		return 1
	}
	stdout.Write(plain)
	return 0
}

// recordBody is what follows a record's frontmatter; b itself when it has none.
func recordBody(b []byte) []byte {
	if !bytes.HasPrefix(b, []byte("---\n")) {
		return b
	}
	if _, body, ok := bytes.Cut(b[4:], []byte("\n---\n")); ok {
		return body
	}
	return b
}

// e2eSuite is the suite a body is encrypted under; "" for a plain body.
func e2eSuite(body []byte) string {
	suite, _ := e2e.Detect(body)
	return suite
}

// encryptOpts is peer send --encrypt: toKeys are the --to-key keys, sealed to
// beside the ones the peer's card publishes.
type encryptOpts struct {
	toKeys []string
}

// mergeKeys is the keys of a then b, each once.
func mergeKeys(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, k := range l {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// channelE2EKeys are the e2e keys on the peer's pinned card, nil when it
// publishes none.
func channelE2EKeys(ch *store.Channel) ([]string, error) {
	signed, root := ch.Card(), ch.Root()
	if signed == nil || root == nil {
		return nil, nil
	}
	c, err := card.Verify(signed, root)
	if err != nil {
		return nil, err
	}
	d, err := e2e.ParseDetails(c.Details)
	if err != nil || d == nil {
		return nil, err
	}
	return d.Keys, nil
}

// sealForPeer seals body to the peer's published keys and the --to-key keys,
// refused naming the peer when there is no key to seal to.
func sealForPeer(name string, ch *store.Channel, enc *encryptOpts, body []byte) ([]byte, error) {
	pubs, err := channelE2EKeys(ch)
	if err != nil {
		return nil, fmt.Errorf("%s: the e2e keys on its card: %w", name, err)
	}
	pubs = mergeKeys(pubs, enc.toKeys)
	if len(pubs) == 0 {
		return nil, fmt.Errorf("%s has published no e2e key: they run peer e2e publish, or name a key with --to-key", name)
	}
	return e2e.Seal(body, pubs)
}

// memberE2EKeys are the e2e keys on a room member's folded party card; nil
// when it publishes none or they cannot be read.
func memberE2EKeys(mem *room.Member) []string {
	root, err := keys.ParsePartyID(mem.Party)
	if err != nil {
		return nil
	}
	c, err := card.Verify(&card.Signed{Body: mem.Card.Body, Sig: mem.Card.Sig}, root)
	if err != nil {
		return nil
	}
	d, err := e2e.ParseDetails(c.Details)
	if err != nil || d == nil {
		return nil
	}
	return d.Keys
}

// sealForRoom seals body to the published keys of the members addrs names,
// or every other member when it names none; refused naming each member
// without a key. Your own records never come back, so you are not sealed to.
func (c *roomConn) sealForRoom(addrs []string, body []byte) ([]byte, error) {
	named := map[string]bool{}
	for _, a := range addrs {
		party, _ := splitAddr(a)
		named[party] = true
	}
	var pubs, keyless []string
	for _, mem := range c.st.Members() {
		if mem.Idx == c.st.Idx() || (len(addrs) > 0 && !named[mem.Party]) {
			continue
		}
		ks := memberE2EKeys(mem)
		if len(ks) == 0 {
			keyless = append(keyless, mem.Party)
		}
		pubs = append(pubs, ks...)
	}
	if len(keyless) > 0 {
		return nil, fmt.Errorf("room %s: nothing sent: no e2e key on the card the room holds for %v", c.ref.Name, keyless)
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("room %s: nobody else is in it to encrypt to", c.ref.Name)
	}
	return e2e.Seal(body, mergeKeys(pubs, nil))
}

// sealedTooLarge refuses a sealed message a relay record cannot carry.
func sealedTooLarge(m *session.Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > envelope.MaxBody {
		return fmt.Errorf("the encrypted message is %d bytes and a record holds at most %d bytes", len(b), envelope.MaxBody)
	}
	return nil
}
