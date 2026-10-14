package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caoer/peer/internal/attach"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/session"
)

// runSendFile sends a doc or file message (design §3.5, §5.2): the file is
// sealed under a one-time key, the ciphertext put on the channel's blob
// route, and only once the relay holds it does the message go — its body the
// descriptor naming the blob and carrying the key inside the ratchet
// envelope. A send that fails after the put leaves a blob nobody can open,
// which the relay drops after 30 days.
func runSendFile(ctx context.Context, warn io.Writer, dir, target, fromAgent, kind, path string) (*sendResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > attach.MaxSize {
		return nil, fmt.Errorf("%s is %d bytes; an attachment is at most %d", path, info.Size(), attach.MaxSize)
	}
	plain, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ct, d, err := attach.Seal(filepath.Base(path), plain)
	if err != nil {
		return nil, err
	}
	name, _ := splitAddr(target)
	_, pe, _, err := sendTarget(ctx, dir, name)
	if err != nil {
		return nil, err
	}
	b, err := relay.New(pe.Relay, nil).PutBlob(ctx, pe.Channel, pe.Token, ct)
	if err != nil {
		return nil, fmt.Errorf("the relay did not take %s, nothing was sent: %w", path, err)
	}
	d.Blob = b.ID
	body, err := d.Marshal()
	if err != nil {
		return nil, err
	}
	return runSend(ctx, warn, dir, target, fromAgent, kind, body)
}

// isAttachment reports whether a kind carries its content as a blob.
func isAttachment(kind string) bool { return kind == session.KindDoc || kind == session.KindFile }

// attachment is a doc or file message's record body: the descriptor, then
// one line saying where the content is or why it is not there. The content
// is fetched, unwrapped and verified now and written beside the record, as
// <deliver>/quarantine/<id>/<name>; a failure keeps nothing of it, and
// peer fetch <id> tries again (the record stays as born). A record already
// born — a replay — is left as it is and nothing is fetched.
func (sv *server) attachment(channel string, m *session.Message) []byte {
	if _, err := os.Stat(filepath.Join(sv.dir, string(deliver.Quarantine), m.ID+".md")); err == nil {
		return m.Body
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	path, err := sv.fetchAttachment(ctx, channel, m.ID, m.Body)
	body := append(bytes.TrimRight(append([]byte(nil), m.Body...), "\n"), "\n\n"...)
	if err != nil {
		fmt.Fprintf(sv.out, "%s %s: blob not fetched: %v\n", m.Kind, m.ID, err)
		return fmt.Appendf(body, "blob not fetched: %v; peer fetch %s tries again\n", err, m.ID)
	}
	rel, _ := filepath.Rel(filepath.Join(sv.dir, string(deliver.Quarantine)), path)
	fmt.Fprintf(sv.out, "fetched %s %s → %s\n", m.Kind, m.ID, path)
	return fmt.Appendf(body, "content: %s (sha256 verified)\n", filepath.ToSlash(rel))
}

// fetchAttachment gets the blob a descriptor names from the channel it came
// on, unwraps and verifies it, and writes it as <deliver>/quarantine/<id>/<name>
// — never anywhere else. A file already there is kept.
func (sv *server) fetchAttachment(ctx context.Context, channel, id string, body []byte) (string, error) {
	d, err := attach.Parse(body)
	if err != nil {
		return "", err
	}
	if !deliver.ValidID(id) {
		return "", fmt.Errorf("message id %q cannot name a directory", id)
	}
	r, err := roster.Load(ctx, sv.p.backend)
	if err != nil {
		return "", err
	}
	var pe *roster.Peer
	for i := range r.Peers {
		if r.Peers[i].Channel == channel {
			pe = &r.Peers[i]
		}
	}
	if pe == nil {
		return "", fmt.Errorf("channel %s is not on the roster", channel)
	}
	ct, err := relay.New(pe.Relay, nil).GetBlob(ctx, pe.Channel, pe.Token, d.Blob)
	if err != nil {
		var re *relay.Error
		if errors.As(err, &re) && re.Code != "" {
			return "", errors.New(re.Code)
		}
		return "", err
	}
	plain, err := attach.Open(d, ct)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(sv.dir, string(deliver.Quarantine), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, d.Name)
	var rnd [4]byte
	rand.Read(rnd[:])
	tmp := filepath.Join(dir, ".fetch."+hex.EncodeToString(rnd[:])+".tmp")
	if err := os.WriteFile(tmp, plain, 0o600); err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	return path, nil
}

// cmdFetch fetches a quarantined doc or file message's content again — for
// a record whose serve could not (the blob not yet there, the relay away).
// The channel is the one whose pinned party sent it.
func cmdFetch(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	deliverFlag := fl.String("deliver", "", "the delivery directory serve uses (default config.json deliver, else <dir>/deliver)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || !deliver.ValidID(fl.Arg(0)) {
		fmt.Fprintln(stderr, "usage: peer fetch [--dir D] [--deliver DIR] <message id>")
		return 2
	}
	id := fl.Arg(0)
	sv, err := openServer(*dirFlag, *deliverFlag, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "peer fetch: %v\n", err)
		return 1
	}
	path, err := sv.refetch(context.Background(), id)
	if err != nil {
		fmt.Fprintf(stderr, "peer fetch: %s: %v\n", id, err)
		return 1
	}
	fmt.Fprintf(stdout, "fetched %s → %s\n", id, path)
	return 0
}

// refetch reads the quarantine record for id and fetches its content from
// the channel of the party that sent it.
func (sv *server) refetch(ctx context.Context, id string) (string, error) {
	rec, err := os.ReadFile(filepath.Join(sv.dir, string(deliver.Quarantine), id+".md"))
	if err != nil {
		return "", err
	}
	from, kind, body, err := splitRecord(rec)
	if err != nil {
		return "", err
	}
	if !isAttachment(kind) {
		return "", fmt.Errorf("a %s message has no attachment", kind)
	}
	party, _ := splitAddr(from)
	r, err := roster.Load(ctx, sv.p.backend)
	if err != nil {
		return "", err
	}
	for _, pe := range r.Peers {
		ch, err := sv.p.store.Channel(ctx, pe.Channel)
		if err != nil {
			return "", err
		}
		if ch.Root() != nil && keys.PartyID(ch.Root()) == party {
			return sv.fetchAttachment(ctx, pe.Channel, id, body)
		}
	}
	return "", fmt.Errorf("no channel on the roster is with %s", party)
}

// splitRecord reads a delivery record's from and kind and its body.
func splitRecord(b []byte) (from, kind string, body []byte, err error) {
	s := string(b)
	head, rest, ok := strings.Cut(strings.TrimPrefix(s, "---\n"), "\n---\n")
	if !strings.HasPrefix(s, "---\n") || !ok {
		return "", "", nil, errors.New("the record has no frontmatter")
	}
	for _, line := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(line, ": ")
		switch k {
		case "from":
			from = v
		case "kind":
			kind = strings.Trim(v, `"`)
		}
	}
	return from, kind, []byte(rest), nil
}
