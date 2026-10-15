package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	"github.com/caoer/peer/internal/store"
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

// withAttachment composes a doc or file message's record body before its
// birth — after the commit, so a crash mid-fetch replays from the spool: the
// descriptor, then serve's one line naming the content's local path or why
// it is not there. The content is fetched, unwrapped and verified now and written
// host-local as <deliver>/quarantine/<id>/<name>, wherever the record itself
// is born; a failure keeps nothing of it, and peer fetch <id> tries again.
// The spool entry on disk is untouched: a replay composes again.
func (sv *server) withAttachment(e *store.Entry) {
	m, err := session.UnmarshalMessage(e.Body)
	if err != nil || !isAttachment(m.Kind) {
		return // birth reports a body that does not open
	}
	m.Body = sv.attachment(e.Channel, m)
	if b, err := json.Marshal(m); err == nil {
		e.Body = b
	}
}

// attachment is the record body for a doc or file message m: the descriptor
// as serve marshals it, a blank line and serve's status line, so no byte the
// peer sent after its descriptor reaches the record. A body whose descriptor
// does not parse goes after serve's line, never before it.
func (sv *server) attachment(channel string, m *session.Message) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	path, err := sv.fetchAttachment(ctx, channel, m.ID, m.Body)
	line := fmt.Sprintf("content: %s (sha256 verified)\n", path)
	if err != nil {
		fmt.Fprintf(sv.out, "%s %s: blob not fetched: %v\n", m.Kind, m.ID, err)
		line = fmt.Sprintf("blob not fetched: %v; peer fetch %s tries again\n", err, m.ID)
	} else {
		fmt.Fprintf(sv.out, "fetched %s %s → %s\n", m.Kind, m.ID, path)
	}
	if d, err := attach.Parse(m.Body); err == nil {
		if desc, err := d.Marshal(); err == nil {
			return fmt.Appendf(desc, "\n\n%s", line)
		}
	}
	return fmt.Appendf(nil, "%s\n%s", line, m.Body)
}

// contentFetched reports whether a record body attachment composed says the
// content is on this host. Serve's line follows the one-line descriptor and
// a blank line, or opens the body when the descriptor did not parse, so the
// peer's bytes never stand where it is read.
func contentFetched(body []byte) bool {
	desc, line, _ := bytes.Cut(body, []byte("\n\n"))
	return bytes.HasPrefix(desc, []byte("{")) && bytes.HasPrefix(line, []byte("content: "))
}

// fetchAttachment gets the blob a descriptor names from the channel it came
// on, unwraps and verifies it, and writes it as <deliver>/quarantine/<id>/<name>
// — never anywhere else, never under a sessions root. A file already there is
// kept and not fetched again. The path returned is absolute.
func (sv *server) fetchAttachment(ctx context.Context, channel, id string, body []byte) (string, error) {
	d, err := attach.Parse(body)
	if err != nil {
		return "", err
	}
	if !deliver.ValidID(id) {
		return "", fmt.Errorf("message id %q cannot name a directory", id)
	}
	base, err := filepath.Abs(sv.dir)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, string(deliver.Quarantine), id)
	path := filepath.Join(dir, d.Name)
	if _, err := os.Stat(path); err == nil {
		return path, nil // fetched before: a replay, or a second host on this disk
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
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

// idLast marks the last argument as the positional one when it begins with
// '-' but is no flag fl defines: a message id is base64url, so one in 64
// begins with '-', and flags go before it.
func idLast(fl *flag.FlagSet, args []string) []string {
	n := len(args)
	if n == 0 || !strings.HasPrefix(args[n-1], "-") || args[n-1] == "--" || (n > 1 && args[n-2] == "--") {
		return args
	}
	name, _, _ := strings.Cut(strings.TrimLeft(args[n-1], "-"), "=")
	if name == "h" || name == "help" || fl.Lookup(name) != nil {
		return args
	}
	return append(append(append([]string(nil), args[:n-1]...), "--"), args[n-1])
}

// cmdFetch fetches a quarantined doc or file message's content again — for
// a record whose serve could not (the blob not yet there, the relay away).
// The channel is the one whose pinned party sent it; the content lands
// host-local in <deliver>/quarantine/<id>/<name> as serve's would.
func cmdFetch(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	deliverFlag := fl.String("deliver", "", "the delivery directory serve uses (default config.json deliver, else <dir>/deliver)")
	if err := fl.Parse(idLast(fl, args)); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer fetch [--dir D] [--deliver DIR] <message id | record path>")
		return 2
	}
	sv, err := openServer(*dirFlag, *deliverFlag, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "peer fetch: %v\n", err)
		return 1
	}
	// The record is <deliver>/quarantine/<id>.md, or wherever the path given
	// says — a fleet host births it under its UCC root.
	id, record := fl.Arg(0), ""
	if strings.HasSuffix(id, ".md") {
		record, id = id, strings.TrimSuffix(filepath.Base(id), ".md")
	} else {
		record = filepath.Join(sv.dir, string(deliver.Quarantine), id+".md")
	}
	if !deliver.ValidID(id) {
		fmt.Fprintf(stderr, "peer fetch: %q is not a message id\n", id)
		return 2
	}
	path, err := sv.refetch(context.Background(), id, record)
	if err != nil {
		fmt.Fprintf(stderr, "peer fetch: %s: %v\n", id, err)
		return 1
	}
	fmt.Fprintf(stdout, "fetched %s → %s\n", id, path)
	return 0
}

// refetch reads the quarantine record for id and fetches its content from
// the channel of the party that sent it.
func (sv *server) refetch(ctx context.Context, id, record string) (string, error) {
	rec, err := os.ReadFile(record)
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
