package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/caoer/peer/internal/feed"
	"github.com/caoer/peer/internal/store"
)

// peer feed sets a party's reader feed up and mints its reader links, on any
// machine of the party (plan-delivery decision 33): no managing party, no
// root act. config.json names the feed by url; the source secret and the
// reader list live in the shared state record feed (internal/store), which
// every machine reads and writes under CAS; the worker holds the hashes, in a
// config each command PUTs signed by this machine's identity key under the
// party's root-signed card — the card is the delegation. A reader token is
// printed once and stored nowhere: the record keeps its hash, label and time.

func feedUsage(w io.Writer) {
	fmt.Fprint(w, `usage: peer feed setup [--dir D] [--reset]
       peer feed link [--dir D] [--label L]
       peer feed revoke [--dir D] <label | hash prefix>
       peer feed show [--dir D] [--remote]
`)
}

// feedNotSetUp is what a host with feed.url and no feed record says.
const feedNotSetUp = "feed: not set up — peer feed setup on any machine of this party"

// feedTries bounds the CAS reloads and the re-PUTs on another machine's write.
const feedTries = 5

// labelMax bounds a reader's label.
const labelMax = 64

func cmdFeed(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		feedUsage(stderr)
		return 2
	}
	switch args[0] {
	case "setup":
		return cmdFeedSetup(args[1:], stdout, stderr)
	case "link":
		return cmdFeedLink(args[1:], stdout, stderr)
	case "revoke":
		return cmdFeedRevoke(args[1:], stdout, stderr)
	case "show":
		return cmdFeedShow(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		feedUsage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "peer feed: unknown command %q\n", args[0])
	feedUsage(stderr)
	return 2
}

func cmdFeedSetup(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("feed setup", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	reset := fl.Bool("reset", false, "mint a new source secret: every serving host dials with it at its next round")
	fl.Usage = func() {
		fmt.Fprint(stderr, "usage: peer feed setup [--dir D] [--reset]\n\nSets this party's reader feed up on the worker config.json feed.url names:\nmints the source secret, puts the config signed by this machine's identity\nkey under the party's card, and commits the shared state record feed. Run it\nonce, on any machine of the party; it refuses while the record exists, and\n--reset mints a new source secret, the reader links kept.\n")
	}
	if code, done := parseFlags(fl, args); done {
		return code
	}
	if fl.NArg() != 0 {
		fl.Usage()
		return 2
	}
	if err := runFeedSetup(context.Background(), *dirFlag, *reset, stdout); err != nil {
		fmt.Fprintf(stderr, "peer feed setup: %v\n", err)
		return 1
	}
	return 0
}

func cmdFeedLink(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("feed link", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	label := fl.String("label", "", "the link's label, for show and revoke (default this host's name)")
	fl.Usage = func() {
		fmt.Fprint(stderr, "usage: peer feed link [--dir D] [--label L]\n\nMints a reader link to this party's feed and prints it once: the token is in\nno file, the record keeps its hash. Run it on any machine of the party, for\nyour own link; peer feed revoke <label> takes it back.\n")
	}
	if code, done := parseFlags(fl, args); done {
		return code
	}
	if fl.NArg() != 0 {
		fl.Usage()
		return 2
	}
	if err := runFeedLink(context.Background(), *dirFlag, *label, stdout); err != nil {
		fmt.Fprintf(stderr, "peer feed link: %v\n", err)
		return 1
	}
	return 0
}

func cmdFeedRevoke(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("feed revoke", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	fl.Usage = func() {
		fmt.Fprint(stderr, "usage: peer feed revoke [--dir D] <label | hash prefix>\n\nTakes a reader link off this party's feed: its page is refused at its next\nconnect. peer feed show lists the labels and hashes.\n")
	}
	if code, done := parseFlags(fl, args); done {
		return code
	}
	if fl.NArg() != 1 {
		fl.Usage()
		return 2
	}
	if err := runFeedRevoke(context.Background(), *dirFlag, fl.Arg(0), stdout); err != nil {
		fmt.Fprintf(stderr, "peer feed revoke: %v\n", err)
		return 1
	}
	return 0
}

func cmdFeedShow(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("feed show", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	remote := fl.Bool("remote", false, "also read the config the worker holds and compare")
	fl.Usage = func() {
		fmt.Fprint(stderr, "usage: peer feed show [--dir D] [--remote]\n\nLists this party's reader links as the feed record holds them: label, token\nhash, when. --remote reads the worker's config too and names what differs.\n")
	}
	if code, done := parseFlags(fl, args); done {
		return code
	}
	if fl.NArg() != 0 {
		fl.Usage()
		return 2
	}
	if err := runFeedShow(context.Background(), *dirFlag, *remote, stdout); err != nil {
		fmt.Fprintf(stderr, "peer feed show: %v\n", err)
		return 1
	}
	return 0
}

// feedParty opens the party under dir for a feed command: config.json names
// the feed. The commands take no root.json.
func feedParty(dir string) (*party, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, err
	}
	if p.cfg.Feed == nil {
		return nil, fmt.Errorf("%s names no feed: feed.url is the worker that serves this party's reader pages", configFile)
	}
	return p, nil
}

// feedDelegation is this machine's hand on the config: the party's public
// card on the state and the identity key, which signs under it.
func (p *party) feedDelegation(ctx context.Context) (*feed.Delegation, error) {
	public, _, _, err := p.ownCard(ctx, false)
	if err != nil {
		return nil, err
	}
	return feed.NewDelegation(public, p.id), nil
}

// putFeedConfig puts f as the party's config, dated now.
func (p *party) putFeedConfig(ctx context.Context, f *store.Feed, d *feed.Delegation) error {
	c := &feed.Config{V: feed.ConfigVersion, Party: p.partyID(), At: feed.At(time.Now()), Source: feed.Hash(f.Source), Readers: f.Hashes()}
	ctx, cancel := context.WithTimeout(ctx, serviceTimeout)
	defer cancel()
	return feed.PutConfig(ctx, serviceClient, p.cfg.Feed.URL, p.partyID(), c, d)
}

// syncFeedConfig puts the record as it stands. A 409 — another machine put a
// newer list meanwhile — re-reads the record and puts again.
func (p *party) syncFeedConfig(ctx context.Context, d *feed.Delegation) error {
	for try := 1; ; try++ {
		f, err := p.store.Feed(ctx)
		if err != nil {
			return err
		}
		if !f.Present() {
			return errors.New(feedNotSetUp)
		}
		err = p.putFeedConfig(ctx, f, d)
		if err == nil || !errors.Is(err, feed.ErrStale) || try >= feedTries {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// getFeedConfig reads the config the worker holds.
func (p *party) getFeedConfig(ctx context.Context, d *feed.Delegation) (*feed.Config, error) {
	ctx, cancel := context.WithTimeout(ctx, serviceTimeout)
	defer cancel()
	return feed.GetConfig(ctx, serviceClient, p.cfg.Feed.URL, p.partyID(), time.Now(), d)
}

// runFeedSetup mints the source secret, commits the feed record and puts the
// config. A record already there refuses unless reset — or, when the worker
// holds no config for it, is put again. On reset the reader links stay.
func runFeedSetup(ctx context.Context, dir string, reset bool, out io.Writer) error {
	p, err := feedParty(dir)
	if err != nil {
		return err
	}
	d, err := p.feedDelegation(ctx)
	if err != nil {
		return err
	}
	var f *store.Feed
	for try := 1; ; try++ {
		if f, err = p.store.Feed(ctx); err != nil {
			return err
		}
		if f.Present() && !reset {
			if _, err := p.getFeedConfig(ctx, d); !errors.Is(err, feed.ErrNoConfig) {
				if err != nil {
					return err
				}
				return fmt.Errorf("the feed is set up, %d reader links: peer feed link mints a link; peer feed setup --reset mints a new source secret", len(f.Readers))
			}
			if err := p.putFeedConfig(ctx, f, d); err != nil {
				return err
			}
			fmt.Fprintf(out, "feed record found; the worker held no config for %s: put it at %s\n", p.partyID(), p.cfg.Feed.URL)
			return nil
		}
		if f.Source, err = feed.NewSecret(); err != nil {
			return err
		}
		err = f.Commit(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || try >= feedTries {
			return err
		}
	}
	if err := p.putFeedConfig(ctx, f, d); err != nil {
		if errors.Is(err, feed.ErrStale) {
			err = p.syncFeedConfig(ctx, d)
		}
		if err != nil {
			return fmt.Errorf("the feed record is committed; the worker did not take the config: %w — run peer feed setup again to put it", err)
		}
	}
	fmt.Fprintf(out, "feed set up for %s at %s\n", p.partyID(), p.cfg.Feed.URL)
	if reset {
		fmt.Fprintf(out, "new source secret; every serving host dials with it at its next round; %d reader links kept\n", len(f.Readers))
	}
	return nil
}

// runFeedLink mints a reader token, records its hash under label by CAS,
// puts the full list, and prints the link once.
func runFeedLink(ctx context.Context, dir, label string, out io.Writer) error {
	if label == "" {
		label = feedHost()
	}
	if err := checkLabel(label); err != nil {
		return err
	}
	p, err := feedParty(dir)
	if err != nil {
		return err
	}
	d, err := p.feedDelegation(ctx)
	if err != nil {
		return err
	}
	token, err := feed.NewSecret()
	if err != nil {
		return err
	}
	r := store.FeedReader{Hash: feed.Hash(token), Label: label, At: feed.At(time.Now())}
	for try := 1; ; try++ {
		f, err := p.store.Feed(ctx)
		if err != nil {
			return err
		}
		if !f.Present() {
			return errors.New(feedNotSetUp)
		}
		f.Readers = append(f.Readers, r)
		err = f.Commit(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || try >= feedTries {
			return err
		}
	}
	if err := p.syncFeedConfig(ctx, d); err != nil {
		return fmt.Errorf("the link is recorded under %q; the worker did not take the list: %w — the next link or revoke puts it again, or peer feed setup", label, err)
	}
	fmt.Fprintf(out, "%s/#p=%s&t=%s\n", strings.TrimSuffix(p.cfg.Feed.URL, "/"), p.partyID(), token)
	fmt.Fprintf(out, "reader %s · %s · %s — the link is printed once and kept nowhere; peer feed revoke %s takes it back\n", label, r.Hash, r.At, label)
	return nil
}

// runFeedRevoke takes the reader what names — a label, or a prefix of its
// hash — off the record by CAS and puts the list.
func runFeedRevoke(ctx context.Context, dir, what string, out io.Writer) error {
	p, err := feedParty(dir)
	if err != nil {
		return err
	}
	d, err := p.feedDelegation(ctx)
	if err != nil {
		return err
	}
	var gone store.FeedReader
	for try := 1; ; try++ {
		f, err := p.store.Feed(ctx)
		if err != nil {
			return err
		}
		if !f.Present() {
			return errors.New(feedNotSetUp)
		}
		var hits []int
		for i, r := range f.Readers {
			if namesReader(what, r) {
				hits = append(hits, i)
			}
		}
		switch len(hits) {
		case 0:
			return fmt.Errorf("no reader link is %q: peer feed show lists them by label and hash", what)
		case 1:
		default:
			names := make([]string, 0, len(hits))
			for _, i := range hits {
				names = append(names, f.Readers[i].Label+" "+f.Readers[i].Hash)
			}
			return fmt.Errorf("%q names %d reader links — give the hash: %s", what, len(hits), strings.Join(names, "; "))
		}
		gone = f.Readers[hits[0]]
		f.Readers = append(f.Readers[:hits[0]], f.Readers[hits[0]+1:]...)
		err = f.Commit(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || try >= feedTries {
			return err
		}
	}
	if err := p.syncFeedConfig(ctx, d); err != nil {
		return fmt.Errorf("%s is off the record; the worker did not take the list: %w — the next link or revoke puts it again", gone.Label, err)
	}
	fmt.Fprintf(out, "revoked %s · %s: its page is refused at its next connect\n", gone.Label, gone.Hash)
	return nil
}

// namesReader reports whether what is r's label or a prefix of its hash,
// with or without sha256:.
func namesReader(what string, r store.FeedReader) bool {
	if what == "" {
		return false
	}
	return r.Label == what || strings.HasPrefix(r.Hash, what) || strings.HasPrefix(strings.TrimPrefix(r.Hash, "sha256:"), what)
}

// runFeedShow lists the record's readers; remote reads the worker's config
// too and names each side's surplus.
func runFeedShow(ctx context.Context, dir string, remote bool, out io.Writer) error {
	p, err := feedParty(dir)
	if err != nil {
		return err
	}
	f, err := p.store.Feed(ctx)
	if err != nil {
		return err
	}
	if !f.Present() {
		fmt.Fprintln(out, feedNotSetUp)
		return nil
	}
	fmt.Fprintf(out, "feed %s · source %s · %d reader links\n", p.cfg.Feed.URL, feed.Hash(f.Source), len(f.Readers))
	for _, r := range f.Readers {
		fmt.Fprintf(out, "  %s · %s · %s\n", r.Label, r.Hash, r.At)
	}
	if !remote {
		return nil
	}
	d, err := p.feedDelegation(ctx)
	if err != nil {
		return err
	}
	c, err := p.getFeedConfig(ctx, d)
	if errors.Is(err, feed.ErrNoConfig) {
		fmt.Fprintln(out, "worker: no config — peer feed setup puts the record")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "worker: at %s · source %s · %d readers\n", c.At, c.Source, len(c.Readers))
	if c.Source != feed.Hash(f.Source) {
		fmt.Fprintln(out, "  the worker's source is not the record's: peer feed setup puts the record")
	}
	held := map[string]bool{}
	for _, h := range c.Readers {
		held[h] = true
	}
	for _, r := range f.Readers {
		if !held[r.Hash] {
			fmt.Fprintf(out, "  not on the worker: %s · %s\n", r.Label, r.Hash)
		}
		delete(held, r.Hash)
	}
	for h := range held {
		fmt.Fprintf(out, "  on the worker, not in the record: %s\n", h)
	}
	return nil
}

func checkLabel(label string) error {
	if len(label) > labelMax {
		return fmt.Errorf("label is %d bytes; at most %d", len(label), labelMax)
	}
	for _, r := range label {
		if r < ' ' || r == 0x7f {
			return errors.New("label holds a control character")
		}
	}
	return nil
}
