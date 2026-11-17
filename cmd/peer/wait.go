package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caoer/peer/internal/store/pages"
)

// cmdWait blocks until the peer's row as peer status prints it changes — a
// message in or out (its last and unread), a state change — or, with no name, any peer's row or
// room line; then prints status for what changed and exits 0. It holds on
// the running serve's watch (statecopy.go), which sends a copy of the state
// on every change its live socket or its own writes bring: no page read,
// no timer. No serve on the directory, or serve going away, exits 1.
func cmdWait(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("wait", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	asJSON := fl.Bool("json", false, "print the changed peers as a JSON array")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() > 1 {
		fmt.Fprintln(stderr, "usage: peer wait [--dir D] [--json] [<name>]")
		return 2
	}
	name := fl.Arg(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rows, lines, err := runWait(ctx, *dirFlag, name)
	if err != nil {
		fmt.Fprintf(stderr, "peer wait: %v\n", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(stderr, "peer wait: %v\n", err)
			return 1
		}
		return 0
	}
	if len(rows) > 0 {
		printStatus(stdout, rows, time.Now())
	}
	for _, l := range lines {
		fmt.Fprintln(stdout, l)
	}
	return 0
}

// runWait returns, once the view changes, the rows that changed (the named
// peer's, or every changed peer's) and, with no name, the room lines that
// changed.
func runWait(ctx context.Context, dir, name string) ([]statusJSON, []string, error) {
	dir, err := peerDir(dir)
	if err != nil {
		return nil, nil, err
	}
	p, err := openParty(dir)
	if err != nil {
		return nil, nil, err
	}
	pb := statePage(p.backend)
	if pb == nil {
		return nil, nil, fmt.Errorf("the state is not a page: wait holds on serve's copy of the state page")
	}
	// The roster page is serve's output, not its state: wait reads none of it.
	p.cfg.Roster = rosterConfig{}

	// A peer's row as compared, by name; a room line, by itself.
	var before map[string]string
	var beforeRooms map[string]bool
	var rows []statusJSON
	var lines []string
	err = watchState(ctx, dir, func(snap pages.Snapshot) (bool, error) {
		pb.Hold(snap)
		all, err := runStatus(ctx, p, time.Now())
		if err != nil {
			return false, err
		}
		peers := map[string]string{}
		for _, s := range all {
			if name != "" && s.Name != name {
				continue
			}
			c := s
			// Active is a function of the clock; the cursor moves with every
			// envelope, and a message's commit is followed by its activity
			// (last, unread), which is what a waiter waits for.
			c.Active, c.Cursor = false, 0
			b, _ := json.Marshal(c)
			peers[s.Name] = string(b)
		}
		if name != "" && len(peers) == 0 {
			return false, fmt.Errorf("no peer named %q", name)
		}
		rooms := map[string]bool{}
		if name == "" {
			roomLines, err := runRoomStatus(ctx, p)
			if err != nil {
				return false, err
			}
			for _, l := range roomLines {
				rooms[l] = true
			}
		}
		if before == nil {
			before, beforeRooms = peers, rooms
			return false, nil
		}
		for _, s := range all {
			if v, ok := peers[s.Name]; ok && before[s.Name] != v {
				rows = append(rows, s)
			}
		}
		for n := range before {
			if _, ok := peers[n]; !ok {
				lines = append(lines, "peer "+n+": gone")
			}
		}
		for l := range rooms {
			if !beforeRooms[l] {
				lines = append(lines, l)
			}
		}
		return len(rows)+len(lines) > 0, nil
	})
	return rows, lines, err
}
