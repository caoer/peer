// Command peer is an end-to-end encrypted messaging CLI for agents.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// version is set at build time with -ldflags "-X main.version=..." (the
// release binaries); a `go install …@<tag>` build carries the tag in its
// build info instead, and a plain `go build` carries neither.
var version = "dev"

func main() {
	bi, ok := debug.ReadBuildInfo()
	version = versionFrom(version, bi, ok)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// versionFrom is the stamped version when there is one, else the module
// version the Go toolchain recorded for a `go install …@<tag>` build, else "dev".
func versionFrom(stamped string, bi *debug.BuildInfo, ok bool) string {
	if stamped != "" && stamped != "dev" {
		return stamped
	}
	if ok && bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "peer %s\n", version)
		return 0
	case "init":
		return cmdInit(args[1:], stdout, stderr)
	case "invite":
		return cmdInvite(args[1:], stdout, stderr)
	case "accept":
		return cmdAccept(args[1:], stdout, stderr)
	case "confirm":
		return cmdConfirm(args[1:], stdout, stderr)
	case "send":
		return cmdSend(args[1:], stdout, stderr)
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	case "forget":
		return cmdForget(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	case "fetch":
		return cmdFetch(args[1:], stdout, stderr)
	case "card":
		return cmdCard(args[1:], stdout, stderr)
	case "keys":
		return cmdKeys(args[1:], stdout, stderr)
	case "identity":
		return cmdIdentity(args[1:], stdout, stderr)
	case "room":
		return cmdRoom(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "peer: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: peer <command> [args]

commands:
  init      generate the root key, identity and party keys [--dir D]
  invite    open a channel for a peer and print the invite link
            [--dir D] [--relay URL] [--login USER:TOKEN] <name>
  accept    join the channel a link names and print the verification code
            [--dir D] [--name N] <link>
  confirm   check the peer's identity and code, pin its card, send yours
            [--dir D] [--code 8-digits] <name>
  send      encrypt a message and put it on the peer's channel
            [--dir D] [--kind K] [--from AGENT] [--text T | --file F] <name>[/<agent>]
            (--kind doc|file: --file is attached, encrypted, as a blob)
            or seal it into a room, to every member or to the --to subset
            [--dir D] [--kind K] [--from AGENT] [--text T | --file F]
            [--to MEMBER[/AGENT],...] <room>
  serve     pull every channel and room, decrypt, deliver into inbox/ or quarantine/;
            a doc or file's content lands in quarantine/<id>/<name>;
            rotate the signed prekey and restock one-time prekeys;
            between rounds, hold the relay's push socket per channel and
            per room
            [--dir D] [--deliver DIR] [--once] [--every 30s]
  forget    forget a peer: a bye on its channel, then its roster entry and
            channel state dropped, so the name is free for a new invite;
            your adds and handovers over that channel are withdrawn, your
            seats in rooms are kept (a room you read through it: leave first)
            [--dir D] <name>
  status    print every peer from the local store, and its roster page row;
            one line per room: idx, members, cursor, dropped, reported
            [--dir D] [--json]
  fetch     fetch a quarantined doc or file's content again
            [--dir D] [--deliver DIR] <message id | record path>
  card      publish: sign your card with the root key, put it on the state
            for every host and send it on every confirmed channel
                                     card publish [--dir D]
  keys      accept or reject a peer's new identity key that serve holds
            keys accept [--dir D] <name> | keys reject [--dir D] <name>
  identity  rotate: a new identity key — the root signs a card retiring the
            old one, every session is dropped, the state is re-sealed and a
            new identity.json written; prints the cost and refuses without --yes
                                     identity rotate [--dir D] [--yes]
  room      a sealed room on your relay: create it (you are idx 0, its
            admin; --add fixes who may add: admins or members), add a peer
            over its confirmed channel (serve runs the rest: their accept,
            the mint, their room card, the roster record, the token), list
            the members, each marked you, matches your channel or vouched
            by the admin; remove a member (the roster record, then the
            revoke), leave (your leave record, then your revoke; the last
            admin hands over or closes), hand the room to a member (the
            handover record, its admin token over the channel), close it
            (everyone removed and revoked, a feed's link with them, the
            state dropped), or rotate
            your seal key now (serve rotates it daily). A --feed room has
            one writer, you: members read, and its link lets anyone read
            it — link prints it, link --rotate makes a new one and cuts
            every old holder off; follow reads a feed from its link alone
            (on an empty directory it makes the party), and serve delivers
            its records as room records
            room create [--dir D] [--relay URL] [--login USER:TOKEN]
                        [--add admins|members] [--feed] <name>
            room add [--dir D] [--read] <room> <peer>
            room members [--dir D] <room>
            room remove [--dir D] <room> <peer | party id | idx>
            room leave [--dir D] <room>
            room handover [--dir D] <room> <peer>
            room close [--dir D] <room>
            room rotate [--dir D] <room>
            room link [--dir D] [--rotate] <room>
            room follow [--dir D] [--name N] <feed link>
  version   print the version

the card any command sends is the one on the state (record "card"), signed by
the root key where root.json is: peer init writes the first, card publish
and identity rotate the rest; a fleet host holds no root.json.

flags come before the name or link. config.json in the peer directory holds
relay, login, agents, details, state (dir, or page + slug + login),
deliver, roster (page + slug + login: the private roster page serve writes
each round), keys (signedPrekeyEvery, oneTimeMin), push (pullEvery: pull
a channel after this many pushed messages, default 10) and ucc (root, seats,
serviceRetries: delivery by the fleet's seat map — a seat row's message,
and a human row's, is an inbox record in the session of the seat the row
names; a room record that names no agent lands in the session of each row
whose rooms column names the room (by name, id or *), group: its room id; a service row's is an HTTPS POST of the record as JSON to the row's
URL, tried again each round up to serviceRetries, default 20; the POST
carries no signature: the URL is the service's secret, and verified: true
means peer verified the sender).
`)
}
