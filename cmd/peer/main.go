// Command peer is an end-to-end encrypted messaging CLI for agents.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
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
  serve     pull every channel, decrypt, deliver into inbox/ or quarantine/;
            a doc or file's content lands in quarantine/<id>/<name>;
            rotate the signed prekey and restock one-time prekeys;
            between rounds, hold the relay's push socket per channel
            [--dir D] [--deliver DIR] [--once] [--every 30s]
  status    print every peer from the local store, and its roster page row
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
names; a service row's is an HTTPS POST of the record as JSON to the row's
URL, tried again each round up to serviceRetries, default 20; the POST
carries no signature: the URL is the service's secret, and verified: true
means peer verified the sender).
`)
}
