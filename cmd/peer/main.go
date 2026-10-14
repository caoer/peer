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
  version   print the version
`)
}
