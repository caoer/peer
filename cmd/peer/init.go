package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/store"
)

// The files init writes under the peer directory.
const (
	rootFile      = "root.json"     // cold root key: move it off the fleet
	identityFile  = "identity.json" // identity key pair + registrationId: sops-nix replicates it
	partyKeysFile = "keys.json"     // party keys record: signed prekey + one-time prekeys
)

// peerDir is --dir, else $PEER_HOME, else <user config dir>/peer.
func peerDir(flagDir string) (string, error) {
	if flagDir != "" {
		return flagDir, nil
	}
	if d := os.Getenv("PEER_HOME"); d != "" {
		return d, nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "peer"), nil
}

func cmdInit(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("init", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	dir, err := peerDir(*dirFlag)
	if err != nil {
		fmt.Fprintf(stderr, "peer init: %v\n", err)
		return 1
	}
	party, err := initDir(dir)
	if err != nil {
		fmt.Fprintf(stderr, "peer init: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "party %s\n", party)
	fmt.Fprintf(stdout, "wrote %s, %s, %s in %s\n", rootFile, identityFile, partyKeysFile, dir)
	fmt.Fprintf(stdout, "%s is the cold root key: keep it off the fleet\n", rootFile)
	return 0
}

// initDir generates a root key, identity and party keys and writes them to
// dir. It refuses when any of the three files exists.
func initDir(dir string) (string, error) {
	names := []string{rootFile, identityFile, partyKeysFile}
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			return "", fmt.Errorf("%s already exists; refusing to overwrite", filepath.Join(dir, n))
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	root, err := keys.GenerateRoot()
	if err != nil {
		return "", err
	}
	id, err := keys.GenerateIdentity(root.Public())
	if err != nil {
		return "", err
	}
	pk, err := keys.GeneratePartyKeys(id, keys.InitialPrekeys)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for i, v := range []any{root, id, pk} {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return "", err
		}
		if err := writeNew(filepath.Join(dir, names[i]), append(b, '\n')); err != nil {
			return "", err
		}
	}
	// The first card record, so a fresh party invites at once: on the state
	// config.json names when it is already in dir, else the file state under
	// dir. It carries config's relays and details and no agents under ucc;
	// peer card publish refreshes it from the whole config and the seat map.
	var cfg config
	if err := readJSON(filepath.Join(dir, configFile), &cfg); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	b, err := openBackend(dir, cfg, id)
	if err != nil {
		return "", err
	}
	p := &party{dir: dir, cfg: cfg, id: id, root: root, backend: b, store: store.New(b, id)}
	if _, err := p.signOwnCard(context.Background(), pk, time.Now()); err != nil {
		return "", fmt.Errorf("the three files are written; the card record is not (%v): run peer card publish", err)
	}
	return keys.PartyID(root.Public()), nil
}

// writeNew creates path with mode 0600, failing if it exists.
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
