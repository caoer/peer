package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
)

func TestInitWritesAndRefusesTwice(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "peer")
	var out, errb bytes.Buffer
	if code := run([]string{"init", "--dir", dir}, &out, &errb); code != 0 {
		t.Fatalf("first init: code %d, stderr %s", code, errb.String())
	}
	for _, n := range []string{rootFile, identityFile, partyKeysFile} {
		fi, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", n, fi.Mode().Perm())
		}
	}
	before, _ := os.ReadFile(filepath.Join(dir, identityFile))

	out.Reset()
	errb.Reset()
	if code := run([]string{"init", "--dir", dir}, &out, &errb); code == 0 {
		t.Fatal("second init succeeded")
	}
	if !strings.Contains(errb.String(), "refusing to overwrite") {
		t.Fatalf("stderr %q", errb.String())
	}
	after, _ := os.ReadFile(filepath.Join(dir, identityFile))
	if !bytes.Equal(before, after) {
		t.Fatal("identity file changed by second init")
	}
}

// The files init writes load back and make a card that verifies against the party id.
func TestInitFilesMakeACard(t *testing.T) {
	dir := t.TempDir()
	party, err := initDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var root keys.Root
	var id keys.Identity
	var pk keys.PartyKeys
	for n, v := range map[string]json.Unmarshaler{rootFile: &root, identityFile: &id, partyKeysFile: &pk} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.UnmarshalJSON(b); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
	if len(pk.Prekeys) != keys.InitialPrekeys {
		t.Fatalf("%d prekeys, want %d", len(pk.Prekeys), keys.InitialPrekeys)
	}
	s, err := card.Sign(card.New(&id, &pk, nil, nil, time.Now()), &root)
	if err != nil {
		t.Fatal(err)
	}
	rootPub, err := keys.ParsePartyID(party)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := card.Verify(s, rootPub); err != nil {
		t.Fatal(err)
	}
}
