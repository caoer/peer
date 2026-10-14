package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
)

// Beside init's three files, the peer directory holds:
const (
	configFile = "config.json" // the party's relay, owner login, agents and details
	stateDir   = "state"       // the file store backend
	outboxDir  = "outbox"      // the send outbox (a store.Journal)
)

// prekeysPerChannel is how many one-time prekeys a party deposits on a new
// channel; the relay holds at most 200 per side.
const prekeysPerChannel = 10

// config is config.json: what init cannot know about the party.
type config struct {
	// Relay is the party's own relay base, e.g. https://example.com/peer;
	// Login is the ccc-pages owner login "<user>:<token>" that creates
	// channels on it. Both can be given as flags instead.
	Relay string `json:"relay,omitempty"`
	Login string `json:"login,omitempty"`
	// Agents is the card's agent list; Details is what the in-channel card
	// carries and envelope #0 does not (design §3.3).
	Agents  []card.Agent    `json:"agents,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

// party is an opened peer directory.
type party struct {
	dir     string
	cfg     config
	id      *keys.Identity
	root    *keys.Root // nil when root.json is not in the directory
	backend store.Backend
	store   *store.Store
	outbox  *store.Journal
}

// openParty reads the identity, the root key and config when present, and
// opens the state store and the outbox under dir.
func openParty(dir string) (*party, error) {
	p := &party{dir: dir}
	p.id = new(keys.Identity)
	if err := readJSON(filepath.Join(dir, identityFile), p.id); err != nil {
		return nil, fmt.Errorf("%w (run peer init first)", err)
	}
	root := new(keys.Root)
	switch err := readJSON(filepath.Join(dir, rootFile), root); {
	case err == nil:
		p.root = root
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	if err := readJSON(filepath.Join(dir, configFile), &p.cfg); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	b, err := file.New(filepath.Join(dir, stateDir))
	if err != nil {
		return nil, err
	}
	p.backend = b
	p.store = store.New(b, p.id)
	if p.outbox, err = store.OpenJournal(filepath.Join(dir, outboxDir)); err != nil {
		return nil, err
	}
	return p, nil
}

// partyID is the party's address: its root public key.
func (p *party) partyID() string { return keys.PartyID(p.id.Party) }

// keys loads the party keys record; an absent record is seeded from init's
// keys.json in memory, for the caller's commit.
func (p *party) keys(ctx context.Context) (*store.Keys, error) {
	k, err := p.store.Keys(ctx)
	if err != nil {
		return nil, err
	}
	if k.PartyKeys == nil {
		pk := new(keys.PartyKeys)
		if err := readJSON(filepath.Join(p.dir, partyKeysFile), pk); err != nil {
			return nil, err
		}
		k.PartyKeys = pk
	}
	return k, nil
}

// signedCard is the party's card, signed by the root key: relays as given,
// agents from config, and config's details when details is set.
func (p *party) signedCard(pk *keys.PartyKeys, relays []string, details bool, now time.Time) (*card.Signed, error) {
	if p.root == nil {
		return nil, fmt.Errorf("%s is not in %s: the card is signed by the root key", rootFile, p.dir)
	}
	c := card.New(p.id, pk, p.cfg.Agents, relays, now)
	if details {
		c.Details = p.cfg.Details
	}
	return card.Sign(c, p.root)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
