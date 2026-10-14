package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caoer/peer/internal/card"
	"github.com/caoer/peer/internal/envelope"
	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/roster"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
	"github.com/caoer/peer/internal/store/pages"
)

// Beside init's three files, the peer directory holds:
const (
	configFile = "config.json" // the party's relay, owner login, agents, details, state, deliver, roster
	stateDir   = "state"       // the file store backend, unless config names another state
	outboxDir  = "outbox"      // the send outbox (a store.Journal)
	spoolDir   = "spool"       // the serve spool (a store.Journal)
	deliverDir = "deliver"     // where serve delivers, unless config names another directory
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
	// State is where the session state lives, shared by every host of the
	// party that serves (design §3.2): a directory for the file backend, or
	// a private ccc-pages state page. Absent, it is <dir>/state.
	State stateConfig `json:"state,omitempty"`
	// Deliver is the directory serve delivers into — inbox/<id>.md and
	// quarantine/<id>.md under it. Absent, it is <dir>/deliver.
	Deliver string `json:"deliver,omitempty"`
	// Roster is the private roster page serve keeps current (status.go).
	Roster rosterConfig `json:"roster,omitempty"`
	// UCC names the fleet's sessions root and the seat map on it (ucc.go):
	// with it, Agents come from the map and serve delivers by it.
	UCC *uccConfig `json:"ucc,omitempty"`
}

// stateConfig names the state backend: Dir for the file backend, or
// Page + Slug (+ Login, default the config login) for a ccc-pages page.
type stateConfig struct {
	Dir   string `json:"dir,omitempty"`
	Page  string `json:"page,omitempty"`
	Slug  string `json:"slug,omitempty"`
	Login string `json:"login,omitempty"`
}

// openBackend opens the state the config names, sealed when it is a page.
func openBackend(dir string, cfg config, id *keys.Identity) (store.Backend, error) {
	st := cfg.State
	if st.Page != "" || st.Slug != "" {
		if st.Login == "" {
			st.Login = cfg.Login
		}
		if st.Page == "" || st.Slug == "" || st.Login == "" {
			return nil, fmt.Errorf("%s: state.page, state.slug and a login (state.login or login) go together", configFile)
		}
		return store.Sealed(pages.New(st.Page, st.Slug, st.Login, nil), store.SealKey(id)), nil
	}
	if st.Dir == "" {
		st.Dir = filepath.Join(dir, stateDir)
	}
	return file.New(st.Dir)
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
	if _, err := p.loadSeats(); err != nil {
		return nil, err
	}
	b, err := openBackend(dir, p.cfg, p.id)
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

// accepts is the kinds the addressed agent takes, from config's agent list.
// Nil — every kind — for the party itself, and for an agent config lists
// without a list of its own. An agent id config does not list is nobody
// here: it takes nothing, so what the sender addressed to it is quarantined
// rather than delivered under no rule at all (plan U11 refuses the label).
func (p *party) accepts(agent string) []string {
	if agent == "" {
		return nil
	}
	for _, a := range p.cfg.Agents {
		if a.ID == agent {
			return a.Accepts
		}
	}
	return []string{}
}

// replayOutbox puts the outbox entries whose commit landed
// (store.ReplayOutbox): every send, and every serve round. An entry whose
// channel is no longer on the roster is dropped, as is one the relay can
// never take; one that failed on something passing waits for the next replay
// and does not hold up the entries behind it.
func (p *party) replayOutbox(ctx context.Context) error {
	r, err := roster.Load(ctx, p.backend)
	if err != nil {
		return err
	}
	return store.ReplayOutbox(p.outbox, func(e *store.Entry) error {
		pe := r.ByChannel(e.Channel)
		if pe == nil {
			return nil
		}
		typ, err := envelope.ParseType(e.Type)
		if err != nil {
			return fmt.Errorf("%w: %v", store.ErrPermanent, err)
		}
		_, err = relay.New(pe.Relay, nil).Put(ctx, e.Channel, pe.Token, envelope.Envelope{Type: typ, Body: e.Body})
		if err != nil && permanentPut(err) {
			return fmt.Errorf("%w: %v", store.ErrPermanent, err)
		}
		return err
	})
}

// permanentPut reports whether a relay refusal can never be put: the channel
// is gone, the token is refused, the request or the envelope itself is wrong.
// Anything else — a 5xx, a timeout, rate limiting — waits for the next replay.
func permanentPut(err error) bool {
	if errors.Is(err, envelope.ErrTooLarge) {
		return true
	}
	for _, p := range []*relay.Error{
		relay.ErrNoSuchChannel, relay.ErrBadToken, relay.ErrTokenUsed,
		relay.ErrTooLarge, relay.ErrBadRequest, relay.ErrMethodNotAllowed, relay.ErrNoSuchRoute,
	} {
		if errors.Is(err, p) {
			return true
		}
	}
	return false
}

// splitAddr cuts "<party>/<agent>" — a protocol address, or a roster
// name with an agent — into its two parts; agent is empty without a slash.
func splitAddr(s string) (party, agent string) {
	party, agent, _ = strings.Cut(s, "/")
	return party, agent
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
