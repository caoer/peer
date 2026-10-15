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
	// Timelines are the peers' collaboration pages serve and send write
	// each message on (timeline.go), by peer name.
	Timelines map[string]timelineConfig `json:"timelines,omitempty"`
	// Keys is the key lifecycle: signedPrekeyEvery, oneTimeMin (keys.go).
	Keys keysConfig `json:"keys,omitempty"`
	// Push is how a running serve uses the relay's push: pullEvery (push.go).
	Push pushConfig `json:"push,omitempty"`
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
	// tl is the current round of timeline writes (timeline.go).
	tl *timelineState
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
	if _, err := p.cfg.signedPrekeyEvery(); err != nil {
		return nil, err
	}
	b, err := openBackend(dir, p.cfg, p.id)
	if err != nil {
		return nil, err
	}
	// A rotation that stopped part way left its new key in identity.json.next
	// (identity.go): once the state opens under that key, it is the party's
	// until peer identity rotate --yes completes the rotation.
	next, err := nextIdentity(dir, p.id)
	if err != nil {
		return nil, err
	}
	if next != nil {
		nb, err := openBackend(dir, p.cfg, next)
		if err != nil {
			return nil, err
		}
		switch _, err := roster.Load(context.Background(), nb); {
		case err == nil:
			p.id, b = next, nb
		case !errors.Is(err, store.ErrCorrupt):
			return nil, err
		}
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

// ownCard is this party's card as the state holds it (store.OwnCard), the
// details form for an in-session send and the public one for envelope #0.
// It is the only card any command sends: the root key signs it where it
// lives — peer init, peer card publish, peer identity rotate — and every
// host reads the record, so nothing on the fleet signs one. A record for
// another identity key than this party's refuses with the publish rule; one
// carrying another signed prekey than the current one is served with a
// reminder line (the previous key opens a bundle one more interval), the
// second return — empty when the card is fresh. The third return is the
// record's signed prekey id, for the channel's announced mark.
func (p *party) ownCard(ctx context.Context, details bool) (*card.Signed, string, uint32, error) {
	oc, err := p.store.OwnCard(ctx)
	if err != nil {
		return nil, "", 0, err
	}
	if !oc.Present() {
		return nil, "", 0, fmt.Errorf("no card on the state: run peer card publish where %s is; it signs this party's card and puts it on the state for every host", rootFile)
	}
	if want := keys.CurveText(p.id.PublicKey()); oc.Identity != want {
		return nil, "", 0, fmt.Errorf("the card on the state is for identity key %s and this party's is %s: run peer card publish where %s is", oc.Identity, want, rootFile)
	}
	stale := ""
	if k, err := p.store.Keys(ctx); err == nil && k.PartyKeys != nil && oc.SignedPrekey != k.PartyKeys.SignedPrekey.ID() {
		stale = fmt.Sprintf("the card on the state carries signed prekey %d and the current one is %d (the previous key opens a bundle one more interval): run peer card publish where %s is", oc.SignedPrekey, k.PartyKeys.SignedPrekey.ID(), rootFile)
	}
	if details {
		return oc.Details, stale, oc.SignedPrekey, nil
	}
	return oc.Public, stale, oc.SignedPrekey, nil
}

// buildOwnCard signs this party's card in both forms with the root key: id
// and pk's signed prekey as the current key after any retired keys (an
// identity rotation lists the old key with its until), agents from config
// (the seat map's under ucc), config's relays, and config's details in the
// details form only.
func (p *party) buildOwnCard(id *keys.Identity, pk *keys.PartyKeys, now time.Time, retired ...card.Key) (public, details *card.Signed, err error) {
	if p.root == nil {
		return nil, nil, errNoRoot(p.dir)
	}
	c := card.New(id, pk, p.cfg.Agents, relaysOf(p.cfg), now)
	c.Keys = append(append([]card.Key{}, retired...), c.Keys...)
	if public, err = card.Sign(c, p.root); err != nil {
		return nil, nil, err
	}
	c.Details = p.cfg.Details
	if details, err = card.Sign(c, p.root); err != nil {
		return nil, nil, err
	}
	return public, details, nil
}

// putOwnCard writes the card record on st under CAS; a conflict reloads and
// writes again, since the record carries no state of another host's.
func putOwnCard(ctx context.Context, st *store.Store, id *keys.Identity, pk *keys.PartyKeys, now time.Time, public, details *card.Signed) error {
	for try := 1; ; try++ {
		oc, err := st.OwnCard(ctx)
		if err != nil {
			return err
		}
		oc.Set(now, keys.CurveText(id.PublicKey()), pk.SignedPrekey.ID(), public, details)
		err = oc.Commit(ctx)
		if err == nil {
			return nil
		}
		if !errors.Is(err, store.ErrConflict) || try >= sendTries {
			return fmt.Errorf("card record: %w", err)
		}
	}
}

// signOwnCard builds this party's card from its own identity and pk and puts
// it on the state: what peer card publish does, and a due rotation.
func (p *party) signOwnCard(ctx context.Context, pk *keys.PartyKeys, now time.Time) (*card.Signed, error) {
	public, details, err := p.buildOwnCard(p.id, pk, now)
	if err != nil {
		return nil, err
	}
	if err := putOwnCard(ctx, p.store, p.id, pk, now, public, details); err != nil {
		return nil, err
	}
	return details, nil
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
		rcpt, err := relay.New(pe.Relay, nil).Put(ctx, e.Channel, pe.Token, envelope.Envelope{Type: typ, Body: e.Body})
		if err == nil {
			p.timelineSent(ctx, e.ID, rcpt.Seq)
		}
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
