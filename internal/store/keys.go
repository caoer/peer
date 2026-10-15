package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"go.mau.fi/libsignal/state/record"

	"github.com/caoer/peer/internal/keys"
)

// Keys is the party keys record, loaded at a version: the libsignal prekey
// and signed-prekey stores. PartyKeys is nil while the record is absent —
// the host seeds it from the party keys file peer init wrote and commits.
// The record keeps raw 32-byte keys (package keys), never libsignal's record
// bytes, whose reload corrupts the public key.
type Keys struct {
	s       *Store
	version int64
	// PartyKeys is the record's content.
	PartyKeys *keys.PartyKeys
}

// Keys loads the party keys record.
func (s *Store) Keys(ctx context.Context) (*Keys, error) {
	k := &Keys{s: s}
	data, v, err := s.backend.Load(ctx, KeysKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return k, nil
	}
	var pk keys.PartyKeys
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, KeysKey, err)
	}
	k.PartyKeys, k.version = &pk, v
	return k, nil
}

// Version is the loaded version; Commit raises it.
func (k *Keys) Version() int64 { return k.version }

// Commit writes the record as version Version()+1; ErrConflict as Channel.Commit.
func (k *Keys) Commit(ctx context.Context) error {
	if k.PartyKeys == nil {
		return ErrNoKeys
	}
	if k.PartyKeys.SignedPrekey == nil {
		return errors.New("store: party keys: no signed prekey")
	}
	data, err := json.Marshal(k.PartyKeys)
	if err != nil {
		return err
	}
	v, err := k.s.backend.Store(ctx, KeysKey, data, k.version)
	if err != nil {
		return err
	}
	k.version = v
	return nil
}

// LoadPreKey is the libsignal prekey store: nil, nil for an unknown id.
func (k *Keys) LoadPreKey(ctx context.Context, id uint32) (*record.PreKey, error) {
	if k.PartyKeys == nil {
		return nil, nil
	}
	for _, p := range k.PartyKeys.Prekeys {
		if p.ID().Value == id {
			return p, nil
		}
	}
	return nil, nil
}

// StorePreKey adds or replaces the one-time prekey id.
func (k *Keys) StorePreKey(ctx context.Context, id uint32, p *record.PreKey) error {
	if k.PartyKeys == nil {
		return ErrNoKeys
	}
	for i, q := range k.PartyKeys.Prekeys {
		if q.ID().Value == id {
			k.PartyKeys.Prekeys[i] = p
			return nil
		}
	}
	k.PartyKeys.Prekeys = append(k.PartyKeys.Prekeys, p)
	if id >= k.PartyKeys.NextPrekeyID {
		k.PartyKeys.NextPrekeyID = id + 1
	}
	return nil
}

// ContainsPreKey reports whether the one-time prekey id is held.
func (k *Keys) ContainsPreKey(ctx context.Context, id uint32) (bool, error) {
	p, _ := k.LoadPreKey(ctx, id)
	return p != nil, nil
}

// RemovePreKey drops the one-time prekey id; the library calls it after a
// PreKey message used it.
func (k *Keys) RemovePreKey(ctx context.Context, id uint32) error {
	if k.PartyKeys == nil {
		return nil
	}
	for i, p := range k.PartyKeys.Prekeys {
		if p.ID().Value == id {
			k.PartyKeys.Prekeys = slices.Delete(k.PartyKeys.Prekeys, i, i+1)
			return nil
		}
	}
	return nil
}

// LoadSignedPreKey is the libsignal signed-prekey store: the current signed
// prekey or the one the last rotation replaced, nil, nil for any other id.
func (k *Keys) LoadSignedPreKey(ctx context.Context, id uint32) (*record.SignedPreKey, error) {
	for _, r := range k.signedPrekeys() {
		if r.ID() == id {
			return r, nil
		}
	}
	return nil, nil
}

// signedPrekeys lists the signed prekeys held: the current one, then the previous.
func (k *Keys) signedPrekeys() []*record.SignedPreKey {
	if k.PartyKeys == nil {
		return nil
	}
	var out []*record.SignedPreKey
	for _, r := range []*record.SignedPreKey{k.PartyKeys.SignedPrekey, k.PartyKeys.PreviousSignedPrekey} {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

// LoadSignedPreKeys lists the current signed prekey and the previous one.
func (k *Keys) LoadSignedPreKeys(ctx context.Context) ([]*record.SignedPreKey, error) {
	return k.signedPrekeys(), nil
}

// StoreSignedPreKey makes r the current signed prekey; the one it replaces
// becomes the previous.
func (k *Keys) StoreSignedPreKey(ctx context.Context, id uint32, r *record.SignedPreKey) error {
	if k.PartyKeys == nil {
		return ErrNoKeys
	}
	if cur := k.PartyKeys.SignedPrekey; cur != nil && cur.ID() != id {
		k.PartyKeys.PreviousSignedPrekey = cur
	}
	k.PartyKeys.SignedPrekey = r
	return nil
}

// ContainsSignedPreKey reports whether id is a signed prekey held.
func (k *Keys) ContainsSignedPreKey(ctx context.Context, id uint32) (bool, error) {
	r, _ := k.LoadSignedPreKey(ctx, id)
	return r != nil, nil
}

// RemoveSignedPreKey drops the signed prekey id, current or previous; a
// record without a current one cannot be committed.
func (k *Keys) RemoveSignedPreKey(ctx context.Context, id uint32) error {
	if k.PartyKeys == nil {
		return nil
	}
	if r := k.PartyKeys.SignedPrekey; r != nil && r.ID() == id {
		k.PartyKeys.SignedPrekey = nil
	}
	if r := k.PartyKeys.PreviousSignedPrekey; r != nil && r.ID() == id {
		k.PartyKeys.PreviousSignedPrekey = nil
	}
	return nil
}
