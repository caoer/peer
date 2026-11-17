package pages

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Snapshot is every record of the page at one moment, as a command holds it
// for its life instead of reading the page record by record: Recs by key,
// each sealed bytes and version, or a ref (Load reads the page); Complete
// when a key not in Recs is absent.
type Snapshot struct {
	Complete bool                    `json:"complete"`
	Recs     map[string]SnapshotItem `json:"recs"`
}

// SnapshotItem is one record of a Snapshot.
type SnapshotItem struct {
	Data []byte `json:"data,omitempty"`
	V    int64  `json:"v"`
	Ref  bool   `json:"ref,omitempty"`
}

// Snapshot is what the synced live socket holds; ok false while Watch is not
// running or not caught up.
func (b *Backend) Snapshot() (Snapshot, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.live
	if l == nil || !l.synced {
		return Snapshot{}, false
	}
	s := Snapshot{Complete: l.complete, Recs: make(map[string]SnapshotItem, len(l.recs))}
	for k, r := range l.recs {
		s.Recs[k] = SnapshotItem{Data: append([]byte(nil), r.data...), V: r.v, Ref: r.ref}
	}
	return s, true
}

// Hold makes Load answer from s for the Backend's life, as a synced socket
// would; a ref, or a key Store found changed, is read from the page. For a
// command that holds no socket: Watch replaces it.
func (b *Backend) Hold(s Snapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := &live{synced: true, complete: s.Complete, recs: make(map[string]*liveRec, len(s.Recs))}
	for k, r := range s.Recs {
		if r.Ref {
			l.recs[k] = &liveRec{v: r.V, ref: true}
			continue
		}
		l.recs[k] = &liveRec{data: append([]byte(nil), r.Data...), v: r.V}
	}
	b.live = l
}

// ReadAll reads every record of the page by its values list
// (`GET /d/<slug>?values=1`, up to 100 a response): one request for a
// party's state, where Load per record is one each.
func (b *Backend) ReadAll(ctx context.Context) (Snapshot, error) {
	s := Snapshot{Complete: true, Recs: map[string]SnapshotItem{}}
	after := ""
	for {
		q := url.Values{"values": {"1"}}
		if after != "" {
			q.Set("after", after)
		}
		var a struct {
			Error  string  `json:"error"`
			Code   string  `json:"code"`
			Cursor *string `json:"cursor"`
			Keys   []struct {
				Key     string `json:"key"`
				Version int64  `json:"version"`
				Value   *struct {
					Schema string          `json:"schema"`
					Data   json.RawMessage `json:"data"`
				} `json:"value"`
			} `json:"keys"`
		}
		status, raw, err := b.doRaw(ctx, http.MethodGet, b.base+"/d/"+b.slug+"?"+q.Encode())
		if err != nil {
			return Snapshot{}, err
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return Snapshot{}, fmt.Errorf("pages: list: status %d, body is not JSON", status)
		}
		if status != http.StatusOK {
			return Snapshot{}, &Error{Status: status, Code: a.Code, Message: a.Error}
		}
		for _, k := range a.Keys {
			it := SnapshotItem{V: k.Version, Ref: true}
			if k.Value != nil && k.Value.Schema == Schema {
				var str string
				if json.Unmarshal(k.Value.Data, &str) == nil {
					if data, err := base64.StdEncoding.DecodeString(str); err == nil {
						it = SnapshotItem{Data: data, V: k.Version}
					}
				}
			}
			s.Recs[k.Key] = it
		}
		if a.Cursor == nil || *a.Cursor == "" {
			return s, nil
		}
		after = *a.Cursor
	}
}
