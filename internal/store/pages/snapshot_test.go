package pages_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// ReadAll takes a page wider than one values list in ceil(n/100) requests;
// held, every record loads from it with no GET, an absent key is absent,
// and a record not of the peer store's schema is read from the page.
func TestReadAllHoldsThePage(t *testing.T) {
	ctx := context.Background()
	srv := pagestest.New(slug, bearer)
	defer srv.Close()
	key := store.SealKey(identity(t))
	b := store.Sealed(pages.New(srv.URL, slug, bearer, nil), key)
	n := pagestest.ListPage + 5
	for i := range n {
		if _, err := b.Store(ctx, fmt.Sprintf("ss.c%03d", i), []byte(fmt.Sprintf("record %d", i)), 0); err != nil {
			t.Fatal(err)
		}
	}
	srv.Set("other", pagestest.Record{Schema: "other@1", Data: json.RawMessage(`"x"`), Version: 1})

	reader := pages.New(srv.URL, slug, bearer, nil)
	snap, err := reader.ReadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.Lists(); got != 2 {
		t.Fatalf("%d list requests for %d records, want 2", got, n+1)
	}
	if len(snap.Recs) != n+1 || !snap.Complete || !snap.Recs["other"].Ref {
		t.Fatalf("snapshot: %d records, complete %v, other %+v", len(snap.Recs), snap.Complete, snap.Recs["other"])
	}
	reader.Hold(snap)
	sb := store.Sealed(reader, key)
	gets := srv.Gets("")
	for i := range n {
		k := fmt.Sprintf("ss.c%03d", i)
		got, v, err := sb.Load(ctx, k)
		if err != nil || v != 1 || !bytes.Equal(got, []byte(fmt.Sprintf("record %d", i))) {
			t.Fatalf("%s: %q %d %v", k, got, v, err)
		}
	}
	if got, v, err := sb.Load(ctx, "ss.absent"); got != nil || v != 0 || err != nil {
		t.Fatalf("absent: %q %d %v", got, v, err)
	}
	if n := srv.Gets("") - gets; n != 0 {
		t.Fatalf("%d GETs from a held snapshot, want 0", n)
	}
	reader.Load(ctx, "other")
	if srv.Gets("other") != 1 {
		t.Fatalf("a record of another schema was not read from the page")
	}
}
