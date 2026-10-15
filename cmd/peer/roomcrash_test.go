package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/store"
)

// A host that dies between a room record's Commit and its birth: the room
// spool holds the committed entry and nothing is born; the next start
// replays the room spool, births the record once and empties the spool; a
// start after that births nothing. The milestone-2 run showed it once on a
// live room (results/milestone-v2.md § 8); TestServeCrashAfterCommitReplaysOnce
// is the channels' half.
func TestRoomServeCrashAfterCommitReplaysOnce(t *testing.T) {
	ctx := context.Background()
	srv, _, base := relaytest.Start(t, login)
	tr := newTrio(t, base, srv, config{})
	id, seq := roomSendOK(t, tr.b, "--text", "survives the crash", tr.bcRoom)
	roomSpool := func() []*store.Entry {
		t.Helper()
		j, err := store.OpenJournal(filepath.Join(tr.a, roomSpoolDir))
		if err != nil {
			t.Fatal(err)
		}
		es, err := j.Entries()
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	born := func() int {
		t.Helper()
		return len(withoutRoster(t, records(t, deliverDirOf(tr.a), deliver.Inbox)))
	}
	before := born()

	sv, err := openServer(tr.a, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	sv.beforeBirth = func(e *store.Entry) error {
		if e.ID == id {
			return errors.New("crash before birth")
		}
		return nil
	}
	if err := sv.start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sv.round(ctx); err == nil || !strings.Contains(err.Error(), "crash before birth") {
		t.Fatalf("round: %v", err)
	}
	es := roomSpool()
	if len(es) != 1 || es[0].ID != id || es[0].Channel != tr.id || es[0].Type != "room" || !es[0].Committed {
		t.Fatalf("room spool after the crash: %+v", es)
	}
	if n := born(); n != before {
		t.Fatalf("%d records born before the crash", n-before)
	}
	if _, _, st := roomOf(t, tr.a, tr.aRoom); !st.Seen(id) || st.Cursor() < seq {
		t.Fatalf("the Commit did not land: seen %v cursor %d, record #%d", st.Seen(id), st.Cursor(), seq)
	}

	var log bytes.Buffer
	for i := 1; i <= 2; i++ {
		sv, err := openServer(tr.a, "", &log)
		if err != nil {
			t.Fatal(err)
		}
		if err := sv.start(ctx); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if err := sv.round(ctx); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if es := roomSpool(); len(es) != 0 {
			t.Fatalf("room spool after start %d: %+v", i, es)
		}
	}
	if n := strings.Count(log.String(), "delivered text "+id); n != 1 {
		t.Fatalf("replay delivered %d times:\n%s", n, log.String())
	}
	in := withoutRoster(t, records(t, deliverDirOf(tr.a), deliver.Inbox))
	if len(in) != before+1 {
		t.Fatalf("%d records born by the replay, want 1", len(in)-before)
	}
	roomRecord(t, in[id], tr.ab.guestParty, tr.ab.hostParty, tr.id, "survives the crash")
}
