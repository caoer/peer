package store_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/store"
)

// Decision 5's orders, with two hosts as two Stores on one backend and the
// decrypt or encrypt step stood in for by the state change it makes.

func journal(t *testing.T) *store.Journal {
	t.Helper()
	j, err := store.OpenJournal(filepath.Join(t.TempDir(), "spool"))
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func count(t *testing.T, j *store.Journal) int {
	t.Helper()
	es, err := j.Entries()
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// serve runs one host's receive of message id at relay seq: spool, commit,
// mark, birth, clear — the loser drops its spool entry and births nothing.
func serve(ctx context.Context, ch *store.Channel, spool *store.Journal, id string, seq int64, birth func(*store.Entry) error) error {
	e := &store.Entry{ID: id, Channel: ch.Name(), Seq: seq, Type: "msg", Body: []byte("plaintext of " + id)}
	if err := spool.Add(e); err != nil {
		return err
	}
	ch.MarkSeen(id, seq)
	ch.SetCursor(seq)
	if err := ch.Commit(ctx); err != nil {
		spool.Remove(e)
		return err
	}
	if err := spool.MarkCommitted(e); err != nil {
		return err
	}
	if err := birth(e); err != nil {
		return err
	}
	return spool.Remove(e)
}

func TestServeLoserBirthsNothing(t *testing.T) {
	ctx := context.Background()
	b := fileBackend(t)
	p := newParty(t, "p", b)
	hostA, hostB := p.store, store.New(b, p.id)
	spoolA, spoolB := journal(t), journal(t)
	var births []string
	birth := func(e *store.Entry) error { births = append(births, e.ID); return nil }

	// Both hosts pulled relay seq 7 and loaded the channel at the same version.
	chA, _ := hostA.Channel(ctx, "c1")
	chB, _ := hostB.Channel(ctx, "c1")
	if err := serve(ctx, chA, spoolA, "m1", 7, birth); err != nil {
		t.Fatal(err)
	}
	if err := serve(ctx, chB, spoolB, "m1", 7, birth); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second commit: %v, want ErrConflict", err)
	}
	if len(births) != 1 || births[0] != "m1" {
		t.Fatalf("births %v, want [m1]", births)
	}
	if count(t, spoolA) != 0 || count(t, spoolB) != 0 {
		t.Fatal("a spool entry survived")
	}
	// The loser reloads and finds the message handled.
	chB, _ = hostB.Channel(ctx, "c1")
	if !chB.Seen("m1") || chB.Cursor() != 7 || chB.Version() != 1 {
		t.Fatalf("reloaded: seen=%v cursor=%d version=%d", chB.Seen("m1"), chB.Cursor(), chB.Version())
	}
}

func TestServeCrashAfterCommitReplaysOnce(t *testing.T) {
	ctx := context.Background()
	p := newParty(t, "p", fileBackend(t))
	spool := journal(t)
	births := 0
	birth := func(*store.Entry) error { births++; return nil }

	// Spool, commit — and the host dies before MarkCommitted and the birth.
	ch, _ := p.store.Channel(ctx, "c1")
	e := &store.Entry{ID: "m2", Channel: "c1", Seq: 8, Type: "msg", Body: []byte("plaintext")}
	if err := spool.Add(e); err != nil {
		t.Fatal(err)
	}
	ch.MarkSeen("m2", 8)
	ch.SetCursor(8)
	commit(t, ctx, ch)

	// Restart: the replay births it once, then nothing is left to replay.
	if err := p.store.ReplaySpool(ctx, spool, birth); err != nil {
		t.Fatal(err)
	}
	if births != 1 || count(t, spool) != 0 {
		t.Fatalf("after replay: %d births, %d entries", births, count(t, spool))
	}
	if err := p.store.ReplaySpool(ctx, spool, birth); err != nil || births != 1 {
		t.Fatalf("second replay: %d births, %v", births, err)
	}

	// A spool entry whose commit never landed is dropped, not delivered: the
	// cursor did not move, so the message is pulled again.
	e3 := &store.Entry{ID: "m3", Channel: "c1", Seq: 9, Type: "msg", Body: []byte("plaintext")}
	if err := spool.Add(e3); err != nil {
		t.Fatal(err)
	}
	if err := p.store.ReplaySpool(ctx, spool, birth); err != nil {
		t.Fatal(err)
	}
	if births != 1 || count(t, spool) != 0 {
		t.Fatalf("uncommitted entry: %d births, %d entries", births, count(t, spool))
	}

	// A marked entry is delivered without consulting the store.
	e4 := &store.Entry{ID: "m4", Channel: "never-loaded", Seq: 1, Type: "msg", Body: []byte("plaintext")}
	if err := spool.Add(e4); err != nil {
		t.Fatal(err)
	}
	if err := spool.MarkCommitted(e4); err != nil {
		t.Fatal(err)
	}
	if err := p.store.ReplaySpool(ctx, spool, birth); err != nil || births != 2 || count(t, spool) != 0 {
		t.Fatalf("marked entry: %d births, %d entries, %v", births, count(t, spool), err)
	}
}

// send runs one host's send: outbox, commit, mark, put, clear — the loser
// drops its outbox entry and re-encrypts from the fresh state.
func send(ctx context.Context, ch *store.Channel, outbox *store.Journal, id string, put func(*store.Entry) error) error {
	e := &store.Entry{ID: id, Channel: ch.Name(), Type: "msg", Body: []byte("ciphertext of " + id + " at v" + string(rune('0'+ch.Version())))}
	if err := outbox.Add(e); err != nil {
		return err
	}
	ch.MarkSeen("sent:"+id, 0) // the ratchet step the encrypt would make
	if err := ch.Commit(ctx); err != nil {
		outbox.Remove(e)
		return err
	}
	if err := outbox.MarkCommitted(e); err != nil {
		return err
	}
	if err := put(e); err != nil {
		return err
	}
	return outbox.Remove(e)
}

func TestSendOrderAndOutboxReplay(t *testing.T) {
	ctx := context.Background()
	b := fileBackend(t)
	p := newParty(t, "p", b)
	hostA, hostB := p.store, store.New(b, p.id)
	outbox := journal(t)
	var puts []string
	put := func(e *store.Entry) error { puts = append(puts, string(e.Body)); return nil }

	// Two hosts encrypt under the same state; one commits, the other's
	// ciphertext is dropped and re-encrypted from the fresh state.
	chA, _ := hostA.Channel(ctx, "c1")
	chB, _ := hostB.Channel(ctx, "c1")
	if err := send(ctx, chA, outbox, "o1", put); err != nil {
		t.Fatal(err)
	}
	if err := send(ctx, chB, outbox, "o2", put); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second send: %v, want ErrConflict", err)
	}
	chB, _ = hostB.Channel(ctx, "c1")
	if err := send(ctx, chB, outbox, "o2", put); err != nil {
		t.Fatal(err)
	}
	if len(puts) != 2 || puts[0] != "ciphertext of o1 at v0" || puts[1] != "ciphertext of o2 at v1" {
		t.Fatalf("puts %q", puts)
	}
	if count(t, outbox) != 0 {
		t.Fatal("an outbox entry survived")
	}

	// A crash after the commit and mark but before the put replays the put;
	// a crash before the commit drops the ciphertext.
	ch, _ := hostA.Channel(ctx, "c1")
	e := &store.Entry{ID: "o3", Channel: "c1", Type: "msg", Body: []byte("committed ciphertext")}
	if err := outbox.Add(e); err != nil {
		t.Fatal(err)
	}
	commit(t, ctx, ch)
	if err := outbox.MarkCommitted(e); err != nil {
		t.Fatal(err)
	}
	e2 := &store.Entry{ID: "o4", Channel: "c1", Type: "msg", Body: []byte("uncommitted ciphertext")}
	if err := outbox.Add(e2); err != nil {
		t.Fatal(err)
	}
	puts = nil
	if err := store.ReplayOutbox(outbox, put); err != nil {
		t.Fatal(err)
	}
	if len(puts) != 1 || puts[0] != "committed ciphertext" || count(t, outbox) != 0 {
		t.Fatalf("replay puts %q, %d entries left", puts, count(t, outbox))
	}
}

// One entry never holds up the rest: a put that can never land drops its
// entry, a put that failed on something passing keeps its entry for the next
// replay, and the entries behind both are tried either way.
func TestOutboxReplayTriesEveryEntry(t *testing.T) {
	outbox := journal(t)
	for _, id := range []string{"gone", "waiting", "good"} {
		e := &store.Entry{ID: id, Channel: "c1", Type: "msg", Body: []byte(id)}
		if err := outbox.Add(e); err != nil {
			t.Fatal(err)
		}
		if err := outbox.MarkCommitted(e); err != nil {
			t.Fatal(err)
		}
	}
	var puts []string
	err := store.ReplayOutbox(outbox, func(e *store.Entry) error {
		puts = append(puts, e.ID)
		switch e.ID {
		case "gone":
			return fmt.Errorf("%w: relay: 404 no_such_channel", store.ErrPermanent)
		case "waiting":
			return errors.New("relay: 503 down")
		}
		return nil
	})
	if err == nil {
		t.Fatal("the replay reported neither failure")
	}
	if strings.Join(puts, " ") != "gone waiting good" {
		t.Fatalf("the replay tried %q, want every entry in order", puts)
	}
	es, _ := outbox.Entries()
	if len(es) != 1 || es[0].ID != "waiting" {
		t.Fatalf("outbox after the replay: %+v, want the transient entry alone", es)
	}
}
