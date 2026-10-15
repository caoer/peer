package relay

// The Go client against a REAL relay Worker — `wrangler dev` of ccc-pages'
// wrangler.peer-relay.jsonc, or a deployed relay — rather than relaytest, so
// contract drift on either side turns red somewhere. Opt-in: skipped unless
// PEER_LIVE_RELAY=<base ending in /peer> and PEER_LIVE_LOGIN=<user:token>.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/caoer/peer/internal/envelope"
)

func TestLiveWorkerContract(t *testing.T) {
	base, login := os.Getenv("PEER_LIVE_RELAY"), os.Getenv("PEER_LIVE_LOGIN")
	if base == "" {
		t.Skip("PEER_LIVE_RELAY unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := New(base, nil)
	if _, err := c.Create(ctx, login+"x"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("create with a wrong login: %v", err)
	}
	ch, err := c.Create(ctx, login)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	card, _ := envelope.PackCard([]byte(`{"v":1}`), make([]byte, envelope.SigSize))
	if r, err := c.Put(ctx, ch.ID, ch.HostToken, card); err != nil || r.Dir != "h2g" || r.Seq != 0 {
		t.Fatalf("host card: %+v %v", r, err)
	}
	if n, err := c.PutPrekeys(ctx, ch.ID, ch.HostToken, []Prekey{{1, pub(1)}, {2, pub(2)}}); err != nil || n != 2 {
		t.Fatalf("prekeys: %d %v", n, err)
	}
	if n, err := c.PutPrekeys(ctx, ch.ID, ch.HostToken, []Prekey{{2, pub(2)}}); err != nil || n != 2 {
		t.Fatalf("repeated prekey: %d %v", n, err)
	}
	if l, err := c.Landing(ctx, ch.ID); err != nil || l == "" {
		t.Fatalf("landing: %v", err)
	}
	guest, err := c.Join(ctx, ch.ID, ch.InviteToken)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if _, err := c.Join(ctx, ch.ID, ch.InviteToken); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second join: %v", err)
	}
	sock, err := c.Subscribe(ctx, ch.ID, ch.HostToken)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sock.Close()
	recs, err := c.Pull(ctx, ch.ID, guest, -1)
	if err != nil || len(recs) != 1 || recs[0].Err != nil || recs[0].Env.Type != envelope.Card || recs[0].At.IsZero() {
		t.Fatalf("guest pull: %+v %v", recs, err)
	}
	if k, ok, err := c.TakePrekey(ctx, ch.ID, guest); err != nil || !ok || k.ID != 1 || !bytes.Equal(k.Pub, pub(1)) {
		t.Fatalf("take: %+v %v %v", k, ok, err)
	}
	if r, err := c.Put(ctx, ch.ID, guest, msgEnv(7)); err != nil || r.Dir != "g2h" || r.Seq != 0 {
		t.Fatalf("guest put: %+v %v", r, err)
	}
	if rec, err := sock.Next(ctx); err != nil || rec.Seq != 0 || rec.Err != nil || !bytes.Equal(rec.Env.Body, msgEnv(7).Body) {
		t.Fatalf("push frame: %+v %v", rec, err)
	}
	if recs, err := c.PullAll(ctx, ch.ID, ch.HostToken, -1); err != nil || len(recs) != 1 {
		t.Fatalf("host pull: %+v %v", recs, err)
	}
	if _, ok, err := c.TakePrekey(ctx, ch.ID, ch.HostToken); err != nil || ok {
		t.Fatalf("empty take: %v %v", ok, err)
	}
	data := bytes.Repeat([]byte{0, 1, 2, 0xff}, 1<<19) // 2 MiB: three chunks
	b, err := c.PutBlob(ctx, ch.ID, ch.HostToken, data)
	if err != nil {
		t.Fatalf("put blob: %v", err)
	}
	if got, err := c.GetBlob(ctx, ch.ID, guest, b.ID); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("get blob: %d %v", len(got), err)
	}
	if _, err := c.GetBlob(ctx, ch.ID, ch.HostToken, b.ID); !errors.Is(err, ErrNoSuchBlob) {
		t.Fatalf("own blob: %v", err)
	}
	if _, err := c.Pull(ctx, "ab"+ch.ID[2:], ch.HostToken, -1); !errors.Is(err, ErrNoSuchChannel) {
		t.Fatalf("other channel: %v", err)
	}
}
