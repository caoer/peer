package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caoer/peer/internal/relay/relaytest"
	"github.com/caoer/peer/internal/session"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/pages/pagestest"
	"github.com/caoer/peer/internal/timeline"
)

// timelineOn is cfg with peer name's timeline on page ps.
func timelineOn(cfg config, name string, ps *pagestest.Server) config {
	cfg.Timelines = map[string]timelineConfig{name: {Page: ps.URL, Slug: ps.Slug, Login: ps.Bearer}}
	return cfg
}

// timelinePages is a handshake whose host keeps the guest's ("ancan")
// timeline on hp and whose guest keeps the host's ("zt") on gp.
func timelinePages(t *testing.T, base string) (p *pair, hp, gp *pagestest.Server) {
	t.Helper()
	hp = pagestest.New("tl-host-0123456789abcdef", "zt:host-page-secret")
	gp = pagestest.New("tl-guest-0123456789abcdef", "ay:guest-page-secret")
	t.Cleanup(hp.Close)
	t.Cleanup(gp.Close)
	p = handshake(t, newDir(t, timelineOn(hostCfg(), "ancan", hp)), newDir(t, timelineOn(config{}, "zt", gp)), base)
	return p, hp, gp
}

// tlRecord is the record under key, its raw data and top-level field order.
func tlRecord(t *testing.T, ps *pagestest.Server, key string) (*timeline.Record, []byte, []string) {
	t.Helper()
	rec, ok := ps.Record(key)
	if !ok {
		t.Fatalf("no record %s", key)
	}
	if rec.Schema != timeline.Schema || rec.Version != 1 {
		t.Fatalf("%s: schema %s version %d", key, rec.Schema, rec.Version)
	}
	var r timeline.Record
	if err := json.Unmarshal(rec.Data, &r); err != nil {
		t.Fatal(err)
	}
	return &r, rec.Data, fieldOrder(t, rec.Data)
}

// fieldOrder is a JSON object's top-level keys in their order.
func fieldOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", raw)
	}
	var keys []string
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// tlKeys are a page's timeline keys.
func tlKeys(ps *pagestest.Server, channel string, n int) []string {
	var out []string
	for dir, max := range map[string]int{timeline.In: n, timeline.Out: n} {
		for seq := int64(0); seq <= int64(max); seq++ {
			if _, ok := ps.Record(timeline.Key(channel, dir, seq)); ok {
				out = append(out, timeline.Key(channel, dir, seq))
			}
		}
	}
	return out
}

// sentSeq is the relay seq a send printed.
func sentSeq(t *testing.T, out string) int64 {
	t.Helper()
	m := sentRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no receipt:\n%s", out)
	}
	n, _ := strconv.ParseInt(m[4], 10, 64)
	return n
}

var fieldsInOrder = []string{"id", "dir", "kind", "from", "to", "at", "body"}

// The plan's verify — 一条通道解密后的消息在私有页面上按时间排列: a message
// each way lands once on each side's page, sent as out under the sender's
// relay seq, received as in under the same seq, with the fields of
// peer-timeline@1 in order and nothing about the host, login, token or
// cursor; the handshake's cards are on the page as card events.
func TestTimelineReceivedAndSent(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p, hp, gp := timelinePages(t, base)
	start := time.Now().Add(-time.Second)

	out := mustOK(t, "send", "--dir", p.guestDir, "--kind", "question", "--text", "are you there?\nline two", "zt/advisor")
	id1, seq1 := sentRE.FindStringSubmatch(out)[1], sentSeq(t, out)
	time.Sleep(5 * time.Millisecond)
	out = mustOK(t, "send", "--dir", p.hostDir, "--kind", "answer", "--text", "here", "ancan")
	id2, seq2 := sentRE.FindStringSubmatch(out)[1], sentSeq(t, out)
	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	mustOK(t, "serve", "--dir", p.guestDir, "--once")

	host, _ := os.Hostname()
	_, _, gpe := channelOf(t, p.guestDir, "zt")
	_, _, hpe := channelOf(t, p.hostDir, "ancan")
	for _, tc := range []struct {
		ps                 *pagestest.Server
		dir                string
		seq                int64
		id, kind, from, to string
		body               string
	}{
		{gp, timeline.Out, seq1, id1, "question", p.guestParty, p.hostParty + "/advisor", `"are you there?\nline two"`},
		{hp, timeline.In, seq1, id1, "question", p.guestParty, p.hostParty + "/advisor", `"are you there?\nline two"`},
		{hp, timeline.Out, seq2, id2, "answer", p.hostParty, p.guestParty, `"here"`},
		{gp, timeline.In, seq2, id2, "answer", p.hostParty, p.guestParty, `"here"`},
	} {
		r, raw, order := tlRecord(t, tc.ps, timeline.Key(p.channel, tc.dir, tc.seq))
		if strings.Join(order, ",") != strings.Join(fieldsInOrder, ",") {
			t.Errorf("field order %v: %s", order, raw)
		}
		if r.ID != tc.id || r.Dir != tc.dir || r.Kind != tc.kind || r.From != tc.from || r.To != tc.to || string(r.Body) != tc.body || r.At.Before(start) {
			t.Errorf("record %s %d: %s", tc.dir, tc.seq, raw)
		}
		for _, secret := range []string{host, login, "owner-secret", hp.Bearer, gp.Bearer, gpe.Token, hpe.Token, p.guestDir, p.hostDir, `"cursor"`} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("record carries %q: %s", secret, raw)
			}
		}
	}
	// The received message is stamped by its sender: the page sorts the
	// question before the answer.
	q, _, _ := tlRecord(t, hp, timeline.Key(p.channel, timeline.In, seq1))
	a, _, _ := tlRecord(t, hp, timeline.Key(p.channel, timeline.Out, seq2))
	if !q.At.Before(a.At) {
		t.Errorf("question at %v, answer at %v", q.At, a.At)
	}
	// Beside the two messages, each page holds the details card its side
	// received in the handshake, as a card event.
	for _, ps := range []*pagestest.Server{hp, gp} {
		keys := tlKeys(ps, p.channel, 5)
		cards := 0
		for _, k := range keys {
			if c, raw, _ := tlRecord(t, ps, k); c.Kind == session.KindCard {
				cards++
				if c.Dir != timeline.In || string(c.Body) != `{"event":"card"}` {
					t.Errorf("card record %s", raw)
				}
			}
		}
		if len(keys) != 3 || cards != 1 {
			t.Errorf("%s holds %v, want a card, the question and the answer", ps.Slug, keys)
		}
	}
}

// A doc or file on the timeline is the descriptor's name, size, sha256 and
// mime: never the key that opens the blob, never the blob id.
func TestTimelineAttachmentCarriesNoKey(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p, hp, gp := timelinePages(t, base)
	path, _ := writeFile(t, "report.pdf", 4096)
	out := mustOK(t, "send", "--dir", p.hostDir, "--kind", "doc", "--file", path, "ancan")
	seq := sentSeq(t, out)
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	q := records(t, deliverDirOf(p.guestDir), "quarantine")
	if len(q) != 1 {
		t.Fatalf("quarantine %v", q)
	}
	var key, blob string
	for _, rec := range q {
		desc, _ := descriptorOf(t, rec)
		key, blob = strings.Trim(string(mustJSON(t, desc.Key)), `"`), desc.Blob
	}
	if blobs := srv.Blobs(p.channel); len(blobs) != 1 || blobs[0] != blob {
		t.Fatalf("blobs %v, descriptor %s", blobs, blob)
	}
	for _, tc := range []struct {
		ps  *pagestest.Server
		dir string
	}{{hp, timeline.Out}, {gp, timeline.In}} {
		r, raw, _ := tlRecord(t, tc.ps, timeline.Key(p.channel, tc.dir, seq))
		if order := fieldOrder(t, r.Body); strings.Join(order, ",") != "name,size,sha256" {
			t.Errorf("%s body fields %v: %s", tc.dir, order, raw)
		}
		var f timeline.File
		json.Unmarshal(r.Body, &f)
		if r.Kind != "doc" || f.Name != "report.pdf" || f.Size != 4096 || len(f.SHA256) != 64 || f.Mime != "" {
			t.Errorf("%s record %s", tc.dir, raw)
		}
		for _, s := range []string{key, blob, `"key"`, `"blob"`} {
			if bytes.Contains(raw, []byte(s)) {
				t.Errorf("%s record carries %q: %s", tc.dir, s, raw)
			}
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A page that refuses costs the round one log line and nothing else: both
// messages are born, the cursor moves, serve and send exit 0.
func TestTimelineRefusalLeavesDelivery(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	bad := pagestest.New("tl-bad-0123456789abcdef", "zt:right-secret")
	t.Cleanup(bad.Close)
	wrong := config{Timelines: map[string]timelineConfig{"zt": {Page: bad.URL, Slug: bad.Slug, Login: "zt:wrong-secret"}}}
	p := handshake(t, newDir(t, hostCfg()), newDir(t, wrong), base)
	_, ch, _ := channelOf(t, p.guestDir, "zt")
	before := ch.Cursor()

	id1, _ := sendOK(t, p.hostDir, "--text", "one", "ancan")
	id2, _ := sendOK(t, p.hostDir, "--text", "two", "ancan")
	out := mustOK(t, "serve", "--dir", p.guestDir, "--once")
	if !strings.Contains(out, "delivered text "+id1) || !strings.Contains(out, "delivered text "+id2) {
		t.Fatalf("serve:\n%s", out)
	}
	if n := strings.Count(out, "timeline zt: "); n != 1 || !strings.Contains(out, "401 bad_token") {
		t.Fatalf("%d timeline lines in one round:\n%s", n, out)
	}
	if _, ch, _ := channelOf(t, p.guestDir, "zt"); ch.Cursor() != before+2 {
		t.Fatalf("cursor %d, want %d", ch.Cursor(), before+2)
	}
	inbox := records(t, deliverDirOf(p.guestDir), "inbox")
	if inbox[id1] == nil || inbox[id2] == nil {
		t.Fatalf("inbox %v", inbox)
	}

	code, sout, errb := cmd(t, "send", "--dir", p.guestDir, "--text", "back", "zt")
	if code != 0 || !sentRE.MatchString(sout) || strings.Count(errb, "timeline zt: ") != 1 {
		t.Fatalf("send with the page refusing: exit %d\n%s%s", code, sout, errb)
	}
	if len(tlKeys(bad, p.channel, 5)) != 0 {
		t.Fatal("a refused page holds records")
	}
}

// The key is the message's place on the relay, and the write is
// create-only: the same message written twice is one record at version 1,
// and a birth the spool replays at start is written once.
func TestTimelineSameMessageOnce(t *testing.T) {
	ctx := context.Background()
	_, _, base := relaytest.Start(t, login)
	p, _, gp := timelinePages(t, base)

	// Cut the guest's serve after the commit, before the birth: the
	// message waits in the spool, on no page.
	id, _ := sendOK(t, p.hostDir, "--text", "replayed", "ancan")
	sv, err := openServer(p.guestDir, "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cut := errors.New("cut before the birth")
	sv.beforeBirth = func(*store.Entry) error { return cut }
	if err := sv.round(ctx); !errors.Is(err, cut) {
		t.Fatalf("round: %v", err)
	}
	_, ch, _ := channelOf(t, p.guestDir, "zt")
	key := timeline.Key(p.channel, timeline.In, ch.Cursor())
	if _, ok := gp.Record(key); ok {
		t.Fatal("a record before the birth")
	}
	// The next start births it and writes it.
	var log bytes.Buffer
	sv2, err := openServer(p.guestDir, "", &log)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv2.start(ctx); err != nil {
		t.Fatal(err)
	}
	r, _, _ := tlRecord(t, gp, key)
	if r.ID != id || string(r.Body) != `"replayed"` {
		t.Fatalf("record %+v\n%s", r, log.String())
	}
	// Written again — another host, a replay after a crash before the spool
	// entry went: one more PUT, refused at v=0, the record unchanged.
	m := &session.Message{V: 1, ID: r.ID, From: r.From, To: r.To, Kind: r.Kind, At: r.At, Body: []byte("replayed")}
	puts := gp.Puts()
	sv2.p.writeTimeline(ctx, "zt", p.channel, timeline.In, ch.Cursor(), m)
	if gp.Puts() != puts+1 {
		t.Fatalf("%d PUTs for one write", gp.Puts()-puts)
	}
	tlRecord(t, gp, key) // still version 1
	if strings.Contains(log.String(), "timeline") {
		t.Fatalf("log:\n%s", log.String())
	}
}

// A sent message whose put failed after its commit has no relay seq yet:
// its record waits beside the outbox and is written under the seq the
// replay's put returns.
func TestTimelineSentAfterOutboxReplay(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	target, err := url.Parse(strings.TrimSuffix(base, "/peer"))
	if err != nil {
		t.Fatal(err)
	}
	fr := &flakyRelay{proxy: httputil.NewSingleHostReverseProxy(target)}
	proxy := httptest.NewServer(fr)
	t.Cleanup(proxy.Close)
	p, _, gp := timelinePages(t, proxy.URL+"/peer")

	fr.refusePuts.Store(true)
	code, _, errb := cmd(t, "send", "--dir", p.guestDir, "--text", "queued", "zt/advisor")
	m := regexp.MustCompile(`peer send: (\S+) is committed but the relay did not take it`).FindStringSubmatch(errb)
	if code != 1 || m == nil {
		t.Fatalf("send with the relay down: exit %d, stderr %q", code, errb)
	}
	pending := filepath.Join(p.guestDir, timelinePendingDir, m[1]+".json")
	if _, err := os.Stat(pending); err != nil {
		t.Fatal(err)
	}
	fr.refusePuts.Store(false)
	mustOK(t, "serve", "--dir", p.guestDir, "--once")
	rows := srv.Envelopes(p.channel, "g2h")
	seq := rows[len(rows)-1].Seq
	r, raw, _ := tlRecord(t, gp, timeline.Key(p.channel, timeline.Out, seq))
	if r.ID != m[1] || r.Dir != timeline.Out || string(r.Body) != `"queued"` {
		t.Fatalf("record %s", raw)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending record left: %v", err)
	}
}
