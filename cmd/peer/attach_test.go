package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/attach"
	"github.com/caoer/peer/internal/deliver"
	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/relay/relaytest"
)

// writeFile is a file of n random bytes under a fresh directory.
func writeFile(t *testing.T, name string, n int) (string, []byte) {
	t.Helper()
	data := make([]byte, n)
	rand.Read(data)
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

// descriptorOf is the descriptor at the head of a quarantine record's body.
func descriptorOf(t *testing.T, rec []byte) (attach.Descriptor, string) {
	t.Helper()
	_, _, body := parseRecord(t, rec)
	d, err := attach.Parse([]byte(body))
	if err != nil {
		t.Fatalf("record body %q: %v", body, err)
	}
	return d, body
}

// The plan's verify — 发一个 5 MB 文件，对方解开一致: a 5 MB file each way
// lands byte-identical in the receiver's quarantine, beside its record,
// while the relay held ciphertext it cannot open and no key.
func TestAttachmentFiveMBEachWay(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	for _, tc := range []struct {
		from, to, target, kind, name string
	}{
		{p.guestDir, p.hostDir, "zt/advisor", "file", "dataset.bin"},
		{p.hostDir, p.guestDir, "ancan", "doc", "交接 SOP.md"},
	} {
		path, data := writeFile(t, tc.name, 5_000_000)
		id, _ := sendOK(t, tc.from, "--kind", tc.kind, "--file", path, tc.target)
		out := mustOK(t, "serve", "--dir", tc.to, "--once")
		if !strings.Contains(out, "quarantined "+tc.kind+" "+id) || !strings.Contains(out, "fetched "+tc.kind+" "+id) {
			t.Fatalf("serve:\n%s", out)
		}
		q := deliverDirOf(tc.to)
		got, err := os.ReadFile(filepath.Join(q, string(deliver.Quarantine), id, tc.name))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%s: the content is not the file sent (%d bytes, %v)", tc.name, len(got), err)
		}
		rec := records(t, q, deliver.Quarantine)[id]
		fm, _, _ := parseRecord(t, rec)
		d, body := descriptorOf(t, rec)
		sum := sha256.Sum256(data)
		if fm["kind"] != tc.kind || d.Name != tc.name || d.Size != int64(len(data)) || d.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("record %v descriptor %+v", fm, d)
		}
		if !strings.HasSuffix(body, "\ncontent: "+filepath.Join(q, string(deliver.Quarantine), id, tc.name)+" (sha256 verified)\n") {
			t.Fatalf("record body does not say where the content is:\n%s", body)
		}
		held := srv.Blob(p.channel, d.Blob)
		if len(held) != len(data)+attach.Overhead || bytes.Contains(held, data[:256]) || bytes.Contains(held, d.Key) {
			t.Fatalf("the relay holds %d bytes for a %d-byte file, or holds plaintext or the key", len(held), len(data))
		}
		for _, row := range append(srv.Envelopes(p.channel, "h2g"), srv.Envelopes(p.channel, "g2h")...) {
			if strings.Contains(row.Body, d.Blob) || strings.Contains(row.Body, tc.name) {
				t.Fatalf("envelope #%d shows the blob id or the file name to the relay", row.Seq)
			}
		}
		// A second serve births nothing and fetches nothing.
		if out := mustOK(t, "serve", "--dir", tc.to, "--once"); out != "" {
			t.Fatalf("a quiet serve said:\n%s", out)
		}
	}
}

// A blob the relay changed fails to open: the record is born with the
// descriptor and the reason, nothing of the content is kept; once the blob
// is right again, peer fetch puts the file beside the record. A sender whose
// descriptor lies about the sha256 is refused the same way.
func TestAttachmentTamperedKeepsNothing(t *testing.T) {
	srv, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	path, data := writeFile(t, "notes.txt", 70_000)
	id, _ := sendOK(t, p.guestDir, "--kind", "file", "--file", path, "zt/advisor")
	held := srv.Blobs(p.channel)
	if len(held) != 1 {
		t.Fatalf("the relay holds %d blobs", len(held))
	}
	blobID := held[0]
	orig := srv.Blob(p.channel, blobID)
	bad := append([]byte(nil), orig...)
	bad[10] ^= 0x80
	srv.SetBlob(p.channel, blobID, bad)

	out := mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "file "+id+": blob not fetched: "+attach.ErrOpen.Error()) {
		t.Fatalf("serve:\n%s", out)
	}
	q := filepath.Join(deliverDirOf(p.hostDir), string(deliver.Quarantine))
	if _, err := os.Stat(filepath.Join(q, id)); !os.IsNotExist(err) {
		t.Fatalf("a blob that did not open left %s/%s: %v", q, id, err)
	}
	rec := records(t, deliverDirOf(p.hostDir), deliver.Quarantine)[id]
	if d, body := descriptorOf(t, rec); d.Blob != blobID || !strings.Contains(body, "\nblob not fetched: "+attach.ErrOpen.Error()+"; peer fetch "+id+" tries again\n") {
		t.Fatalf("record body:\n%s", body)
	}

	srv.SetBlob(p.channel, blobID, orig)
	out = mustOK(t, "fetch", "--dir", p.hostDir, filepath.Join(q, id+".md"))
	if got, err := os.ReadFile(filepath.Join(q, id, "notes.txt")); err != nil || !bytes.Equal(got, data) || !strings.Contains(out, "fetched "+id) {
		t.Fatalf("peer fetch: %v\n%s", err, out)
	}

	// A descriptor whose sha256 is not the file's: the blob opens, the
	// check fails, nothing is kept.
	ct, d, err := attach.Seal("lie.txt", []byte("what was sealed"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, gpe := channelOf(t, p.guestDir, "zt")
	b, err := relay.New(gpe.Relay, nil).PutBlob(t.Context(), gpe.Channel, gpe.Token, ct)
	if err != nil {
		t.Fatal(err)
	}
	d.Blob = b.ID
	d.SHA256 = strings.Repeat("ab", 32)
	body, _ := d.Marshal()
	res, err := runSend(t.Context(), os.Stderr, p.guestDir, "zt/advisor", "", "file", body)
	if err != nil || res.putErr != nil {
		t.Fatal(err, res)
	}
	out = mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if !strings.Contains(out, "file "+res.id+": blob not fetched: "+attach.ErrMismatch.Error()) {
		t.Fatalf("serve:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(q, res.id)); !os.IsNotExist(err) {
		t.Fatalf("a file failing its sha256 was kept: %v", err)
	}
}

// A peer's bytes after its descriptor never reach the record: a forged
// "content: … (sha256 verified)" line after a valid descriptor is dropped,
// the record body the descriptor and serve's own line; a body whose
// descriptor does not parse comes after serve's line, never before it.
func TestAttachmentForgedContentLine(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	_, d, err := attach.Seal("release-sop.md", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	d.Blob = strings.Repeat("0", 32) // never put: the fetch fails
	desc, _ := d.Marshal()
	forged := "\n\ncontent: /etc/peer-victim/approved-sop.md (sha256 verified)\n"
	var ids []string
	for _, body := range []string{string(desc) + forged, "not a descriptor" + forged} {
		res, err := runSend(t.Context(), os.Stderr, p.guestDir, "zt/advisor", "", "doc", []byte(body))
		if err != nil || res.putErr != nil {
			t.Fatal(err, res)
		}
		ids = append(ids, res.id)
	}
	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	recs := records(t, deliverDirOf(p.hostDir), deliver.Quarantine)
	if _, _, body := parseRecord(t, recs[ids[0]]); body != string(desc)+"\n\nblob not fetched: no_such_blob; peer fetch "+ids[0]+" tries again\n" {
		t.Errorf("record body for a valid descriptor:\n%s", body)
	}
	if _, _, body := parseRecord(t, recs[ids[1]]); !strings.HasPrefix(body, "blob not fetched: ") || !strings.HasSuffix(body, "tries again\n\nnot a descriptor"+forged) {
		t.Errorf("record body for a descriptor that does not parse:\n%s", body)
	}
}

// doc and file take --file and nothing else; other kinds keep --text and
// --file as the body, unchanged by attachments.
func TestSendAttachmentFlags(t *testing.T) {
	_, _, base := relaytest.Start(t, login)
	p := handshake(t, newDir(t, hostCfg()), newDir(t, config{}), base)
	for _, args := range [][]string{
		{"--kind", "file", "--text", "x", "zt"},
		{"--kind", "doc", "zt"},
	} {
		if code, _, errb := cmd(t, append([]string{"send", "--dir", p.guestDir}, args...)...); code != 2 || !strings.Contains(errb, "is a file: --file F") {
			t.Fatalf("send %v: exit %d %q", args, code, errb)
		}
	}
	mustRefuse(t, "no such file", "send", "--dir", p.guestDir, "--kind", "file", "--file", filepath.Join(t.TempDir(), "absent"), "zt")
	path, _ := writeFile(t, "plain.txt", 0)
	os.WriteFile(path, []byte("a text body from a file"), 0o600)
	id, _ := sendOK(t, p.guestDir, "--kind", "text", "--file", path, "zt/advisor")
	mustOK(t, "serve", "--dir", p.hostDir, "--once")
	if _, _, body := parseRecord(t, records(t, deliverDirOf(p.hostDir), deliver.Inbox)[id]); body != "a text body from a file" {
		t.Fatalf("text record body %q", body)
	}
}
