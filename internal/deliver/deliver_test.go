package deliver

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	ancan = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/legal"
	zt    = "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/advisor"
)

func TestRoute(t *testing.T) {
	seat := []string{"text", "task", "question", "answer", "ack"}
	for _, c := range []struct {
		kind    string
		accepts []string
		want    Place
	}{
		{"text", seat, Inbox}, {"task", seat, Inbox}, {"question", seat, Inbox}, {"answer", seat, Inbox}, {"ack", seat, Inbox},
		{"doc", seat, Quarantine}, {"file", seat, Quarantine},
		{"doc", []string{"doc"}, Quarantine}, {"doc", nil, Quarantine}, {"file", nil, Quarantine},
		{"vnd.zt.ping", seat, Quarantine}, {"vnd.zt.ping", nil, Inbox}, {"vnd.zt.ping", []string{"vnd.zt.ping"}, Inbox},
		{"text", nil, Inbox}, {"text", []string{"task"}, Quarantine},
	} {
		if got := Route(c.kind, c.accepts); got != c.want {
			t.Errorf("Route(%q, %v) = %s, want %s", c.kind, c.accepts, got, c.want)
		}
	}
}

func TestRecordBytes(t *testing.T) {
	at := time.Date(2026, 10, 14, 20, 0, 0, 123000000, time.UTC)
	b, err := Record{From: ancan, To: zt, Kind: "task", At: at, Body: []byte("do the thing\n")}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := "---\nfrom: " + ancan + "\nto: " + zt + "\nkind: task\nverified: true\nat: 2026-10-14T20:00:00.123Z\n---\ndo the thing\n"
	if string(b) != want {
		t.Fatalf("record:\n%s\nwant:\n%s", b, want)
	}
	for _, bad := range []Record{
		{From: "ancan/legal", To: zt, Kind: "text"},
		{From: ancan, To: zt + "\nkind: ack", Kind: "text"},
		{From: ancan, To: zt, Kind: "vnd.x y"},
	} {
		if _, err := bad.Bytes(); err == nil {
			t.Errorf("%+v: written", bad)
		}
	}
}

func TestWriteOnce(t *testing.T) {
	dir := t.TempDir()
	r := Record{From: ancan, To: zt, Kind: "text", At: time.Now(), Body: []byte("hi")}
	path, born, err := Write(dir, Inbox, "m1", r)
	if err != nil || !born || path != filepath.Join(dir, "inbox", "m1.md") {
		t.Fatalf("first write: %s born=%v err=%v", path, born, err)
	}
	first, _ := os.ReadFile(path)
	r.Body = []byte("replayed")
	if path2, born, err := Write(dir, Inbox, "m1", r); err != nil || born || path2 != path {
		t.Fatalf("second write: %s born=%v err=%v", path2, born, err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(first, again) {
		t.Fatal("second write changed the record")
	}
	if names, _ := filepath.Glob(filepath.Join(dir, "inbox", "*")); len(names) != 1 {
		t.Fatalf("inbox holds %v", names)
	}
	if _, _, err := Write(dir, Quarantine, "../m2", r); err == nil || !strings.Contains(err.Error(), "cannot name a file") {
		t.Fatalf("bad id: %v", err)
	}
	if _, born, err := Write(dir, Quarantine, "m2", r); err != nil || !born {
		t.Fatalf("quarantine write: born=%v err=%v", born, err)
	}
}
