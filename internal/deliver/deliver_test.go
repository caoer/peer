package deliver

import (
	"bytes"
	"errors"
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
		// An empty list is an address nothing here answers to: it takes no
		// kind, where a nil list takes every kind.
		{"text", []string{}, Quarantine}, {"vnd.zt.ping", []string{}, Quarantine}, {"ack", []string{}, Quarantine},
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
		{From: ancan, To: zt, Kind: "vnd.ed25519:" + strings.Repeat("C", 43) + ".do thing"},
		{From: ancan, To: "ed25519:" + strings.Repeat("B", 43) + "/legal team", Kind: "text"},
		{From: ancan, To: "ed25519:" + strings.Repeat("B", 43) + "/a/b", Kind: "text"},
		{From: "ed25519:" + strings.Repeat("A", 43) + "/" + strings.Repeat("x", 65), To: zt, Kind: "text"},
	} {
		if _, err := bad.Bytes(); !errors.Is(err, ErrRecord) {
			t.Errorf("%+v: %v, want ErrRecord", bad, err)
		}
	}
}

// A room record carries group, the room id, as its sixth key, after at; a
// group that is not a room id refuses.
func TestRecordBytesGroup(t *testing.T) {
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	group := strings.Repeat("ab", 16)
	b, err := Record{From: ancan, To: zt, Kind: "text", At: at, Body: []byte("hi all\n"), Group: group}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := "---\nfrom: " + ancan + "\nto: " + zt + "\nkind: text\nverified: true\nat: 2026-10-15T09:00:00Z\ngroup: " + group + "\n---\nhi all\n"
	if string(b) != want {
		t.Fatalf("record:\n%s\nwant:\n%s", b, want)
	}
	for _, bad := range []string{"AB" + group[2:], group[:31], group + "\nkind: ack", "r1"} {
		if _, err := (Record{From: ancan, To: zt, Kind: "text", At: at, Group: bad}).Bytes(); !errors.Is(err, ErrRecord) {
			t.Errorf("group %q: %v, want ErrRecord", bad, err)
		}
	}
}

// The documented vendor kind — vnd.<party id>.<name>, so it holds the party
// id's colon — is a record the writer can write, as a quoted scalar.
func TestRecordBytesVendorKind(t *testing.T) {
	kind := "vnd.ed25519:" + strings.Repeat("C", 43) + ".ping"
	if !ValidVendorKind(kind) {
		t.Fatalf("%q is not a vendor kind", kind)
	}
	b, err := Record{From: ancan, To: zt, Kind: kind, At: time.Now(), Body: []byte("x")}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nkind: \""+kind+"\"\n") {
		t.Fatalf("record does not carry the kind as a quoted scalar:\n%s", b)
	}
}

func TestValidAddr(t *testing.T) {
	party := "ed25519:" + strings.Repeat("A", 43)
	for _, good := range []string{party, party + "/legal", party + "/legal.team_2-x"} {
		if !ValidAddr(good) {
			t.Errorf("ValidAddr(%q) = false", good)
		}
	}
	for _, bad := range []string{"", "ancan", "ancan/legal", party + "x", party + "/", party + "/a b", party + "/a/b", party + "/" + strings.Repeat("x", 65)} {
		if ValidAddr(bad) {
			t.Errorf("ValidAddr(%q) = true", bad)
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

// A roster notice lands in the inbox whatever the seat's accepts says: a
// list without roster, and an empty list that takes no other kind.
func TestRouteRosterWhateverAccepts(t *testing.T) {
	for _, accepts := range [][]string{{"text", "task"}, {}, nil} {
		if got := Route(KindRoster, accepts); got != Inbox {
			t.Errorf("Route(%q, %v) = %s, want %s", KindRoster, accepts, got, Inbox)
		}
	}
}
