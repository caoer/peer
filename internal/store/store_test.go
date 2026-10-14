package store_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/keys"
	"github.com/caoer/peer/internal/store"
	"github.com/caoer/peer/internal/store/file"
	"github.com/caoer/peer/internal/store/pages"
	"github.com/caoer/peer/internal/store/pages/pagestest"
)

// The test binary doubles as the second process: with PEER_STORE_CHILD set it
// runs child instead of the tests.
func TestMain(m *testing.M) {
	if os.Getenv("PEER_STORE_CHILD") != "" {
		os.Exit(child())
	}
	os.Exit(m.Run())
}

// backendFromSpec opens "file:<dir>" or "pages:<url>|<slug>|<bearer>" (sealed).
func backendFromSpec(spec string, id *keys.Identity) (store.Backend, error) {
	kind, rest, _ := strings.Cut(spec, ":")
	switch kind {
	case "file":
		return file.New(rest)
	case "pages":
		parts := strings.Split(rest, "|")
		if len(parts) != 3 {
			return nil, fmt.Errorf("bad pages spec %q", spec)
		}
		return store.Sealed(pages.New(parts[0], parts[1], parts[2], nil), store.SealKey(id)), nil
	}
	return nil, fmt.Errorf("bad backend spec %q", spec)
}

// child loads channel c, marks PEER_STORE_ID seen, waits for the parent's
// line, commits; a conflict reloads and redoes the work until the commit lands.
func child() int {
	ctx := context.Background()
	var id keys.Identity
	if err := json.Unmarshal([]byte(os.Getenv("PEER_STORE_IDENTITY")), &id); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	b, err := backendFromSpec(os.Getenv("PEER_STORE_BACKEND"), &id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	s := store.New(b, &id)
	msg := os.Getenv("PEER_STORE_ID")
	ch, err := s.Channel(ctx, "c")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ch.MarkSeen(msg, 1)
	fmt.Println("loaded")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	retried := 0
	for {
		err := ch.Commit(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		retried++
		if ch, err = s.Channel(ctx, "c"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		ch.MarkSeen(msg, 1)
	}
	fmt.Printf("committed version=%d retried=%d\n", ch.Version(), retried)
	return 0
}

type childProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Reader
}

func startChild(t *testing.T, spec, identity, msg string) *childProc {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "PEER_STORE_CHILD=1", "PEER_STORE_BACKEND="+spec, "PEER_STORE_IDENTITY="+identity, "PEER_STORE_ID="+msg)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return &childProc{cmd: cmd, stdin: stdin, out: bufio.NewReader(stdout)}
}

func (c *childProc) line(t *testing.T) string {
	t.Helper()
	l, err := c.out.ReadString('\n')
	if err != nil {
		t.Fatalf("child output: %v", err)
	}
	return strings.TrimSpace(l)
}

// Two processes load the same version, both commit: one lands, the other
// gets ErrConflict, reloads and retries, and nothing is lost — the plan
// line's 两个进程同时写，一个成功一个重试，没有一条丢 — on both backends.
func TestTwoProcessesCommitConcurrently(t *testing.T) {
	root, err := keys.GenerateRoot()
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.GenerateIdentity(root.Public())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"file", "pages"} {
		t.Run(kind, func(t *testing.T) {
			var spec string
			switch kind {
			case "file":
				spec = "file:" + filepath.Join(t.TempDir(), "state")
			case "pages":
				srv := pagestest.New("state-0123456789abcdef", "zt:token")
				defer srv.Close()
				spec = "pages:" + srv.URL + "|" + srv.Slug + "|" + srv.Bearer
			}
			a := startChild(t, spec, string(identity), "from-a")
			b := startChild(t, spec, string(identity), "from-b")
			for _, c := range []*childProc{a, b} {
				if l := c.line(t); l != "loaded" {
					t.Fatalf("child said %q before loading", l)
				}
			}
			// Both hold version 0; release them together.
			for _, c := range []*childProc{a, b} {
				if _, err := io.WriteString(c.stdin, "go\n"); err != nil {
					t.Fatal(err)
				}
			}
			results := []string{a.line(t), b.line(t)}
			for _, c := range []*childProc{a, b} {
				if err := c.cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			}
			retries := 0
			for _, r := range results {
				var v, n int
				if _, err := fmt.Sscanf(r, "committed version=%d retried=%d", &v, &n); err != nil {
					t.Fatalf("child result %q: %v", r, err)
				}
				retries += n
			}
			if retries != 1 {
				t.Fatalf("results %q: %d retries, want exactly one loser", results, retries)
			}
			backend, err := backendFromSpec(spec, id)
			if err != nil {
				t.Fatal(err)
			}
			ch, err := store.New(backend, id).Channel(context.Background(), "c")
			if err != nil {
				t.Fatal(err)
			}
			if ch.Version() != 2 || !ch.Seen("from-a") || !ch.Seen("from-b") {
				t.Fatalf("final: version %d, a=%v b=%v — a commit was lost", ch.Version(), ch.Seen("from-a"), ch.Seen("from-b"))
			}
		})
	}
}
