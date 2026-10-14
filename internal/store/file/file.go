// Package file is the store backend for one machine: one JSON file per
// record under a directory, `{"version": n, "data": …}`, written under an
// exclusive flock on a sibling lock file so two processes on the machine
// compare-and-swap correctly. Records are plaintext, mode 0600, like the
// identity file beside them.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/caoer/peer/internal/store"
)

// Backend is a directory of versioned JSON records.
type Backend struct{ dir string }

// New opens (creating) dir.
func New(dir string) (*Backend, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Backend{dir: dir}, nil
}

type fileRecord struct {
	Version int64           `json:"version"`
	Data    json.RawMessage `json:"data"`
}

func (b *Backend) paths(key string) (rec, lock string, err error) {
	if !store.ValidKey(key) {
		return "", "", fmt.Errorf("file: %q is not a record key", key)
	}
	return filepath.Join(b.dir, key+".json"), filepath.Join(b.dir, key+".lock"), nil
}

// Load reads a record under a shared lock.
func (b *Backend) Load(ctx context.Context, key string) ([]byte, int64, error) {
	rec, lock, err := b.paths(key)
	if err != nil {
		return nil, 0, err
	}
	unlock, err := flock(lock, syscall.LOCK_SH)
	if err != nil {
		return nil, 0, err
	}
	defer unlock()
	r, err := read(rec)
	if err != nil {
		return nil, 0, err
	}
	return r.Data, r.Version, nil
}

// Store writes a record under an exclusive lock when its version is expect.
// Data must be JSON: the file is readable as it lies.
func (b *Backend) Store(ctx context.Context, key string, data []byte, expect int64) (int64, error) {
	if !json.Valid(data) {
		return 0, fmt.Errorf("file: %s: data is not JSON", key)
	}
	rec, lock, err := b.paths(key)
	if err != nil {
		return 0, err
	}
	unlock, err := flock(lock, syscall.LOCK_EX)
	if err != nil {
		return 0, err
	}
	defer unlock()
	cur, err := read(rec)
	if err != nil {
		return 0, err
	}
	if cur.Version != expect {
		return 0, &store.ConflictError{Key: key, Expected: expect, Found: cur.Version}
	}
	next := expect + 1
	out, err := json.Marshal(fileRecord{Version: next, Data: data})
	if err != nil {
		return 0, err
	}
	tmp := rec + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		return 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, rec); err != nil {
		return 0, err
	}
	return next, nil
}

// read parses a record file; an absent file is the zero record (version 0).
func read(path string) (fileRecord, error) {
	var r fileRecord
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("file: %s: %w", path, err)
	}
	return r, nil
}

// flock takes a lock on path and returns the release.
func flock(path string, how int) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
