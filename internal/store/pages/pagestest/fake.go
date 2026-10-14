// Package pagestest serves a fake ccc-pages /d/ store for tests: the owner
// Bearer, CAS by ?v=, the envelope cap, and the status codes and bodies the
// real one answers (plan-research-ccc-pages § 5). The real one is U9's.
package pagestest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is one fake page's /d/ store.
type Server struct {
	*httptest.Server
	Slug, Bearer string
	// MaxEnvelope is the cap on {"schema","data"}; the real one's is 256 KiB.
	MaxEnvelope int

	mu      sync.Mutex
	records map[string]Record
	puts    int
}

// Record is one stored object.
type Record struct {
	Schema  string
	Data    json.RawMessage
	Version int64
}

var (
	keyRE    = regexp.MustCompile(`^[a-z0-9._-]{1,128}$`)
	schemaRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}@[0-9]{1,9}$`)
)

// New starts a fake serving one page; Close it when done.
func New(slug, bearer string) *Server {
	s := &Server{Slug: slug, Bearer: bearer, MaxEnvelope: 256 * 1024, records: map[string]Record{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Record returns the stored object.
func (s *Server) Record(key string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[key]
	return r, ok
}

// Set stores an object as given, for a test that corrupts one.
func (s *Server) Set(key string, r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[key] = r
}

// Puts counts the PUT requests received, refused ones included.
func (s *Server) Puts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	answer := func(status int, body map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(body)
	}
	refuse := func(status int, code, msg string) {
		answer(status, map[string]any{"error": msg, "code": code})
	}
	if r.Header.Get("Authorization") != "Bearer "+s.Bearer {
		refuse(401, "bad_token", "bad token")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "d" {
		refuse(404, "no_such_route", "no such route")
		return
	}
	if parts[1] != s.Slug {
		refuse(404, "no_such_page", "no such page")
		return
	}
	key := parts[2]
	if !keyRE.MatchString(key) {
		refuse(400, "bad_key", "bad key")
		return
	}
	now := time.Now().UnixMilli()
	switch r.Method {
	case http.MethodGet:
		rec, ok := s.Record(key)
		if !ok {
			refuse(404, "no_such_object", "no such object")
			return
		}
		answer(200, map[string]any{"key": key, "value": map[string]any{"schema": rec.Schema, "data": rec.Data}, "version": rec.Version, "updated_at": now})
	case http.MethodPut:
		s.mu.Lock()
		s.puts++
		s.mu.Unlock()
		v := r.URL.Query().Get("v")
		force := v == "force"
		expect, err := strconv.ParseInt(v, 10, 64)
		if !force && (err != nil || len(v) > 9) {
			refuse(400, "bad_version", "?v= must be an integer or force")
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 512*1024+1))
		if len(raw) > 512*1024 {
			refuse(413, "too_large", "request body over 512 KiB")
			return
		}
		var env map[string]json.RawMessage
		if err := json.Unmarshal(raw, &env); err != nil {
			refuse(400, "bad_json", "body is not JSON")
			return
		}
		schemaRaw, hasSchema := env["schema"]
		data, hasData := env["data"]
		if len(env) != 2 || !hasSchema || !hasData {
			refuse(400, "bad_envelope", "envelope is {schema, data}")
			return
		}
		var schema string
		if err := json.Unmarshal(schemaRaw, &schema); err != nil || !schemaRE.MatchString(schema) {
			refuse(400, "bad_schema", "bad schema id")
			return
		}
		compact, _ := json.Marshal(map[string]any{"schema": schema, "data": data})
		if len(compact) > s.MaxEnvelope {
			refuse(413, "too_large", "object over the cap")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		cur := s.records[key].Version
		if !force && cur != expect {
			answer(409, map[string]any{"error": "expected version " + strconv.FormatInt(expect, 10) + ", found " + strconv.FormatInt(cur, 10), "code": "version_conflict", "version": cur})
			return
		}
		next := cur + 1
		s.records[key] = Record{Schema: schema, Data: append(json.RawMessage(nil), data...), Version: next}
		answer(200, map[string]any{"ok": true, "key": key, "version": next, "updated_at": now})
	default:
		refuse(405, "method_not_allowed", "method not allowed")
	}
}
