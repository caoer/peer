package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The reader page is a published artefact a reader audits by eye, so the
// properties the reader relies on are pinned here.

var pagePath = filepath.Join("..", "..", "worker", "reader", "index.html")

func readPage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(pagePath)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// code is the page without its HTML comments, which load and run nothing.
func code(page string) string {
	return regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(page, "")
}

// inlineBody returns the text of the page's only <tag> element.
func inlineBody(t *testing.T, page, tag string) string {
	t.Helper()
	if n := len(regexp.MustCompile(`(?i)<`+tag+`\b`).FindAllString(page, -1)); n != 1 {
		t.Fatalf("%d <%s> elements, want 1", n, tag)
	}
	m := regexp.MustCompile(`(?s)<` + tag + `>(.*?)</` + tag + `>`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no attribute-free <%s> element", tag)
	}
	return m[1]
}

// TestPageNoExternalReference holds the page to one file: no element or rule
// that loads anything, no storage but the key's IndexedDB database, and one
// connection, the same-origin feed socket.
func TestPageNoExternalReference(t *testing.T) {
	page := code(readPage(t))
	lower := strings.ToLower(page)
	for _, bad := range []string{
		"<script src", "<link", "<img", "<iframe", "<object", "<embed", "<audio", "<video", "<source", "<base", "<form",
		"@import", "url(", "http://", "https://", " src=", " href=",
		"localstorage", "sessionstorage", "document.cookie", "caches.", "serviceworker",
		"fetch(", "sendbeacon", "xmlhttprequest", "eventsource",
		"innerhtml", "outerhtml", "insertadjacenthtml", "document.write",
		"eval(", "new function", "import(", "window.open", "location.href", "location.assign", "location.replace",
	} {
		if strings.Contains(lower, bad) {
			t.Errorf("the page contains %q", bad)
		}
	}
	inlineBody(t, page, "script")
	inlineBody(t, page, "style")
	if n := strings.Count(page, "WebSocket("); n != 1 {
		t.Errorf("%d WebSocket constructions, want 1", n)
	}
	if !strings.Contains(page, `new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/feed/" + party)`) {
		t.Error("the page's connection is not the same-origin /feed/<party id> socket")
	}
	if n := strings.Count(page, "indexedDB."); n != 1 || !strings.Contains(page, `indexedDB.open(DB, 1)`) || !strings.Contains(page, `const DB = "peer-reader";`) {
		t.Error("the page's storage is not the one peer-reader IndexedDB database")
	}
}

// TestPageSecretNeverExtractable pins that every secret key the page holds is
// born or imported non-extractable, and that its one export reads a public key.
func TestPageSecretNeverExtractable(t *testing.T) {
	page := code(readPage(t))
	for _, c := range []struct{ call, want string }{
		{"generateKey(", `crypto.subtle.generateKey(X25519, false, ["deriveBits"])`},
		{"exportKey(", `crypto.subtle.exportKey("raw", pair.publicKey)`},
		{`importKey("pkcs8"`, `crypto.subtle.importKey("pkcs8", der, X25519, false, ["deriveBits"])`},
	} {
		if n, m := strings.Count(page, c.call), strings.Count(page, c.want); n != 1 || m != 1 {
			t.Errorf("%d %s calls and %d of the form %s, want 1 and 1", n, c.call, m, c.want)
		}
	}
	if strings.Contains(page, "wrapKey(") {
		t.Error("the page wraps a key")
	}
}

// TestPageCSPHashes recomputes the policy from the page's own bytes.
func TestPageCSPHashes(t *testing.T) {
	page := readPage(t)
	metas := regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]*)">`).FindAllStringSubmatchIndex(page, -1)
	if len(metas) != 1 {
		t.Fatalf("%d CSP meta elements, want 1", len(metas))
	}
	got := page[metas[0][2]:metas[0][3]]

	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	want := "default-src 'none'; connect-src 'self' wss://peer.0xtau.com; script-src " + hash(inlineBody(t, page, "script")) +
		"; style-src " + hash(inlineBody(t, page, "style")) + "; base-uri 'none'; form-action 'none'"
	if got != want {
		t.Errorf("CSP\n got %s\nwant %s", got, want)
	}

	// A meta policy governs only what comes after it.
	if metas[0][0] > strings.Index(page, "<style>") || metas[0][0] > strings.Index(page, "<script>") {
		t.Error("the CSP meta must come before the style and the script")
	}
}
