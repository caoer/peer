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

// The chat page is a published artefact a reader audits by eye, so the two
// properties the reader relies on are pinned here.

var pagePath = filepath.Join("..", "..", "docs", "timeline", "index.html")

func readPage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(pagePath)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
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
// that loads anything, no way to store the key, and one request, to /d/.
func TestPageNoExternalReference(t *testing.T) {
	page := readPage(t)
	lower := strings.ToLower(page)
	for _, bad := range []string{
		"<script src", "<link", "<img", "<iframe", "<object", "<embed", "<audio", "<video", "<source", "<base", "<form",
		"@import", "url(", "http://", "https://", " src=", " href=",
		"localstorage", "sessionstorage", "indexeddb", "document.cookie",
		"sendbeacon", "xmlhttprequest", "websocket", "eventsource",
		"innerhtml", "outerhtml", "insertadjacenthtml", "document.write",
		"eval(", "new function", "import(", "window.open", "location.href", "location.assign", "location.replace",
	} {
		if strings.Contains(lower, bad) {
			t.Errorf("the page contains %q", bad)
		}
	}
	inlineBody(t, page, "script")
	inlineBody(t, page, "style")
	if n := strings.Count(page, "fetch("); n != 1 {
		t.Errorf("%d fetch calls, want 1", n)
	}
	if !strings.Contains(page, `let url = "/d/" + encodeURIComponent(SLUG)`) {
		t.Error("the page's request is not the same-origin /d/ listing")
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
	want := "default-src 'none'; connect-src 'self'; script-src " + hash(inlineBody(t, page, "script")) +
		"; style-src " + hash(inlineBody(t, page, "style")) + "; base-uri 'none'; form-action 'none'"
	if got != want {
		t.Errorf("CSP\n got %s\nwant %s", got, want)
	}

	// A meta policy governs only what comes after it.
	if metas[0][0] > strings.Index(page, "<style>") || metas[0][0] > strings.Index(page, "<script>") {
		t.Error("the CSP meta must come before the style and the script")
	}
}
