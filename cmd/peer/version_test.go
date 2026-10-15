package main

import (
	"runtime/debug"
	"testing"
)

// The version printed is the stamped one when a release build set it, else
// the module version a `go install …@<tag>` build records, else "dev".
func TestVersionFrom(t *testing.T) {
	tagged := &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}}
	devel := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}
	for _, c := range []struct {
		name, stamped string
		bi            *debug.BuildInfo
		ok            bool
		want          string
	}{
		{"stamped wins", "v0.2.0-rc", tagged, true, "v0.2.0-rc"},
		{"go install @tag", "dev", tagged, true, "v0.2.0"},
		{"empty stamp, tag", "", tagged, true, "v0.2.0"},
		{"plain go build", "dev", devel, true, "dev"},
		{"no build info", "dev", nil, false, "dev"},
	} {
		if got := versionFrom(c.stamped, c.bi, c.ok); got != c.want {
			t.Errorf("%s: versionFrom(%q, …) = %q, want %q", c.name, c.stamped, got, c.want)
		}
	}
}
