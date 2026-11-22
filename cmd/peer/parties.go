package main

import (
	"bufio"
	"os"
	"strings"
)

// peers/parties.md — the sender binding (contracts formats/v3 § parties): a
// sending party → the position its records belong to. peer-wake reads it to
// tell that position's holder a record arrived; the border's unlabeled notice
// (ucc.go) reads the same rows to know which session a notice is born in.
//
// The file is UCC's, not this code's: a row that does not parse is skipped,
// never fatal — a refusal here would stop every delivery over a map serve
// does not own. Grammar: | <party id> | [[<session>/rosters/<role-slug>]] |.
const partiesFile = "peers/parties.md"

// partySeat is the session directory, under the sessions root, of the
// position a party is bound to; ok false when the file is absent, unreadable,
// or binds the party to no position.
func partySeat(path, party string) (dir string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 2 || strings.TrimSpace(cells[0]) != party {
			continue
		}
		link := strings.TrimSpace(cells[1])
		link = strings.TrimPrefix(link, "[[")
		link = strings.TrimSuffix(link, "]]")
		if i := strings.Index(link, "/rosters/"); i > 0 {
			return strings.TrimSpace(link[:i]), true
		}
	}
	return "", false
}
