package seats

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/card"
)

const sess = "projects/demo"

// The fixture is the first real map: two seats in the protocol session, the
// human, born in the session of the advisor position that relays to him, and
// a service.
func TestParse(t *testing.T) {
	b, err := os.ReadFile("testdata/seats.md")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != 4 {
		t.Fatalf("%d rows, want 4", m.Len())
	}
	seat := []string{"text", "task", "question", "answer", "ack"}
	for _, want := range []Row{
		{Label: "leader", Kind: Seat, Session: sess, Seat: sess + "/rosters/leader-peer-v1", Accepts: seat},
		{Label: "cli", Kind: Seat, Session: sess, Seat: sess + "/rosters/worker-cli", Accepts: seat},
		{Label: "zt", Kind: Human, Session: sess, Seat: sess + "/rosters/advisor-demo", Accepts: []string{"text", "question", "answer"}},
		{Label: "hook", Kind: Service, URL: "https://example.net/peer/hook", Accepts: []string{"text"}},
	} {
		got, ok := m.Row(want.Label)
		if !ok {
			t.Errorf("%s: no row", want.Label)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", want.Label, got, want)
		}
	}
	if _, ok := m.Row("nobody"); ok {
		t.Error("nobody has a row")
	}
	agents := []card.Agent{
		{ID: "leader", Accepts: seat}, {ID: "cli", Accepts: seat},
		{ID: "zt", Accepts: []string{"text", "question", "answer"}}, {ID: "hook", Accepts: []string{"text"}},
	}
	if got := m.Agents(); !reflect.DeepEqual(got, agents) {
		t.Errorf("agents:\n got %+v\nwant %+v", got, agents)
	}
}

// Columns in another order, an extra column, no frontmatter, a repeated
// kind: still the map.
func TestParseShape(t *testing.T) {
	m, err := Parse([]byte("# Seats\n\nsome prose\n\n| note | accepts | to | label |\n|:--|---|---:|---|\n| the leader | text text ack | [[" + sess + "/rosters/leader-peer-v1]] | leader |\n\nafter the table\n| not | a | row |\n"))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := m.Row("leader")
	if !ok || m.Len() != 1 || r.Kind != Seat || r.Session != sess || !reflect.DeepEqual(r.Accepts, []string{"text", "ack"}) {
		t.Fatalf("%+v (%d rows)", r, m.Len())
	}
}

func TestParseRefuses(t *testing.T) {
	row := func(label, to, accepts string) string {
		return "| label | to | accepts |\n|---|---|---|\n| " + label + " | " + to + " | " + accepts + " |\n"
	}
	seat := "[[" + sess + "/rosters/leader-peer-v1]]"
	for _, c := range []struct{ name, text, reason string }{
		{"no table", "# Seats\n\nnothing here\n", "no table"},
		{"no separator", "| label | to | accepts |\n| leader | " + seat + " | text |\n", "separator"},
		{"missing column", "| label | to |\n|---|---|\n| leader | " + seat + " |\n", "no accepts column"},
		{"bad label", row("the leader", seat, "text"), `label "the leader" is not an agent id`},
		{"duplicate", row("leader", seat, "text") + "| leader | " + seat + " | text |\n", `label "leader" appears twice`},
		// A human row names the seat that relays to the person.
		{"bare human", row("zt", "human", "text"), "none of"},
		{"human not a seat", row("zt", "human [["+sess+"/advisor]]", "text"), "is not a seat"},
		{"to none", row("leader", "leader-peer-v1", "text"), "none of"},
		{"bad service", row("hook", "service ftp://x/y", "text"), "not an https URL"},
		{"http service", row("hook", "service http://example.net/hook", "text"), "not an https URL"},
		{"service no host", row("hook", "service https:///y", "text"), "not an https URL"},
		{"seat without rosters", row("leader", "[["+sess+"/leader-peer-v1]]", "text"), "is not a seat"},
		{"seat escaping", row("leader", "[[../"+sess+"/rosters/leader-peer-v1]]", "text"), "is not a seat"},
		// A pipe splits the cell — an alias has no place in a table.
		{"seat with alias", row("leader", "[["+sess+"/rosters/leader-peer-v1|leader]]", "text"), "none of"},
		{"unknown kind", row("leader", seat, "text memo"), `accepts "memo", not one of`},
		{"vendor kind", row("leader", seat, "vnd.x.y"), `accepts "vnd.x.y", not one of`},
		{"accepts nothing", row("leader", seat, ""), "accepts nothing"},
	} {
		_, err := Parse([]byte(c.text))
		if !errors.Is(err, ErrMap) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: %v, want ErrMap naming %q", c.name, err, c.reason)
		}
	}
}

func TestLoad(t *testing.T) {
	if _, err := Load("testdata/absent.md"); err == nil || !strings.Contains(err.Error(), "seat map testdata/absent.md") {
		t.Errorf("absent map: %v", err)
	}
	if m, err := Load("testdata/seats.md"); err != nil || m.Len() != 4 {
		t.Errorf("fixture: %v, %d rows", err, m.Len())
	}
}
