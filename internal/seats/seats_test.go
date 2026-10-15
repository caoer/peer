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

// The rooms column: names, ids and *, spaces between; empty or absent is
// none; InRoom picks the rows naming a room in the map's order.
func TestParseRooms(t *testing.T) {
	id := strings.Repeat("0f", 16)
	m, err := Parse([]byte("| label | to | accepts | rooms |\n|---|---|---|---|\n" +
		"| leader | [[" + sess + "/rosters/leader-peer-v1]] | text task | ops " + id + " ops |\n" +
		"| cli | [[" + sess + "/rosters/worker-cli]] | text | * |\n" +
		"| zt | human [[" + sess + "/rosters/advisor-demo]] | text | |\n" +
		"| hook | service https://example.net/peer/hook | text | |\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := m.Row("leader"); !reflect.DeepEqual(r.Rooms, []string{"ops", id}) {
		t.Fatalf("leader's rooms: %v", r.Rooms)
	}
	if r, _ := m.Row("zt"); r.Rooms != nil {
		t.Fatalf("an empty rooms cell: %v", r.Rooms)
	}
	labels := func(rows []Row) (out []string) {
		for _, r := range rows {
			out = append(out, r.Label)
		}
		return out
	}
	for _, c := range []struct {
		name, id string
		want     []string
	}{
		{"ops", "", []string{"leader", "cli"}},
		{"0f0f0f0f", id, []string{"leader", "cli"}},
		{"chat", strings.Repeat("1", 32), []string{"cli"}},
	} {
		if got := labels(m.InRoom(c.name, c.id)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("InRoom(%q, %q) = %v, want %v", c.name, c.id, got, c.want)
		}
	}
	// A map without the column is a map where no row takes a room.
	m, err = Parse([]byte("| label | to | accepts |\n|---|---|---|\n| cli | [[" + sess + "/rosters/worker-cli]] | text |\n"))
	if err != nil || m.InRoom("ops", id) != nil {
		t.Fatalf("no rooms column: %v, %v", err, m.InRoom("ops", id))
	}
	for _, c := range []struct{ name, text, reason string }{
		{"bad room", "| label | to | accepts | rooms |\n|---|---|---|---|\n| cli | [[" + sess + "/rosters/worker-cli]] | text | ops/x |\n", `room "ops/x" is not a room name`},
		{"service room", "| label | to | accepts | rooms |\n|---|---|---|---|\n| hook | service https://example.net/peer/hook | text | * |\n", "a service row takes no rooms"},
	} {
		if _, err := Parse([]byte(c.text)); !errors.Is(err, ErrMap) || !strings.Contains(err.Error(), c.reason) {
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
