package relay_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caoer/peer/internal/relay"
)

// A state answer is taken only whole: a counter left out, a bad seat, or a
// record outside the caller's view [from, next) is ErrAnswer, never a zero.
func TestRoomStateHostileRelay(t *testing.T) {
	ctx := context.Background()
	tok := strings.Repeat("A", 43)
	id := strings.Repeat("0", 32)
	serve := func(body string) *relay.Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return relay.New(srv.URL+"/peer", srv.Client())
	}
	good := base64.StdEncoding.EncodeToString(sealed(1))
	row := func(seq string) string {
		return `{"seq":` + seq + `,"idx":1,"type":"sealed","body":"` + good + `","at":5}`
	}
	answer := func(room, you, log, records string) string {
		return `{"room":` + room + `,"you":` + you + `,"log":` + log + `,"records":[` + records + `]}`
	}
	room := `{"created":1,"add":"admins","membership":3,"next":5,"retention":10,"alarm":null}`
	you := `{"idx":1,"role":"write","from":2,"admin":false,"sockets":0}`
	log := `{"count":3,"first":2,"oldest":5}`

	st, err := serve(answer(room, you, log, row("2")+","+row("4"))).RoomState(ctx, id, tok, -1)
	if err != nil || st.Room.Next != 5 || st.Room.Retention != 10 || st.Room.Alarm != nil || st.You.From != 2 ||
		st.Log.Count != 3 || *st.Log.First != 2 || len(st.Records) != 2 || st.Records[1].Seq != 4 {
		t.Fatalf("a whole answer: %+v %v", st, err)
	}

	for name, body := range map[string]string{
		"no log":         `{"room":` + room + `,"you":` + you + `,"records":[]}`,
		"no membership":  answer(strings.Replace(room, `"membership":3,`, ``, 1), you, log, ``),
		"no next":        answer(strings.Replace(room, `"next":5,`, ``, 1), you, log, ``),
		"no created":     answer(strings.Replace(room, `"created":1,`, ``, 1), you, log, ``),
		"no retention":   answer(strings.Replace(room, `"retention":10,`, ``, 1), you, log, ``),
		"zero retention": answer(strings.Replace(room, `"retention":10`, `"retention":0`, 1), you, log, ``),
		"bad add":        answer(strings.Replace(room, `"admins"`, `"all"`, 1), you, log, ``),
		"no from":        answer(room, strings.Replace(you, `"from":2,`, ``, 1), log, ``),
		"no idx":         answer(room, strings.Replace(you, `"idx":1,`, ``, 1), log, ``),
		"no sockets":     answer(room, strings.Replace(you, `,"sockets":0`, ``, 1), log, ``),
		"bad role":       answer(room, strings.Replace(you, `"write"`, `"admin"`, 1), log, ``),
		"no count":       answer(room, you, `{"first":2,"oldest":5}`, ``),
		"no records":     `{"room":` + room + `,"you":` + you + `,"log":` + log + `}`,
		"below from":     answer(room, you, log, row("1")),
		"at next":        answer(room, you, log, row("5")),
		"not ascending":  answer(room, you, log, row("3")+","+row("2")),
		"not json":       `<html>`,
	} {
		if _, err := serve(body).RoomState(ctx, id, tok, -1); !errors.Is(err, relay.ErrAnswer) {
			t.Errorf("%s: %v, want ErrAnswer", name, err)
		}
	}
}
