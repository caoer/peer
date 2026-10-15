// Package timeline is a channel's decrypted message timeline on its private
// collaboration page (design §8 协作页, the generic part): one plaintext
// record per message, received or sent, that the page lists by time.
//
// A record names the message and nothing about the party's machinery: no
// host, login, cursor or local id (design §3.6). Its key is fixed by the
// message's place on the relay — the channel, the direction and the relay
// seq of that direction — so a message has one key wherever and however
// often it is written, and the write is create-only: a key already there is
// the same message, written before, and is left as it is.
package timeline

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/caoer/peer/internal/attach"
	"github.com/caoer/peer/internal/session"
)

// Schema is the K7 schema id of a timeline record.
const Schema = "peer-timeline@1"

// The two directions: a message this party received, one it sent.
const (
	In  = "in"
	Out = "out"
)

// Key is a message's record key: "tl.<channel>.<dir>.<seq>", the seq
// zero-padded to 8 so the keys of a direction list in seq order.
func Key(channel, dir string, seq int64) string {
	return fmt.Sprintf("tl.%s.%s.%08d", channel, dir, seq)
}

// Prefix is the key prefix of one channel's records, both directions.
func Prefix(channel string) string { return "tl." + channel + "." }

// Record is one message on the timeline, in this field order.
type Record struct {
	ID   string    `json:"id"`
	Dir  string    `json:"dir"`
	Kind string    `json:"kind"`
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
	// Body is the text for every kind but doc, file and card; the
	// attachment's descriptor without its key and blob for doc and file;
	// {"event":"card"} for a card.
	Body json.RawMessage `json:"body"`
}

// File is a doc or file message's body on the timeline: what the descriptor
// says about the content, never the key that opens it or where its blob is.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mime   string `json:"mime,omitempty"`
}

// Of is the record of message m in direction dir.
func Of(dir string, m *session.Message) (*Record, error) {
	var body any
	switch m.Kind {
	case session.KindCard:
		body = map[string]string{"event": "card"}
	case session.KindDoc, session.KindFile:
		d, err := attach.Parse(m.Body)
		if err != nil {
			body = map[string]string{"error": err.Error()}
			break
		}
		body = File{Name: d.Name, Size: d.Size, SHA256: d.SHA256, Mime: d.Mime}
	default:
		body = string(m.Body)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &Record{ID: m.ID, Dir: dir, Kind: m.Kind, From: m.From, To: m.To, At: m.At.UTC(), Body: b}, nil
}
