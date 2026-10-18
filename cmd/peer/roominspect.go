package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/caoer/peer/internal/relay"
	"github.com/caoer/peer/internal/sealed"
)

// A record body up to inspectWhole bytes prints whole; a larger one prints
// its first inspectHead bytes (the header and the first stanzas) and its
// sha256.
const (
	inspectWhole = 4096
	inspectHead  = 512
)

// roomInspect is what peer room inspect prints: the relay's view of a room
// through this party's token. room, you and log are the relay's state
// answer as it is; members is the relay's member list, null when the token
// is not admin; each record is the relay's row with what its framing shows.
type roomInspect struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Relay   string          `json:"relay"`
	Room    relay.RoomInfo  `json:"room"`
	You     relay.RoomSeat  `json:"you"`
	Log     relay.RoomLog   `json:"log"`
	Members []relay.Member  `json:"members"`
	Records []inspectRecord `json:"records"`
	// Notes names what the relay did not show this token, and why.
	Notes []string `json:"notes,omitempty"`
}

// inspectRecord is one record the relay holds: seq, the writer's idx, the
// put time and the time retention drops it (relay epoch milliseconds), the
// decoded size and sha256, the body (standard base64) whole or its head,
// and sealed, the record's cleartext framing. Error replaces what a
// malformed row lacks.
type inspectRecord struct {
	Seq     int64          `json:"seq"`
	Idx     int            `json:"idx"`
	Type    string         `json:"type,omitempty"`
	At      int64          `json:"at,omitempty"`
	Expires int64          `json:"expires,omitempty"`
	Size    int            `json:"size,omitempty"`
	SHA256  string         `json:"sha256,omitempty"`
	Body    string         `json:"body,omitempty"`
	Head    string         `json:"head,omitempty"`
	Sealed  *inspectSealed `json:"sealed,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// inspectSealed is the part of a sealed record anyone holding it reads: the
// signed header — the writer's idx and counter, the key commitment, the
// writer's time — and the idxs it is sealed to, in wire order (65535 is a
// feed's link). Nothing here is verified.
type inspectSealed struct {
	Idx uint16   `json:"idx"`
	Ctr uint64   `json:"ctr"`
	KH  string   `json:"kh"`
	At  string   `json:"at"`
	To  []uint16 `json:"to"`
}

func cmdRoomInspect(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("room inspect", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dirFlag := fl.String("dir", "", "peer directory (default $PEER_HOME, else <config dir>/peer)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || fl.Arg(0) == "" {
		fmt.Fprintln(stderr, "usage: peer room inspect [--dir D] <room>")
		return 2
	}
	if err := runRoomInspect(context.Background(), *dirFlag, fl.Arg(0), stdout); err != nil {
		fmt.Fprintf(stderr, "peer room inspect: %v\n", err)
		return 1
	}
	return 0
}

// runRoomInspect prints the relay's view of room name as JSON: its state
// route read to the end with this party's token, and the member list when
// the token is admin. It reads; it changes nothing here or on the relay.
func runRoomInspect(ctx context.Context, dir, name string, out io.Writer) error {
	dir, err := peerDir(dir)
	if err != nil {
		return err
	}
	p, err := openParty(dir)
	if err != nil {
		return err
	}
	l, err := loadRooms(ctx, p.backend)
	if err != nil {
		return err
	}
	ref := l.byName(name)
	if ref == nil {
		return fmt.Errorf("no room named %s", name)
	}
	if ref.Token == "" {
		return fmt.Errorf("room %s (%s): %s, and this party holds no token for it", ref.Name, ref.ID, ref.Stage)
	}
	rc := relay.New(ref.Relay, nil)
	st, err := rc.RoomStateAll(ctx, ref.ID, ref.Token)
	if errors.Is(err, relay.ErrNoSuchRoute) {
		return fmt.Errorf("the relay at %s has no room state route: it predates it", ref.Relay)
	}
	if err != nil {
		return err
	}
	v := roomInspect{ID: ref.ID, Name: ref.Name, Relay: ref.Relay, Room: st.Room, You: st.You, Log: st.Log, Records: []inspectRecord{}}
	if st.You.Admin {
		ms, err := rc.ListMembers(ctx, ref.ID, ref.Token)
		if err != nil {
			return fmt.Errorf("members: %w", err)
		}
		v.Members = ms.Members
	} else {
		v.Notes = append(v.Notes, "members: the relay lists them to an admin token, and this one is not")
	}
	if st.You.From > 0 {
		v.Notes = append(v.Notes, fmt.Sprintf("records below #%d: none is served to this seat, which joined at #%d", st.You.From, st.You.From))
	}
	for _, r := range st.Records {
		v.Records = append(v.Records, inspectRow(r, st.Room.Retention))
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func inspectRow(r relay.RoomRecord, retention int64) inspectRecord {
	row := inspectRecord{Seq: r.Seq, Idx: r.Idx}
	if r.Err != nil {
		if !r.At.IsZero() {
			row.At = r.At.UnixMilli()
		}
		row.Error = r.Err.Error()
		return row
	}
	sum := sha256.Sum256(r.Body)
	row.Type = "sealed"
	row.At = r.At.UnixMilli()
	row.Expires = row.At + retention
	row.Size = len(r.Body)
	row.SHA256 = hex.EncodeToString(sum[:])
	if len(r.Body) <= inspectWhole {
		row.Body = base64.StdEncoding.EncodeToString(r.Body)
	} else {
		row.Head = base64.StdEncoding.EncodeToString(r.Body[:inspectHead])
	}
	rec, err := sealed.Parse(r.Body)
	if err != nil {
		row.Error = err.Error()
		return row
	}
	h := rec.Header
	row.Sealed = &inspectSealed{
		Idx: h.Idx,
		Ctr: h.Ctr,
		KH:  base64.StdEncoding.EncodeToString(h.KH[:]),
		At:  h.At.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		To:  rec.Recipients(),
	}
	return row
}
