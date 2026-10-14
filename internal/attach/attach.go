// Package attach is the content of a doc or file message (design §3.5,
// §5.2): the file is sealed under a fresh one-time key, the ciphertext goes
// to the channel's blob route, and the message — inside the Double Ratchet
// envelope — carries a Descriptor naming the blob and holding that key. The
// relay sees the ciphertext's size and nothing else.
//
// The cipher is AES-256-GCM from the Go standard library. Each key seals
// exactly one file, once, so the nonce is fixed at zero: GCM's one rule is a
// (key, nonce) pair never sealing twice, and a key that is never reused
// keeps it. The file is sealed whole, not chunked; the relay's 64 MiB cap
// bounds what a host holds in memory.
package attach

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/caoer/peer/internal/relay"
)

const (
	// KeySize is the one-time key's length (AES-256).
	KeySize = 32
	// Overhead is what sealing adds: the GCM tag.
	Overhead = 16
	// MaxSize is the largest file: the relay's blob cap less the tag.
	MaxSize = relay.MaxBlob - Overhead
	// maxName bounds a file name in bytes, a common file system's limit.
	maxName = 255
)

// Descriptor is a doc or file message's body. Key is the one-time key
// (standard base64 in JSON); Size and SHA256 are the plaintext's, checked
// after unwrapping.
type Descriptor struct {
	Blob   string `json:"blob"`
	Key    []byte `json:"key"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mime   string `json:"mime,omitempty"`
}

// Errors a receiver reports on its quarantine record.
var (
	ErrDescriptor = errors.New("attach: descriptor")
	ErrOpen       = errors.New("attach: the blob does not open under the message's key")
	ErrMismatch   = errors.New("attach: the unwrapped file does not match the message's size and sha256")
)

// Seal encrypts plain under a fresh key and returns the ciphertext and the
// descriptor to send, its Blob left for the caller to fill from the put.
func Seal(name string, plain []byte) ([]byte, Descriptor, error) {
	if !ValidName(name) {
		return nil, Descriptor{}, fmt.Errorf("%w: name %q is not a file name", ErrDescriptor, name)
	}
	if len(plain) > MaxSize {
		return nil, Descriptor{}, fmt.Errorf("attach: %s is %d bytes, at most %d go as an attachment", name, len(plain), MaxSize)
	}
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, Descriptor{}, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, Descriptor{}, err
	}
	sum := sha256.Sum256(plain)
	ct := aead.Seal(nil, make([]byte, aead.NonceSize()), plain, nil)
	return ct, Descriptor{Key: key, Name: name, Size: int64(len(plain)), SHA256: hex.EncodeToString(sum[:])}, nil
}

// Open unwraps ct under d's key and checks it against d's size and sha256.
// Nothing of a file that fails either check is returned.
func Open(d Descriptor, ct []byte) ([]byte, error) {
	if err := d.Check(); err != nil {
		return nil, err
	}
	if int64(len(ct)) != d.Size+Overhead {
		return nil, fmt.Errorf("%w: the blob is %d bytes, a %d-byte file seals to %d", ErrOpen, len(ct), d.Size, d.Size+Overhead)
	}
	aead, err := newAEAD(d.Key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), ct, nil)
	if err != nil {
		return nil, ErrOpen
	}
	sum := sha256.Sum256(plain)
	if int64(len(plain)) != d.Size || hex.EncodeToString(sum[:]) != d.SHA256 {
		return nil, ErrMismatch
	}
	return plain, nil
}

// Marshal is the message body for d.
func (d Descriptor) Marshal() ([]byte, error) {
	if err := d.Check(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// Parse reads a descriptor from the start of body; anything after the JSON
// value — the status line a quarantine record adds — is ignored.
func Parse(body []byte) (Descriptor, error) {
	var d Descriptor
	// An unknown field is ignored, the card's rule for what is not marked critical.
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&d); err != nil {
		return Descriptor{}, fmt.Errorf("%w: %v", ErrDescriptor, err)
	}
	return d, d.Check()
}

// Check is the descriptor's shape: a blob id, a key, a file name, a size in
// range and a sha256.
func (d Descriptor) Check() error {
	switch {
	case !relay.ValidBlobID(d.Blob):
		return fmt.Errorf("%w: blob %q is not a blob id", ErrDescriptor, d.Blob)
	case len(d.Key) != KeySize:
		return fmt.Errorf("%w: key is %d bytes, want %d", ErrDescriptor, len(d.Key), KeySize)
	case !ValidName(d.Name):
		return fmt.Errorf("%w: name %q is not a file name", ErrDescriptor, d.Name)
	case d.Size < 0 || d.Size > MaxSize:
		return fmt.Errorf("%w: size %d out of 0..%d", ErrDescriptor, d.Size, MaxSize)
	case len(d.SHA256) != 64 || strings.ToLower(d.SHA256) != d.SHA256:
		return fmt.Errorf("%w: sha256 %q is not 64 lowercase hex", ErrDescriptor, d.SHA256)
	}
	if _, err := hex.DecodeString(d.SHA256); err != nil {
		return fmt.Errorf("%w: sha256: %v", ErrDescriptor, err)
	}
	return nil
}

// ValidName reports whether name can be a file's name in one directory: no
// path, not . or .., no control character, valid UTF-8, at most 255 bytes.
func ValidName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > maxName || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r == '/' || r == '\\' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
