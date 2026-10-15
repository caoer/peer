package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/caoer/peer/internal/keys"
)

// sealInfo is the HKDF info of the sealing key; a new value is a new key.
const sealInfo = "peer store seal v1"

// SealKey derives the store's sealing key from the identity key — HKDF-SHA256
// over the identity private key — so every fleet host, which holds the
// identity file, opens the same records and nothing else has to be shared.
func SealKey(id *keys.Identity) [32]byte {
	priv := id.KeyPair.PrivateKey().Serialize()
	k, err := hkdf.Key(sha256.New, priv[:], nil, sealInfo, 32)
	if err != nil {
		panic(err) // fixed hash and lengths
	}
	var out [32]byte
	copy(out[:], k)
	return out
}

// Sealed wraps a backend so records leave the process sealed: AES-256-GCM,
// a random nonce before the ciphertext, the record key as associated data
// so a blob cannot be moved under another key. A blob that does not open
// refuses with ErrCorrupt before any libsignal deserialization sees it.
func Sealed(b Backend, key [32]byte) Backend {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // 32-byte key
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &sealed{b: b, aead: aead}
}

type sealed struct {
	b    Backend
	aead cipher.AEAD
}

func (s *sealed) Load(ctx context.Context, key string) ([]byte, int64, error) {
	blob, v, err := s.b.Load(ctx, key)
	if err != nil || blob == nil {
		return nil, v, err
	}
	n := s.aead.NonceSize()
	if len(blob) < n+s.aead.Overhead() {
		return nil, 0, fmt.Errorf("%w: %s: %d bytes", ErrCorrupt, key, len(blob))
	}
	plain, err := s.aead.Open(nil, blob[:n], blob[n:], []byte(key))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %s", ErrCorrupt, key)
	}
	return plain, v, nil
}

func (s *sealed) Store(ctx context.Context, key string, data []byte, expect int64) (int64, error) {
	n := s.aead.NonceSize()
	nonce := make([]byte, n, n+len(data)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	return s.b.Store(ctx, key, s.aead.Seal(nonce, nonce, data, []byte(key)), expect)
}
