package envelope

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// Wire layout of go.mau.fi/libsignal v0.2.2 (serialize/ProtoBufferSerializer.go,
// serialize/WhisperTextProtocol.proto):
//
//	SignalMessage       = version byte || protobuf || 8-byte MAC
//	PreKeySignalMessage = version byte || protobuf, its field 4 a SignalMessage
//
// The version byte's high nibble is the message version (3).

const (
	signalVersion = 3
	macLength     = 8  // protocol.MacLength
	keyLength     = 33 // 0x05 || 32-byte Curve25519 point
	djbType       = 0x05
)

// SignalMessage fields.
const (
	smRatchetKey      = 1
	smCounter         = 2
	smPreviousCounter = 3
	smCiphertext      = 4
)

// PreKeySignalMessage fields.
const (
	pkPreKeyID       = 1
	pkBaseKey        = 2
	pkIdentityKey    = 3
	pkMessage        = 4
	pkRegistrationID = 5
	pkSignedPreKeyID = 6
)

// lowOrder lists the Curve25519 u-coordinates (bit 255 cleared) that give an
// all-zero shared secret: 0, 1, the two points of order 8, p-1, p, p+1.
var lowOrder = [][32]byte{
	{},
	{1},
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	ffTail(0xec),
	ffTail(0xed),
	ffTail(0xee),
}

func ffTail(first byte) [32]byte {
	var k [32]byte
	k[0] = first
	for i := 1; i < 31; i++ {
		k[i] = 0xff
	}
	k[31] = 0x7f
	return k
}

// CheckKey requires the serialized public-key form libsignal reads with
// ecc.DecodePoint: exactly 33 bytes, type 0x05, not a low-order point.
func CheckKey(k []byte) error {
	if len(k) != keyLength {
		return fmt.Errorf("%w: key is %d bytes, want %d", ErrMalformed, len(k), keyLength)
	}
	if k[0] != djbType {
		return fmt.Errorf("%w: key type 0x%02x", ErrMalformed, k[0])
	}
	var u [32]byte
	copy(u[:], k[1:])
	u[31] &= 0x7f
	for _, bad := range lowOrder {
		if bytes.Equal(u[:], bad[:]) {
			return fmt.Errorf("%w: low-order key", ErrMalformed)
		}
	}
	return nil
}

// CheckSignalMessage validates a normal Signal message.
func CheckSignalMessage(b []byte) error {
	if len(b) < 1+macLength+1 {
		return fmt.Errorf("%w: signal message is %d bytes", ErrMalformed, len(b))
	}
	if err := checkVersion(b[0]); err != nil {
		return err
	}
	var ratchet, ciphertext bool
	err := scan(b[1:len(b)-macLength], func(num protowire.Number, typ protowire.Type, v []byte, n uint64) error {
		switch num {
		case smRatchetKey:
			if typ != protowire.BytesType || ratchet {
				return fieldErr("ratchetKey")
			}
			ratchet = true
			return CheckKey(v)
		case smCounter, smPreviousCounter:
			return checkUint32(typ, n)
		case smCiphertext:
			if typ != protowire.BytesType || ciphertext || len(v) == 0 {
				return fieldErr("ciphertext")
			}
			ciphertext = true
			return nil
		}
		return fmt.Errorf("%w: unknown field %d", ErrMalformed, num)
	})
	if err != nil {
		return err
	}
	if !ratchet || !ciphertext {
		return fmt.Errorf("%w: signal message lacks ratchetKey or ciphertext", ErrMalformed)
	}
	return nil
}

// CheckPreKeyMessage validates a PreKeySignalMessage and its inner message.
func CheckPreKeyMessage(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("%w: prekey message is %d bytes", ErrMalformed, len(b))
	}
	if err := checkVersion(b[0]); err != nil {
		return err
	}
	seen := map[protowire.Number]bool{}
	err := scan(b[1:], func(num protowire.Number, typ protowire.Type, v []byte, n uint64) error {
		if seen[num] {
			return fmt.Errorf("%w: field %d repeated", ErrMalformed, num)
		}
		seen[num] = true
		switch num {
		case pkPreKeyID, pkRegistrationID, pkSignedPreKeyID:
			return checkUint32(typ, n)
		case pkBaseKey, pkIdentityKey:
			if typ != protowire.BytesType {
				return fieldErr("key")
			}
			return CheckKey(v)
		case pkMessage:
			if typ != protowire.BytesType {
				return fieldErr("message")
			}
			return CheckSignalMessage(v)
		}
		return fmt.Errorf("%w: unknown field %d", ErrMalformed, num)
	})
	if err != nil {
		return err
	}
	for _, f := range []protowire.Number{pkBaseKey, pkIdentityKey, pkMessage} {
		if !seen[f] {
			return fmt.Errorf("%w: prekey message lacks field %d", ErrMalformed, f)
		}
	}
	return nil
}

func checkVersion(b byte) error {
	if b>>4 != signalVersion {
		return fmt.Errorf("%w: message version %d", ErrMalformed, b>>4)
	}
	return nil
}

func checkUint32(typ protowire.Type, n uint64) error {
	if typ != protowire.VarintType || n > 1<<32-1 {
		return fmt.Errorf("%w: field is not a uint32", ErrMalformed)
	}
	return nil
}

func fieldErr(name string) error {
	return fmt.Errorf("%w: bad or repeated %s", ErrMalformed, name)
}

// scan walks a protobuf message; fn gets each field's bytes (bytes type) or
// value (varint type). Any other wire type, or a truncated field, refuses.
func scan(b []byte, fn func(protowire.Number, protowire.Type, []byte, uint64) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(n))
		}
		b = b[n:]
		var v []byte
		var u uint64
		switch typ {
		case protowire.BytesType:
			v, n = protowire.ConsumeBytes(b)
		case protowire.VarintType:
			u, n = protowire.ConsumeVarint(b)
		default:
			return fmt.Errorf("%w: field %d wire type %d", ErrMalformed, num, typ)
		}
		if n < 0 {
			return fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(n))
		}
		b = b[n:]
		if err := fn(num, typ, v, u); err != nil {
			return err
		}
	}
	return nil
}
