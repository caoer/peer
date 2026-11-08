package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "write testdata/vector-v1.json if it does not exist")

var vectorPath = filepath.Join("testdata", "vector-v1.json")

// vector is the committed known-answer test. Its secret is a throwaway.
type vector struct {
	Secret    string `json:"secret"`
	Public    string `json:"public"`
	Plaintext string `json:"plaintext"`
	Envelope  string `json:"envelope"`
}

func writeVector(t *testing.T) {
	t.Helper()
	pub, secret := newKey(t)
	v := vector{Secret: secret, Public: pub, Plaintext: "hello, peer e2e v1 — 你好"}
	env, err := Seal([]byte(v.Plaintext), []string{pub})
	if err != nil {
		t.Fatal(err)
	}
	v.Envelope = string(env)
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(vectorPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("the vector is written once: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
}

func readVector(t *testing.T) vector {
	t.Helper()
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func newKey(t *testing.T) (pub, secret string) {
	t.Helper()
	pub, secret, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, secret
}

func seal(t *testing.T, plain string, pubs ...string) []byte {
	t.Helper()
	env, err := Seal([]byte(plain), pubs)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// mutate decodes env, applies f and re-encodes it.
func mutate(t *testing.T, env []byte, f func(*envelope)) []byte {
	t.Helper()
	var e envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	f(&e)
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// flip changes one byte in the middle of a standard-base64 field.
func flip(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01
	return base64.StdEncoding.EncodeToString(b)
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestVector(t *testing.T) {
	if *update {
		writeVector(t)
	}
	v := readVector(t)
	if suite, ok := Detect([]byte(v.Envelope)); !ok || suite != Suite {
		t.Fatalf("Detect(vector) = %q, %v", suite, ok)
	}
	plain, err := Open([]byte(v.Envelope), v.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != v.Plaintext {
		t.Fatalf("plaintext = %q, want %q", plain, v.Plaintext)
	}
	k, err := ParseSecret(v.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if got := formatPublic(k.PublicKey()); got != v.Public {
		t.Fatalf("public = %s, want %s", got, v.Public)
	}
}

func TestEnvelopeShape(t *testing.T) {
	pub, _ := newKey(t)
	// The plaintext holds a space and a '!', which neither base64 nor the
	// compact JSON around it can contain, so finding it means a leak.
	const plain = "hi, peer!"
	env := seal(t, plain, pub)
	// enc is 32 bytes of base64 and ct 48 bytes, which needs no padding.
	shape := regexp.MustCompile(`^\{"e2e":1,"suite":"peer-e2e-v1","to":\[\{"key":"x25519:[A-Za-z0-9_-]{43}","enc":"[A-Za-z0-9+/]{43}=","ct":"[A-Za-z0-9+/]{64}"\}\],"body":"[A-Za-z0-9+/=]+"\}$`)
	if !shape.Match(env) {
		t.Fatalf("envelope shape: %s", env)
	}
	if bytes.Contains(env, []byte(plain)) {
		t.Fatalf("plaintext in envelope: %s", env)
	}
}

func TestSealOpenPlaintexts(t *testing.T) {
	pub, secret := newKey(t)
	for _, plain := range []string{"", "x", strings.Repeat("长消息", 20000)} {
		got, err := Open(seal(t, plain, pub), secret)
		if err != nil {
			t.Fatalf("len %d: %v", len(plain), err)
		}
		if string(got) != plain {
			t.Fatalf("len %d: round trip differs", len(plain))
		}
	}
}

func TestSealFreshKeyEachMessage(t *testing.T) {
	pub, _ := newKey(t)
	var first, second envelope
	if err := json.Unmarshal(seal(t, "same", pub), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(seal(t, "same", pub), &second); err != nil {
		t.Fatal(err)
	}
	if first.Body == second.Body || first.To[0].Enc == second.To[0].Enc {
		t.Fatal("two seals of one plaintext share a body or an enc")
	}
}

func TestSealRefuses(t *testing.T) {
	if _, err := Seal([]byte("x"), nil); err == nil {
		t.Fatal("Seal with no keys succeeded")
	}
	pub, _ := newKey(t)
	if _, err := Seal([]byte("x"), []string{pub, "x25519:short"}); err == nil {
		t.Fatal("Seal with a bad key succeeded")
	}
}

func TestOpenWrongSecret(t *testing.T) {
	pub, _ := newKey(t)
	_, other := newKey(t)
	_, err := Open(seal(t, "x", pub), other)
	wantErr(t, err, ErrNotRecipient)
}

func TestOpenStanzaRelabelledToWrongKey(t *testing.T) {
	pub, _ := newKey(t)
	otherPub, otherSecret := newKey(t)
	env := mutate(t, seal(t, "x", pub), func(e *envelope) { e.To[0].Key = otherPub })
	_, err := Open(env, otherSecret)
	wantErr(t, err, ErrDecrypt)
}

func TestOpenTampered(t *testing.T) {
	pub, secret := newKey(t)
	env := seal(t, "secret message", pub)
	for name, f := range map[string]func(*envelope){
		"enc":  func(e *envelope) { e.To[0].Enc = flip(t, e.To[0].Enc) },
		"ct":   func(e *envelope) { e.To[0].CT = flip(t, e.To[0].CT) },
		"body": func(e *envelope) { e.Body = flip(t, e.Body) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Open(mutate(t, env, f), secret)
			wantErr(t, err, ErrDecrypt)
		})
	}
}

func TestOpenChangedSuite(t *testing.T) {
	pub, secret := newKey(t)
	env := mutate(t, seal(t, "x", pub), func(e *envelope) { e.Suite = "peer-e2e-v2" })
	if suite, ok := Detect(env); !ok || suite != "peer-e2e-v2" {
		t.Fatalf("Detect = %q, %v", suite, ok)
	}
	_, err := Open(env, secret)
	wantErr(t, err, ErrMalformed)
}

func TestOpenMalformed(t *testing.T) {
	pub, secret := newKey(t)
	env := seal(t, "x", pub)
	for name, in := range map[string][]byte{
		"plain text": []byte("hello"),
		"truncated":  env[:len(env)-1],
		"short enc":  mutate(t, env, func(e *envelope) { e.To[0].Enc = "AAAA" }),
		"short ct":   mutate(t, env, func(e *envelope) { e.To[0].CT = "AAAA" }),
		"enc base64": mutate(t, env, func(e *envelope) { e.To[0].Enc = "!" + e.To[0].Enc[1:] }),
		"body b64":   mutate(t, env, func(e *envelope) { e.Body = "!" }),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Open(in, secret)
			wantErr(t, err, ErrMalformed)
		})
	}
}

func TestTwoKeys(t *testing.T) {
	pubA, secretA := newKey(t)
	pubB, secretB := newKey(t)
	_, secretC := newKey(t)
	env := seal(t, "to both", pubA, pubB)
	for _, secret := range []string{secretA, secretB} {
		got, err := Open(env, secret)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "to both" {
			t.Fatalf("plaintext = %q", got)
		}
	}
	_, err := Open(env, secretC)
	wantErr(t, err, ErrNotRecipient)
}

func TestDetect(t *testing.T) {
	const tail = `,"suite":"peer-e2e-v1","to":[],"body":""}`
	accept := map[string]string{
		"exact":             `{"e2e":1` + tail,
		"leading ws":        " \t\r\n" + `{"e2e":1` + tail,
		"other valid suite": `{"e2e":1,"suite":"a.B_c-9"}`,
	}
	for name, in := range accept {
		t.Run("accept "+name, func(t *testing.T) {
			if _, ok := Detect([]byte(in)); !ok {
				t.Fatalf("Detect(%s) = false", in)
			}
		})
	}
	reject := map[string]string{
		"plain":           "hello",
		"empty":           "",
		"e2e 2":           `{"e2e":2` + tail,
		"e2e string":      `{"e2e":"1"` + tail,
		"e2e null":        `{"e2e":null` + tail,
		"array":           `[{"e2e":1}]`,
		"number":          `1`,
		"other first key": `{"suite":"peer-e2e-v1","e2e":1}`,
		"space in prefix": `{ "e2e":1` + tail,
		"no suite":        `{"e2e":1}`,
		"null suite":      `{"e2e":1,"suite":null}`,
		"uppercase suite": `{"e2e":1,"SUITE":"peer-e2e-v1"}`,
		"numeric suite":   `{"e2e":1,"suite":7}`,
		"empty suite":     `{"e2e":1,"suite":""}`,
		"bad char suite":  `{"e2e":1,"suite":"a b"}`,
		"long suite":      `{"e2e":1,"suite":"` + strings.Repeat("a", 65) + `"}`,
		"newline suite":   `{"e2e":1,"suite":"a\n"}`,
		"bad json":        `{"e2e":1,`,
		"trailing data":   `{"e2e":1,"suite":"a"} x`,
	}
	for name, in := range reject {
		t.Run("reject "+name, func(t *testing.T) {
			if suite, ok := Detect([]byte(in)); ok {
				t.Fatalf("Detect(%s) = %q, true", in, suite)
			}
		})
	}
}

func TestKeyStrings(t *testing.T) {
	pub, secret := newKey(t)
	if len(strings.TrimPrefix(pub, PublicPrefix)) != 43 || len(strings.TrimPrefix(secret, SecretPrefix)) != 43 {
		t.Fatalf("key lengths: %s", pub)
	}
	if _, err := ParsePublic(pub); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSecret(secret); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublic(secret); err == nil {
		t.Fatal("ParsePublic took a secret")
	}
	body := strings.TrimPrefix(pub, PublicPrefix)
	for _, bad := range []string{
		"", "x25519:", body, "ed25519:" + body,
		PublicPrefix + body + "A",
		PublicPrefix + body[:42],
		PublicPrefix + body + "=",
		PublicPrefix + "+" + body[1:],
		PublicPrefix + strings.Repeat("A", 42) + "B", // non-canonical trailing bits
	} {
		if _, err := ParsePublic(bad); err == nil {
			t.Errorf("ParsePublic(%q) succeeded", bad)
		}
	}
	const leak = "not-a-valid-secret"
	if _, err := ParseSecret(SecretPrefix + leak); err == nil || strings.Contains(err.Error(), leak) {
		t.Fatalf("ParseSecret error = %v", err)
	}
}

func TestParseDetails(t *testing.T) {
	pub, _ := newKey(t)
	ok := `{"v":1,"suite":"peer-e2e-v1","keys":["` + pub + `"]}`
	for name, in := range map[string]string{"none": "", "no member": `{"model":"x"}`} {
		t.Run(name, func(t *testing.T) {
			d, err := ParseDetails(json.RawMessage(in))
			if d != nil || err != nil {
				t.Fatalf("ParseDetails = %v, %v", d, err)
			}
		})
	}
	d, err := ParseDetails(json.RawMessage(`{"model":"x","e2e":` + ok + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.V != 1 || d.Suite != Suite || len(d.Keys) != 1 || d.Keys[0] != pub {
		t.Fatalf("details = %+v", d)
	}
	for name, in := range map[string]string{
		"not json":   `{`,
		"not object": `{"e2e":[]}`,
		"version":    `{"e2e":{"v":2,"suite":"peer-e2e-v1","keys":["` + pub + `"]}}`,
		"suite":      `{"e2e":{"v":1,"suite":"other","keys":["` + pub + `"]}}`,
		"no keys":    `{"e2e":{"v":1,"suite":"peer-e2e-v1","keys":[]}}`,
		"bad key":    `{"e2e":{"v":1,"suite":"peer-e2e-v1","keys":["x25519:short"]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if d, err := ParseDetails(json.RawMessage(in)); err == nil {
				t.Fatalf("ParseDetails = %+v, want error", d)
			}
		})
	}
}
