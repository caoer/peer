// records.mjs — the store decrypt-driver.mjs serves at /d/<slug>, built from
// the committed test vector. Everything here is a throwaway: the vector's key
// is published in docs/protocol.md and `other` is made fresh on each run.
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

export const vector = JSON.parse(
  readFileSync(new URL("../../../../internal/e2e/testdata/vector-v1.json", import.meta.url), "utf8"),
);

const pair = generateKeyPairSync("x25519");
export const other = {
  public: "x25519:" + pair.publicKey.export({ format: "jwk" }).x,
  secret: "x25519-secret:" + pair.privateKey.export({ format: "jwk" }).d,
};

const real = JSON.parse(vector.envelope);
const stanza = real.to[0];
const flip = (b64) => {
  const b = Buffer.from(b64, "base64");
  b[0] ^= 1;
  return b.toString("base64");
};

// Fixed key order, as the wire has it.
const envelope = (fields) => JSON.stringify({ e2e: 1, suite: real.suite, to: real.to, body: real.body, ...fields });

const bodies = {
  "plain": "a plain message, not encrypted",
  "vector": vector.envelope,
  "two-keys": envelope({ to: [{ ...stanza, key: other.public }, stanza] }),
  "indented": "  \n" + vector.envelope,
  "tampered": envelope({ body: flip(real.body) }),
  "bad-enc": envelope({ to: [{ ...stanza, enc: "AAAA" }] }),
  "other-key": envelope({ to: [{ ...stanza, key: other.public }] }),
  "other-suite": envelope({ suite: "peer-e2e-v9" }),
  "no-stanzas": envelope({ to: [] }),
  "e2e-two": '{"e2e":2,"suite":"peer-e2e-v1"}',
};

const encrypted = new Set(["vector", "two-keys", "indented", "tampered", "bad-enc", "other-key", "other-suite", "no-stanzas"]);

export const records = Object.entries(bodies).map(([id, body], i) => ({
  id,
  dir: i % 2 ? "out" : "in",
  kind: "text",
  from: "fp-from",
  to: "fp-to",
  at: `2026-11-08T12:00:${String(i).padStart(2, "0")}Z`,
  body,
  ...(encrypted.has(id) ? { e2e: true } : {}),
}));

// The shape the page store answers `?prefix=tl.&values=1` with.
export const listing = () => ({
  ok: true,
  keys: records.map((data, i) => ({
    key: `tl.chan.${data.dir}.${String(i + 1).padStart(8, "0")}`,
    value: { schema: "peer-timeline@1", data },
    version: 1,
  })),
  cursor: null,
});
