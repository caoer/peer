// records.mjs — the records decrypt-driver.mjs's fake feed replays and sends
// live, built from the committed test vector. Everything here is a throwaway:
// the vector's key is published in docs/protocol.md and `other` is made fresh
// on each run.
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

const record = (id, i, fields) => ({
  id,
  dir: i % 2 ? "out" : "in",
  kind: "text",
  from: "fp-from",
  to: "fp-to",
  at: `2026-11-08T12:00:${String(i).padStart(2, "0")}Z`,
  ...fields,
});

// The peer-timeline@1 data the party's one source replays to a viewer.
export const records = Object.entries(bodies).map(([id, body], i) =>
  record(id, i, { body, ...(encrypted.has(id) ? { e2e: true } : {}) }));

// Two records a source sends while the page is open: a plain one, and one
// whose body the Object cut at 60,000 bytes.
export const live = record("live", 20, { body: "a message sent while the page was open" });
export const truncated = record("cut", 21, { body: "a long message, cut by the Object at 60,000 bytes…", truncated: true });

// The frames the Object relays to one viewer on its connect: every record the
// party's source holds, addressed to that viewer, then the card's current
// reader keys.
export const replay = (viewer, readers) => [
  ...records.map((rec) => ({ rec, to: viewer })),
  { replay_done: viewer, readers },
];
