/**
 * The feed config's signature (decision 33, D17): any machine of a party
 * configures its feed with the party's identity key, and the Worker trusts
 * that because the request carries the party's root-signed public card
 * naming that key. No root signature on the config, no login, no key stored.
 *
 * Two headers on PUT /feed/<party id>/config:
 *   X-Peer-Card       base64url, no padding, of `signature (64) ‖ card bytes`
 *                     — the card as envelope #0 carries it (docs/protocol.md
 *                     § The card); verified under the party id BEFORE it is
 *                     parsed; its current key is the first keys[] entry whose
 *                     `until` is null.
 *   X-Peer-Signature  base64url, no padding, of the identity key's XEdDSA
 *                     signature over the exact body bytes (libsignal
 *                     ecc.CalculateSignature).
 * GET carries the same two headers, the signature over the UTF-8 bytes of
 * X-Peer-At (RFC 3339 UTC) — never over empty bytes, which would be constant.
 *
 * XEdDSA as libsignal spells it: the Curve25519 public key u becomes the
 * Ed25519 key y = (u − 1)/(u + 1) mod 2²⁵⁵ − 19; the Edwards sign bit is not
 * fixed but carried in bit 7 of signature[63], which the verifier moves onto
 * y and clears before the standard Ed25519 check (ecc/SignCurve25519.go).
 */

export const MAX_SKEW_MS = 5 * 60 * 1000;
export const PARTY_RE = /^ed25519:[A-Za-z0-9_-]{43}$/;
export const CURVE_RE = /^curve25519:[A-Za-z0-9_-]{43}$/;
// A card is a few hundred bytes; 64 KiB is room for every key a party kept.
export const CARD_MAX = 64 * 1024;
const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

export type FeedConfig = { v: 1; party: string; at: string; source: string; readers: string[] };
export type Refusal = { status: number; code: string; error: string };
// What the Worker keeps of a verified card: the current identity key's 32
// Montgomery bytes. Nothing else is read, nothing is stored.
export type Delegation = { identity: Uint8Array };

export function b64urlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function ed25519Verifies(pub: Uint8Array, bytes: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (pub.length !== 32 || sig.length !== 64) return false;
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return false; // not a point of the curve
  }
  return crypto.subtle.verify({ name: "Ed25519" }, key, sig, bytes);
}

// True when `sig` (base64url) is the party id's own Ed25519 signature of `bytes`:
// the root key, which signs cards and nothing else.
export async function verifiedBy(party: string, bytes: Uint8Array, sig: string | Uint8Array): Promise<boolean> {
  if (!PARTY_RE.test(party)) return false;
  const pub = b64urlDecode(party.slice("ed25519:".length));
  const s = typeof sig === "string" ? b64urlDecode(sig) : sig;
  if (pub === null || s === null) return false;
  return ed25519Verifies(pub, bytes, s);
}

const P = (1n << 255n) - 19n;
const modp = (x: bigint) => ((x % P) + P) % P;
function powmod(base: bigint, exp: bigint): bigint {
  let r = 1n;
  base = modp(base);
  for (; exp > 0n; exp >>= 1n) {
    if (exp & 1n) r = (r * base) % P;
    base = (base * base) % P;
  }
  return r;
}

// The Ed25519 public key libsignal's verifier derives from a Curve25519 one:
// y = (u − 1)·(u + 1)⁻¹ mod p, little-endian, bit 255 the sign bit the
// signature carried. Null for u ≡ −1 (no inverse) and for a key of another
// length.
export function edwardsOf(u: Uint8Array, signBit: 0 | 1): Uint8Array | null {
  if (u.length !== 32) return null;
  let x = 0n;
  for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(u[i]!);
  x &= (1n << 255n) - 1n;
  x = modp(x);
  if (x === P - 1n) return null;
  const y = modp((x - 1n) * powmod(x + 1n, P - 2n));
  const out = new Uint8Array(32);
  let v = y;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (signBit) out[31]! |= 0x80;
  return out;
}

// True when `sig` (64 bytes) is the identity key's XEdDSA signature of `bytes`.
export async function identityVerifies(identity: Uint8Array, bytes: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (sig.length !== 64) return false;
  const pub = edwardsOf(identity, sig[63]! & 0x80 ? 1 : 0);
  if (pub === null) return false;
  const s = sig.slice();
  s[63]! &= 0x7f;
  return ed25519Verifies(pub, bytes, s);
}

const refusal = (status: number, code: string, error: string): Refusal => ({ status, code, error });
const badCard = (why: string) => refusal(401, "bad_card", `X-Peer-Card: ${why}`);

type CardKey = { identity?: unknown; until?: unknown };

// The delegation an X-Peer-Card header carries for `party`, or why it is
// refused: the root signature is checked over the raw bytes before anything
// is parsed, then the card must be v 1, for this party, with a current key.
export async function cardOf(party: string, header: string | null): Promise<Delegation | Refusal> {
  if (header === null) return badCard("the party's root-signed card, base64url of signature ‖ card bytes, is required");
  if (header.length > CARD_MAX) return badCard("too large");
  const packed = b64urlDecode(header);
  if (packed === null || packed.length <= 64) return badCard("not base64url of signature ‖ card bytes");
  const bytes = packed.subarray(64);
  if (!(await verifiedBy(party, bytes, packed.subarray(0, 64)))) return badCard("not signed by this party's root key");
  let c: { v?: unknown; party?: unknown; keys?: unknown };
  try {
    c = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return badCard("not JSON");
  }
  if (c?.v !== 1 || c.party !== party || !Array.isArray(c.keys)) return badCard("not a v1 card of this party");
  const current = (c.keys as CardKey[]).find((k) => k !== null && typeof k === "object" && k.until == null);
  if (current === undefined || typeof current.identity !== "string" || !CURVE_RE.test(current.identity)) return badCard("no current identity key");
  const identity = b64urlDecode(current.identity.slice("curve25519:".length));
  if (identity === null || identity.length !== 32 || identity.every((b) => b === 0)) return badCard("identity key is not 32 bytes");
  return { identity };
}

const timely = (at: string, now: number) => RFC3339_UTC.test(at) && Math.abs(Date.parse(at) - now) <= MAX_SKEW_MS;

// Null when `sig` is the card's current identity key's signature of `bytes`,
// else the refusal — a body the root key signed is named as such.
async function delegatedSignature(party: string, d: Delegation, bytes: Uint8Array, sig: string | null, what: string): Promise<Refusal | null> {
  const s = sig === null ? null : b64urlDecode(sig);
  if (s === null || s.length !== 64) return refusal(401, "bad_signature", `X-Peer-Signature is the identity key's signature of ${what}, base64url of 64 bytes`);
  if (await identityVerifies(d.identity, bytes, s)) return null;
  if (await verifiedBy(party, bytes, s)) return refusal(401, "root_signed", `${what} is signed by the root key; the feed config is signed by the identity key the card names`);
  return refusal(401, "bad_signature", `X-Peer-Signature is not the card's current identity key's signature of ${what}`);
}

// The config a signed PUT carries, or why it is refused.
export async function signedConfig(party: string, body: Uint8Array, card: string | null, sig: string | null, now = Date.now()): Promise<FeedConfig | Refusal> {
  let c: Partial<FeedConfig>;
  try {
    c = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    return refusal(400, "bad_request", "config is not JSON");
  }
  if (
    c?.v !== 1 ||
    c.party !== party ||
    typeof c.at !== "string" ||
    typeof c.source !== "string" ||
    !HASH_RE.test(c.source) ||
    !Array.isArray(c.readers) ||
    c.readers.length > 64 ||
    !c.readers.every((r) => typeof r === "string" && HASH_RE.test(r))
  )
    return refusal(400, "bad_request", 'config is {"v":1,"party":"<this party id>","at":"<RFC 3339 UTC>","source":"sha256:<hex>","readers":["sha256:<hex>",…]}');
  const d = await cardOf(party, card);
  if ("status" in d) return d;
  const refused = await delegatedSignature(party, d, body, sig, "the body");
  if (refused !== null) return refused;
  if (!timely(c.at, now)) return refusal(401, "stale", `at must be within ${MAX_SKEW_MS / 60000} minutes of now`);
  return { v: 1, party, at: c.at, source: c.source, readers: [...new Set(c.readers)] };
}

// Null when a signed GET is this party's, else why not.
export async function signedRead(party: string, at: string | null, card: string | null, sig: string | null, now = Date.now()): Promise<Refusal | null> {
  const d = await cardOf(party, card);
  if ("status" in d) return d;
  if (at === null) return refusal(401, "bad_signature", "reading the config takes X-Peer-At, X-Peer-Card and X-Peer-Signature");
  const refused = await delegatedSignature(party, d, new TextEncoder().encode(at), sig, "X-Peer-At");
  if (refused !== null) return refused;
  if (!timely(at, now)) return refusal(401, "stale", `X-Peer-At must be within ${MAX_SKEW_MS / 60000} minutes of now`);
  return null;
}
