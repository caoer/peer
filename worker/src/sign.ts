/**
 * The feed config's signature: Ed25519 by the party id's own key, so only a
 * party's root configures its feed and the Worker needs no login of it.
 *
 * PUT /feed/<party id>/config: `X-Peer-Signature` is base64url (no padding)
 * of the signature over the exact body bytes; the body's `party` is the URL's
 * party id and its `at` within MAX_SKEW_MS of now.
 * GET /feed/<party id>/config: the body is empty, so the signature is over
 * the bytes of the `X-Peer-At` header (RFC 3339 UTC), within the same skew.
 */

export const MAX_SKEW_MS = 5 * 60 * 1000;
export const PARTY_RE = /^ed25519:[A-Za-z0-9_-]{43}$/;
const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

export type FeedConfig = { v: 1; party: string; at: string; source: string; readers: string[] };
export type Refusal = { status: number; code: string; error: string };

export function b64urlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// True when `sig` (base64url) is the party id's Ed25519 signature of `bytes`.
export async function verifiedBy(party: string, bytes: Uint8Array, sig: string): Promise<boolean> {
  if (!PARTY_RE.test(party)) return false;
  const pub = b64urlDecode(party.slice("ed25519:".length));
  const s = b64urlDecode(sig);
  if (pub === null || pub.length !== 32 || s === null || s.length !== 64) return false;
  const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, s, bytes);
}

const timely = (at: string, now: number) => RFC3339_UTC.test(at) && Math.abs(Date.parse(at) - now) <= MAX_SKEW_MS;
const refusal = (status: number, code: string, error: string): Refusal => ({ status, code, error });

// The config a signed PUT carries, or why it is refused.
export async function signedConfig(party: string, body: Uint8Array, sig: string | null, now = Date.now()): Promise<FeedConfig | Refusal> {
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
  if (sig === null || !(await verifiedBy(party, body, sig))) return refusal(401, "bad_signature", "X-Peer-Signature is not this party's signature of the body");
  if (!timely(c.at, now)) return refusal(401, "stale", `at must be within ${MAX_SKEW_MS / 60000} minutes of now`);
  return { v: 1, party, at: c.at, source: c.source, readers: [...new Set(c.readers)] };
}

// Null when a signed GET is this party's, else why not.
export async function signedRead(party: string, at: string | null, sig: string | null, now = Date.now()): Promise<Refusal | null> {
  if (at === null || sig === null) return refusal(401, "bad_signature", "reading the config takes X-Peer-At and X-Peer-Signature");
  if (!(await verifiedBy(party, new TextEncoder().encode(at), sig))) return refusal(401, "bad_signature", "X-Peer-Signature is not this party's signature of X-Peer-At");
  if (!timely(at, now)) return refusal(401, "stale", `X-Peer-At must be within ${MAX_SKEW_MS / 60000} minutes of now`);
  return null;
}
