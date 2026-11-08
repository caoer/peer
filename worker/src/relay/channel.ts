/**
 * PeerChannel — the store-and-forward relay behind /peer (the `peer` protocol).
 *
 * One DO per channel, named `p/<id>` (peerName). Two sides meet here: the
 * host, who opened the channel with an owner login, and the guest, who joined
 * it once with the invite token. Each side is known to the relay by its token
 * and nothing else — no party name, no key, no agent. The relay keeps
 * ciphertext it cannot read:
 *
 *   - envelopes, numbered per direction (`h2g` for what the host put, `g2h`
 *     for the guest's), each read by the other side with `after=<seq>`, kept
 *     RETENTION_MS from arrival and then dropped by the alarm. Never dropped on
 *     a read: every host of a fleet reads the same channel, and no token may
 *     delete what the other side has not read yet.
 *   - each side's one-time prekeys, taken one at a time by the other side, so
 *     a prekey is handed out once — an envelope can be read any number of times.
 *   - blobs: an attachment's ciphertext (a `doc` or `file` message names one
 *     and carries its key inside the ratchet envelope), raw bytes up to
 *     BLOB_MAX, stored as BLOB_CHUNK rows because a row holds at most 2 MB,
 *     read by the other side only, kept RETENTION_MS from the put like an
 *     envelope.
 *
 * Push: a side may also hold WebSockets on the envelopes route (hibernatable,
 * tagged by side, the token's hash in the attachment). Each put is stored
 * first and then sent to the other side's open sockets as the row a pull
 * answers; pull stays the source of truth, so a socket starts with a re-pull
 * from the client's cursor and a frame lost to a dropped socket is read by
 * the next pull.
 *
 * Nothing lives in memory. Every deploy restarts every Durable Object, so all
 * state is the SQLite tables below, and a client resumes with its last seq.
 * The per-direction counters live in the `channel` row, not in max(seq): the
 * alarm may empty a direction, and a number handed out once is never reused,
 * or a client holding `after=<seq>` would skip what lands next.
 *
 * The routes are handlePeer below, kept in this module beside the class: the
 * Worker supplies only the owner check, so a channel-only Worker can mount the
 * same routes with its own.
 */

import { DurableObject } from "cloudflare:workers";
import { type PeerRoom, roomRoutes } from "./room";

// What arrived more than this long ago is dropped (the alarm).
export const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
// An envelope's body: standard padded base64 of at most this many bytes.
export const BODY_MAX = 1024 * 1024;
const BODY_TEXT_MAX = 4 * Math.ceil(BODY_MAX / 3);
// A request body: the largest envelope plus its JSON frame; every other
// route's body is a small JSON object.
const REQUEST_MAX = BODY_TEXT_MAX + 4096;
export const SMALL_REQUEST_MAX = 64 * 1024;
// One pull answers at most this many envelopes and this much body text, and
// always one envelope when any qualifies — a single envelope can be the size
// of the whole budget. The client pulls again after its last seq until [].
export const PULL_MAX = 100;
export const PULL_BYTES_MAX = 4 * 1024 * 1024;
export const PREKEYS_PER_PUT = 100;
export const PREKEYS_HELD_MAX = 200;
// A blob is stored in rows of this many bytes: an SQLite-backed Durable
// Object holds at most 2 MB in one string, BLOB or row (Cloudflare, Durable
// Objects limits), so a chunk is half that. The Worker buffers one chunk at
// a time, never the blob.
export const BLOB_CHUNK = 1024 * 1024;
// The largest blob, in ciphertext bytes. Cloudflare refuses a request body
// over 100 MB on the Free and Pro plans (Workers limits) before the Worker
// sees it; 64 MiB stays clear of that, of the 128 MB isolate, and of one
// Object's 10 GB at any plausible rate.
export const BLOB_MAX = 64 * 1024 * 1024;
export const BLOB_ID_RE = /^[0-9a-f]{32}$/;
// Open push sockets per side: one side's token can never use up the other's.
export const SOCKETS_PER_SIDE = 16;
// A client keeps its socket alive with this text frame; the runtime answers
// it without waking the object.
export const PING = "ping";
export const PONG = "pong";
// Closing codes of a push socket whose token stopped opening a side of the
// channel, or whose channel stopped existing — checked on each client frame
// the runtime does not answer itself.
export const CLOSE_BAD_TOKEN = 4401;
export const CLOSE_NO_SUCH_CHANNEL = 4404;
// A prekey's public half, base64: 44 characters for a 33-byte key.
const PUB_MAX = 256;
const UINT32_MAX = 0xffff_ffff;

export const ENVELOPE_TYPES = ["card", "prekey", "msg"] as const;
export type EnvelopeType = (typeof ENVELOPE_TYPES)[number];
export type Dir = "h2g" | "g2h";
type Side = "host" | "guest";

export const CHANNEL_ID_RE = /^[0-9a-f]{32}$/;
// 32 random bytes, base64url without padding: never a "." (the invite link
// joins its parts with one).
export const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const AFTER_RE = /^-?[0-9]{1,15}$/;
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

export const peerName = (id: string) => `p/${id}`;

export type Envelope = { seq: number; type: EnvelopeType; body: string; at: number };
export type Prekey = { id: number; pub: string };
export type Refusal = { refused: { status: number; code: string; error: string } };

const refusal = (status: number, code: string, error: string): Refusal => ({ refused: { status, code, error } });
const NO_SUCH_CHANNEL = refusal(404, "no_such_channel", "no such channel");
const BAD_TOKEN = refusal(401, "bad_token", "this token opens no side of this channel");
const NO_SUCH_BLOB = refusal(404, "no_such_blob", "no such blob for this side: never put, put by this side, not finished, or past retention");

// A push socket's attachment: its side (also its tag) and the hash of the
// token that opened it. `gone` marks a socket this object closed —
// getWebSockets keeps it until the far end answers, and it must receive
// nothing more.
type SocketAtt = { side: Side; hash: string; gone?: true };

const dirOf = (side: Side): Dir => (side === "host" ? "h2g" : "g2h");
const otherSide = (side: Side): Side => (side === "host" ? "guest" : "host");

const hex = (bytes: Uint8Array): string => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

export async function sha256Hex(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}

// index.ts's secretMatches, spelled again here because index.ts imports this
// module (as bus.ts spells `fail`): constant-time over the two digests, which
// are always 32 bytes, so the length of what was presented is not told either.
// peer-relay.ts checks its owner login with it.
export async function secretMatches(presented: string, expected: string): Promise<boolean> {
  const enc = new TextEncoder();
  const a = await crypto.subtle.digest("SHA-256", enc.encode(presented));
  const b = await crypto.subtle.digest("SHA-256", enc.encode(expected));
  return crypto.subtle.timingSafeEqual(a, b);
}

export function mintToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const mintChannelId = (): string => hex(crypto.getRandomValues(new Uint8Array(16)));

// The decoded length of standard padded base64, or null when it is not that.
export function decodedLength(text: string): number | null {
  if (text.length % 4 !== 0 || !B64_RE.test(text)) return null;
  const pad = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
  return (text.length / 4) * 3 - pad;
}

class TooManyPrekeys extends Error {}

export class PeerChannel extends DurableObject<PeerEnv> {
  constructor(ctx: DurableObjectState, env: PeerEnv) {
    super(ctx, env);
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair(PING, PONG));
    // Only a created channel gets tables: a request naming an id nobody
    // created reads, and writes nothing.
    if (this.created()) this.ensureSchema();
  }

  private ensureSchema(): void {
    const sql = this.ctx.storage.sql;
    sql.exec(
      "CREATE TABLE IF NOT EXISTS channel (" +
        "one INTEGER PRIMARY KEY CHECK (one = 1), owner TEXT NOT NULL, created INTEGER NOT NULL, " +
        "next_h2g INTEGER NOT NULL DEFAULT 0, next_g2h INTEGER NOT NULL DEFAULT 0)",
    );
    // role: host | invite | guest. hash: SHA-256 hex of the token; `used` is
    // set on the invite when it is spent.
    sql.exec("CREATE TABLE IF NOT EXISTS tokens (role TEXT PRIMARY KEY, hash TEXT NOT NULL, created INTEGER NOT NULL, used INTEGER)");
    sql.exec(
      "CREATE TABLE IF NOT EXISTS envelopes (" +
        "dir TEXT NOT NULL, seq INTEGER NOT NULL, type TEXT NOT NULL, body TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (dir, seq))",
    );
    sql.exec("CREATE INDEX IF NOT EXISTS envelopes_by_at ON envelopes (at)");
    // Taken oldest first: rowid order is insertion order. A taken key keeps
    // its row with `taken` set, so a retried batch carrying its id lands as
    // nothing and the key is never handed out twice.
    sql.exec(
      "CREATE TABLE IF NOT EXISTS prekeys (side TEXT NOT NULL, id INTEGER NOT NULL, pub TEXT NOT NULL, at INTEGER NOT NULL, taken INTEGER, PRIMARY KEY (side, id))",
    );
    // A blob is readable once `size` is set (the put finished); its bytes are
    // the chunks in n order. `at` is when the put began: the alarm drops a
    // finished blob and an abandoned put alike.
    sql.exec("CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, side TEXT NOT NULL, at INTEGER NOT NULL, size INTEGER, chunks INTEGER)");
    sql.exec("CREATE INDEX IF NOT EXISTS blobs_by_at ON blobs (at)");
    sql.exec("CREATE TABLE IF NOT EXISTS blob_chunks (blob TEXT NOT NULL, n INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (blob, n))");
  }

  // Arms the retention alarm when none is: every row is younger than the one
  // an armed alarm is waiting for.
  private async armAlarm(at: number): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(at + RETENTION_MS + 1);
  }

  private created(): boolean {
    const sql = this.ctx.storage.sql;
    if (sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'channel'").toArray().length === 0) return false;
    return sql.exec("SELECT 1 FROM channel").toArray().length > 0;
  }

  // The side a token hash opens, compared in constant time against both.
  private async sideOf(hash: string): Promise<Side | null> {
    const rows = this.ctx.storage.sql.exec<{ role: Side; hash: string }>("SELECT role, hash FROM tokens WHERE role IN ('host', 'guest')").toArray();
    let side: Side | null = null;
    for (const row of rows) if (await secretMatches(hash, row.hash)) side = row.role;
    return side;
  }

  // POST /peer/channels, after the Worker checked the owner login.
  async create(owner: string, hostHash: string, inviteHash: string): Promise<{ ok: true } | Refusal> {
    // 128 random bits: a collision is a broken random source, not a client error.
    if (this.created()) return refusal(500, "internal_error", "the minted channel id is taken; nothing was created");
    this.ensureSchema();
    const now = Date.now();
    const sql = this.ctx.storage.sql;
    this.ctx.storage.transactionSync(() => {
      sql.exec("INSERT INTO channel (one, owner, created) VALUES (1, ?, ?)", owner, now);
      sql.exec("INSERT INTO tokens (role, hash, created) VALUES ('host', ?, ?), ('invite', ?, ?)", hostHash, now, inviteHash, now);
    });
    return { ok: true };
  }

  // POST /peer/c/<id>/join: the invite is spent once, and the guest's token
  // is the one the Worker minted for this attempt.
  async join(inviteHash: string, guestHash: string): Promise<{ ok: true } | Refusal> {
    if (!this.created()) return NO_SUCH_CHANNEL;
    const sql = this.ctx.storage.sql;
    const invite = sql.exec<{ hash: string }>("SELECT hash FROM tokens WHERE role = 'invite'").one();
    if (!(await secretMatches(inviteHash, invite.hash))) return BAD_TOKEN;
    // No await from here on: two joins racing with the right token cannot both
    // read the invite unspent.
    if (sql.exec<{ used: number | null }>("SELECT used FROM tokens WHERE role = 'invite'").one().used !== null)
      return refusal(409, "token_used", "this invite was already used");
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      sql.exec("UPDATE tokens SET used = ? WHERE role = 'invite'", now);
      sql.exec("INSERT INTO tokens (role, hash, created) VALUES ('guest', ?, ?)", guestHash, now);
    });
    return { ok: true };
  }

  // POST /peer/c/<id>/envelopes. The Worker checked type and body.
  async put(tokenHash: string, type: EnvelopeType, body: string): Promise<{ dir: Dir; seq: number } | Refusal> {
    if (!this.created()) return NO_SUCH_CHANNEL;
    const side = await this.sideOf(tokenHash);
    if (side === null) return BAD_TOKEN;
    const dir = dirOf(side);
    const sql = this.ctx.storage.sql;
    const at = Date.now();
    const seq = this.ctx.storage.transactionSync(() => {
      const n = Number(sql.exec(`SELECT next_${dir} AS n FROM channel`).one().n);
      sql.exec("INSERT INTO envelopes (dir, seq, type, body, at) VALUES (?, ?, ?, ?, ?)", dir, n, type, body, at);
      sql.exec(`UPDATE channel SET next_${dir} = ?`, n + 1);
      return n;
    });
    // Stored first, sent after: the output gate holds the frames until the row
    // is durable, so a frame never names a row a pull cannot read.
    this.push(otherSide(side), { seq, type, body, at });
    await this.armAlarm(at);
    return { dir, seq };
  }

  // GET /peer/c/<id>/envelopes?after=<n>: the other direction, seq > after.
  async pull(tokenHash: string, after: number): Promise<{ envelopes: Envelope[] } | Refusal> {
    if (!this.created()) return NO_SUCH_CHANNEL;
    const side = await this.sideOf(tokenHash);
    if (side === null) return BAD_TOKEN;
    const dir = dirOf(otherSide(side));
    const sql = this.ctx.storage.sql;
    // Sizes first, so a page of large bodies is never read whole into memory.
    const sizes = sql
      .exec<{ seq: number; n: number }>("SELECT seq, length(body) AS n FROM envelopes WHERE dir = ? AND seq > ? ORDER BY seq LIMIT ?", dir, after, PULL_MAX)
      .toArray();
    let last: number | null = null;
    let budget = PULL_BYTES_MAX;
    for (const row of sizes) {
      budget -= row.n;
      if (budget < 0 && last !== null) break;
      last = row.seq;
    }
    if (last === null) return { envelopes: [] };
    const envelopes = sql
      .exec<Envelope>("SELECT seq, type, body, at FROM envelopes WHERE dir = ? AND seq > ? AND seq <= ? ORDER BY seq", dir, after, last)
      .toArray()
      .map((r) => ({ seq: Number(r.seq), type: r.type, body: r.body, at: Number(r.at) }));
    return { envelopes };
  }

  // PUT /peer/c/<id>/prekeys: appended to the token's own side. An id the
  // side ever put — held or already taken — is ignored, so a retried batch
  // lands once.
  async putPrekeys(tokenHash: string, keys: Prekey[]): Promise<{ count: number } | Refusal> {
    if (!this.created()) return NO_SUCH_CHANNEL;
    const side = await this.sideOf(tokenHash);
    if (side === null) return BAD_TOKEN;
    const sql = this.ctx.storage.sql;
    const now = Date.now();
    try {
      const count = this.ctx.storage.transactionSync(() => {
        for (const k of keys)
          sql.exec("INSERT INTO prekeys (side, id, pub, at) VALUES (?, ?, ?, ?) ON CONFLICT (side, id) DO NOTHING", side, k.id, k.pub, now);
        const held = Number(sql.exec("SELECT count(*) AS n FROM prekeys WHERE side = ? AND taken IS NULL", side).one().n);
        if (held > PREKEYS_HELD_MAX) throw new TooManyPrekeys();
        return held;
      });
      return { count };
    } catch (e) {
      if (e instanceof TooManyPrekeys) return refusal(413, "too_large", `a side holds at most ${PREKEYS_HELD_MAX} prekeys`);
      throw e;
    }
  }

  // POST /peer/c/<id>/prekeys/take: the other side's oldest untaken key,
  // marked taken as it is handed out; null when that side holds none.
  async takePrekey(tokenHash: string): Promise<{ key: Prekey | null } | Refusal> {
    if (!this.created()) return NO_SUCH_CHANNEL;
    const side = await this.sideOf(tokenHash);
    if (side === null) return BAD_TOKEN;
    const row = this.ctx.storage.sql
      .exec<Prekey>(
        "UPDATE prekeys SET taken = ? WHERE rowid = (SELECT rowid FROM prekeys WHERE side = ? AND taken IS NULL ORDER BY rowid LIMIT 1) RETURNING id, pub",
        Date.now(),
        otherSide(side),
      )
      .toArray()[0];
    return { key: row ? { id: Number(row.id), pub: row.pub } : null };
  }

  // The push upgrade on GET /peer/c/<id>/envelopes, after the Worker hashed
  // the bearer token (`x-peer-hash`): refused as the pull refuses, or a 101.
  // The socket is tagged by its side and carries nothing but the hash.
  async fetch(req: Request): Promise<Response> {
    if (!this.created()) return refused(NO_SUCH_CHANNEL);
    const hash = req.headers.get("x-peer-hash") ?? "";
    const side = await this.sideOf(hash);
    if (side === null) return refused(BAD_TOKEN);
    // No await from the count to the accept: two upgrades cannot both take the last place.
    const held = this.open(side).length;
    if (held >= SOCKETS_PER_SIDE)
      return fail(429, "too_many_sockets", `this side already holds ${held} sockets on this channel; the cap is ${SOCKETS_PER_SIDE}`);
    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, [side]);
    server.serializeAttachment({ side, hash } satisfies SocketAtt);
    return new Response(null, { status: 101, webSocket: client });
  }

  // A client frame the runtime did not answer (anything but PING). The relay
  // reads nothing from a socket; the frame is only the moment to check that
  // the socket's token still opens its side of a channel that exists.
  async webSocketMessage(ws: WebSocket): Promise<void> {
    const att = ws.deserializeAttachment() as SocketAtt | null;
    if (att === null || att.gone) return;
    if (!this.created()) return this.closeAs(ws, CLOSE_NO_SUCH_CHANNEL, "no_such_channel");
    if ((await this.sideOf(att.hash)) !== att.side) return this.closeAs(ws, CLOSE_BAD_TOKEN, "bad_token");
  }

  // The runtime does not answer a client's close frame for a hibernated
  // socket; echoing it completes the handshake (as UsageHub).
  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    try {
      ws.close(code === 1005 || code === 1006 || code === 1015 ? 1000 : code, reason);
    } catch {
      // already closed
    }
  }

  async webSocketError(): Promise<void> {
    // Nothing is kept per socket; the runtime drops it.
  }

  // One frame per envelope, the row a pull answers. A socket that cannot take
  // it never fails the put: its client reads the row on its next pull.
  private push(to: Side, row: Envelope): void {
    const frame = JSON.stringify(row);
    for (const ws of this.open(to)) {
      try {
        ws.send(frame);
      } catch {
        // gone between the listing and the send
      }
    }
  }

  // A side's sockets that are OPEN and not closed by this object
  // (getWebSockets keeps CLOSING sockets).
  private open(side: Side): WebSocket[] {
    return this.ctx.getWebSockets(side).filter((ws) => {
      if (ws.readyState !== WebSocket.OPEN) return false;
      const att = ws.deserializeAttachment() as SocketAtt | null;
      return att !== null && att.gone !== true;
    });
  }

  private closeAs(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.serializeAttachment({ ...(ws.deserializeAttachment() as SocketAtt), gone: true } satisfies SocketAtt);
      ws.close(code, reason);
    } catch {
      // already gone
    }
  }

  // POST /peer/c/<id>/blobs, first call: a fresh blob id on the token's side.
  // The Worker then streams the request body in as chunks and finishes it;
  // until blobFinish it reads as no blob at all.
  async blobBegin(tokenHash: string): Promise<{ blob: string } | Refusal> {
    if (!this.created()) return NO_SUCH_CHANNEL;
    const side = await this.sideOf(tokenHash);
    if (side === null) return BAD_TOKEN;
    const blob = hex(crypto.getRandomValues(new Uint8Array(16)));
    const at = Date.now();
    this.ctx.storage.sql.exec("INSERT INTO blobs (id, side, at) VALUES (?, ?, ?)", blob, side, at);
    await this.armAlarm(at);
    return { blob };
  }

  // One chunk of a put in progress; false when the blob is gone (the alarm
  // took an abandoned put) or already finished.
  async blobAppend(blob: string, n: number, data: ArrayBuffer): Promise<boolean> {
    const sql = this.ctx.storage.sql;
    if (sql.exec("SELECT 1 FROM blobs WHERE id = ? AND size IS NULL", blob).toArray().length === 0) return false;
    sql.exec("INSERT INTO blob_chunks (blob, n, data) VALUES (?, ?, ?)", blob, n, data);
    return true;
  }

  async blobFinish(blob: string, size: number, chunks: number): Promise<boolean> {
    const sql = this.ctx.storage.sql;
    return sql.exec("UPDATE blobs SET size = ?, chunks = ? WHERE id = ? AND size IS NULL RETURNING id", size, chunks, blob).toArray().length === 1;
  }

  // A put that failed part way: its rows go now rather than at the alarm.
  async blobDrop(blob: string): Promise<void> {
    const sql = this.ctx.storage.sql;
    this.ctx.storage.transactionSync(() => {
      sql.exec("DELETE FROM blob_chunks WHERE blob = ?", blob);
      sql.exec("DELETE FROM blobs WHERE id = ?", blob);
    });
  }

  // GET /peer/c/<id>/blobs/<blob>: a finished blob the OTHER side put — the
  // same rule as envelopes, a token reads what was put for it. The Worker
  // then reads the chunks one call at a time.
  async blobOpen(tokenHash: string, blob: string): Promise<{ size: number; chunks: number } | Refusal> {
    if (!this.created()) return NO_SUCH_CHANNEL;
    const side = await this.sideOf(tokenHash);
    if (side === null) return BAD_TOKEN;
    const row = this.ctx.storage.sql
      .exec<{ size: number; chunks: number }>("SELECT size, chunks FROM blobs WHERE id = ? AND side = ? AND size IS NOT NULL", blob, otherSide(side))
      .toArray()[0];
    if (!row) return NO_SUCH_BLOB;
    return { size: Number(row.size), chunks: Number(row.chunks) };
  }

  async blobChunk(blob: string, n: number): Promise<ArrayBuffer | null> {
    const row = this.ctx.storage.sql.exec<{ data: ArrayBuffer }>("SELECT data FROM blob_chunks WHERE blob = ? AND n = ?", blob, n).toArray()[0];
    return row ? row.data : null;
  }

  // Retention: what arrived more than RETENTION_MS ago goes — envelopes and
  // blobs — and the alarm is set again for the oldest row left.
  async alarm(): Promise<void> {
    if (!this.created()) return;
    const sql = this.ctx.storage.sql;
    const cutoff = Date.now() - RETENTION_MS;
    sql.exec("DELETE FROM envelopes WHERE at < ?", cutoff);
    this.ctx.storage.transactionSync(() => {
      sql.exec("DELETE FROM blob_chunks WHERE blob IN (SELECT id FROM blobs WHERE at < ?)", cutoff);
      sql.exec("DELETE FROM blobs WHERE at < ?", cutoff);
    });
    const oldest = sql
      .exec<{ at: number | null }>("SELECT min(at) AS at FROM (SELECT at FROM envelopes UNION ALL SELECT at FROM blobs)")
      .one().at;
    if (oldest !== null) await this.ctx.storage.setAlarm(Number(oldest) + RETENTION_MS + 1);
  }
}

// --- the routes (/peer) ---

export interface PeerEnv {
  PEER_CHANNEL: DurableObjectNamespace<PeerChannel>;
  // One instance per v2 room, named `r/<id>` (src/peer-room.ts).
  PEER_ROOM: DurableObjectNamespace<PeerRoom>;
  // Every /peer request, keyed on the client IP, before anything wakes.
  PEER_HITS: RateLimit;
}

export const answer = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data, null, 2) + "\n", {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
  });
export const fail = (status: number, code: string, error: string) => answer({ error, code }, status);
export const refused = (r: Refusal) => fail(r.refused.status, r.refused.code, r.refused.error);
export const methodNotAllowed = () => fail(405, "method_not_allowed", "method not allowed");
export const badRequest = (error: string) => fail(400, "bad_request", error);
const badToken = () => refused(BAD_TOKEN);

// The peer release the landings point an agent at. One spelling: README.md
// carries the same tag, and relay.spec.ts fails when the two differ, so a
// release bump (scripts/release-build.sh, U5) changes both or neither.
export const RELEASE_TAG = "v0.5.2";

// Every landing's install route, before its accept or follow line: an agent
// on a machine without peer stopped at the accept line and asked its human.
export const INSTALL = `Install peer first if \`peer --help\` does not run:

  go install github.com/caoer/peer/cmd/peer@${RELEASE_TAG}

or take a binary from https://github.com/caoer/peer/releases/tag/${RELEASE_TAG}
(peer-${RELEASE_TAG}-darwin-arm64, peer-${RELEASE_TAG}-linux-amd64; SHA256SUMS beside them).
`;

const LANDING = `peer — an invitation to an end-to-end encrypted channel

Someone sent you this link so that your agent and theirs can talk through the
peer protocol. ${INSTALL}
Then accept the invitation with the peer CLI, passing the WHOLE link, the part
after '#' included:

  peer accept '<the link>'

The part after '#' carries the inviter's key and a one-time token; a browser
never sends it to this server. The token works once. This relay stores only
ciphertext and cannot read what passes through it.
`;

// A body read up to `max` bytes, or null past it — never buffered whole first.
export async function readCapped(req: Request, max: number): Promise<string | null> {
  const declared = parseInt(req.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(declared) && declared > max) return null;
  if (req.body === null) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

// A JSON object body, or the refusal to answer instead.
export async function readObject(req: Request, max: number): Promise<Record<string, unknown> | Response> {
  const text = await readCapped(req, max);
  if (text === null) return fail(413, "too_large", `request body over ${max} bytes`);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return badRequest("the body is not JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return badRequest("the body is a JSON object");
  return value as Record<string, unknown>;
}

// The side token from `Authorization: Bearer <token>`, hashed; null when
// absent or not a token's shape.
export async function bearerHash(req: Request): Promise<string | null> {
  const h = req.headers.get("authorization") ?? "";
  if (!h.startsWith("Bearer ")) return null;
  const token = h.slice(7).trim();
  return TOKEN_RE.test(token) ? sha256Hex(token) : null;
}

function parseKeys(value: unknown): Prekey[] | Response {
  if (!Array.isArray(value) || value.length === 0) return badRequest("keys is a non-empty array of {id, pub}");
  if (value.length > PREKEYS_PER_PUT) return fail(413, "too_large", `at most ${PREKEYS_PER_PUT} prekeys per request`);
  const keys: Prekey[] = [];
  for (const k of value) {
    if (typeof k !== "object" || k === null || Array.isArray(k)) return badRequest("each key is {id, pub}");
    const { id, pub } = k as Record<string, unknown>;
    if (typeof id !== "number" || !Number.isInteger(id) || id < 0 || id > UINT32_MAX) return badRequest("a key's id is a uint32");
    if (typeof pub !== "string" || pub.length === 0 || pub.length > PUB_MAX || decodedLength(pub) === null)
      return badRequest(`a key's pub is standard base64 of at most ${PUB_MAX} characters`);
    keys.push({ id, pub });
  }
  return keys;
}

// /peer — the relay's routes. `ownerOf` answers the owner login a request
// carries, or null; only opening a channel asks for one. A route that throws
// — an Object call failing while a deploy restarts it, a blob dropped under
// its put — answers 500 `internal_error` in the contract's `{error, code}`
// shape, the same from the main Worker and the relay alone.
export async function handlePeer(
  req: Request,
  env: PeerEnv,
  parts: string[],
  ownerOf: (req: Request) => Promise<string | null>,
): Promise<Response> {
  try {
    return await peerRoutes(req, env, parts, ownerOf);
  } catch (e) {
    return fail(500, "internal_error", e instanceof Error ? e.message : "internal error");
  }
}

async function peerRoutes(
  req: Request,
  env: PeerEnv,
  parts: string[],
  ownerOf: (req: Request) => Promise<string | null>,
): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  if (!(await env.PEER_HITS.limit({ key: ip })).success) return fail(429, "rate_limited", "too many requests from this address; retry in a few seconds");
  const route = parts.slice(1);
  // v2 rooms: their own Object and routes (src/peer-room.ts), behind the same limiter.
  if (route[0] === "rooms" || route[0] === "r" || route[0] === "f") return roomRoutes(req, env, route, ownerOf);

  if (route.length === 1 && route[0] === "channels") {
    if (req.method !== "POST") return methodNotAllowed();
    const owner = await ownerOf(req);
    if (owner === null) return fail(401, "bad_token", "opening a channel takes the owner login: Bearer <user>:<token>");
    const id = mintChannelId();
    const hostToken = mintToken();
    const inviteToken = mintToken();
    const made = await env.PEER_CHANNEL.getByName(peerName(id)).create(owner, await sha256Hex(hostToken), await sha256Hex(inviteToken));
    if ("refused" in made) return refused(made);
    return answer({ id, hostToken, inviteToken });
  }

  if (route.length === 2 && route[0] === "i") {
    if (req.method !== "GET" && req.method !== "HEAD") return methodNotAllowed();
    if (!CHANNEL_ID_RE.test(route[1]!)) return refused(NO_SUCH_CHANNEL);
    return new Response(req.method === "HEAD" ? null : LANDING, {
      headers: { "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" },
    });
  }

  if (route.length < 3 || route[0] !== "c") return fail(404, "no_such_route", "no such route");
  const id = route[1]!;
  if (!CHANNEL_ID_RE.test(id)) return refused(NO_SUCH_CHANNEL);
  const channel = env.PEER_CHANNEL.getByName(peerName(id));
  const op = route.slice(2).join("/");

  if (op === "join") {
    if (req.method !== "POST") return methodNotAllowed();
    const body = await readObject(req, SMALL_REQUEST_MAX);
    if (body instanceof Response) return body;
    const invite = body.inviteToken;
    if (typeof invite !== "string" || !TOKEN_RE.test(invite)) return badToken();
    const guestToken = mintToken();
    const joined = await channel.join(await sha256Hex(invite), await sha256Hex(guestToken));
    if ("refused" in joined) return refused(joined);
    return answer({ guestToken });
  }

  if (op === "envelopes") {
    if (req.method !== "POST" && req.method !== "GET") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    if (req.method === "GET" && req.headers.get("upgrade")?.toLowerCase() === "websocket")
      return channel.fetch(new Request("https://peer/push", { headers: { upgrade: "websocket", "x-peer-hash": hash } }));
    if (req.method === "GET") {
      const raw = new URL(req.url).searchParams.get("after");
      if (raw !== null && !AFTER_RE.test(raw)) return badRequest("after is a whole number, -1 or more");
      const after = raw === null ? -1 : Number(raw);
      if (after < -1) return badRequest("after is a whole number, -1 or more");
      const pulled = await channel.pull(hash, after);
      if ("refused" in pulled) return refused(pulled);
      return answer(pulled.envelopes);
    }
    const body = await readObject(req, REQUEST_MAX);
    if (body instanceof Response) return body;
    const { type, body: data } = body;
    if (typeof type !== "string" || !(ENVELOPE_TYPES as readonly string[]).includes(type))
      return badRequest(`type is one of ${ENVELOPE_TYPES.join(", ")}`);
    if (typeof data !== "string") return badRequest("body is a standard base64 string");
    const n = decodedLength(data);
    if (n === null || n === 0) return badRequest("body is non-empty standard base64 with padding");
    if (n > BODY_MAX) return fail(413, "too_large", `an envelope's body is at most ${BODY_MAX} bytes decoded`);
    const landed = await channel.put(hash, type as EnvelopeType, data);
    if ("refused" in landed) return refused(landed);
    return answer(landed);
  }

  if (op === "prekeys") {
    if (req.method !== "PUT") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    const body = await readObject(req, SMALL_REQUEST_MAX);
    if (body instanceof Response) return body;
    const keys = parseKeys(body.keys);
    if (keys instanceof Response) return keys;
    const stored = await channel.putPrekeys(hash, keys);
    if ("refused" in stored) return refused(stored);
    return answer(stored);
  }

  if (op === "prekeys/take") {
    if (req.method !== "POST") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    const taken = await channel.takePrekey(hash);
    if ("refused" in taken) return refused(taken);
    return answer(taken.key ?? {});
  }

  if (op === "blobs") {
    if (req.method !== "POST") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    return putBlob(req, channel, hash);
  }

  if (route.length === 4 && route[2] === "blobs") {
    if (req.method !== "GET") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    const blob = route[3]!;
    if (!BLOB_ID_RE.test(blob)) return refused(NO_SUCH_BLOB);
    return getBlob(channel, hash, blob);
  }

  return fail(404, "no_such_route", "no such route");
}

const tooLargeBlob = () => fail(413, "too_large", `a blob is at most ${BLOB_MAX} bytes`);

// POST /peer/c/<id>/blobs: the request body is the ciphertext, raw bytes
// (no base64 — a blob is not an envelope), streamed into BLOB_CHUNK rows.
// Answers {blob, size} once every byte is stored; a put that fails part way
// leaves nothing readable.
async function putBlob(req: Request, channel: DurableObjectStub<PeerChannel>, hash: string): Promise<Response> {
  const declared = parseInt(req.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(declared) && declared > BLOB_MAX) return tooLargeBlob();
  if (req.body === null) return badRequest("the body is the blob's bytes, at least one");
  const begun = await channel.blobBegin(hash);
  if ("refused" in begun) return refused(begun);
  const { blob } = begun;
  const reader = req.body.getReader();
  const buf = new Uint8Array(BLOB_CHUNK);
  let fill = 0;
  let size = 0;
  let chunks = 0;
  const flush = async () => {
    if (!(await channel.blobAppend(blob, chunks, buf.slice(0, fill).buffer))) throw new Error("the blob was dropped during its put");
    chunks++;
    fill = 0;
  };
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > BLOB_MAX) {
        await reader.cancel();
        await channel.blobDrop(blob);
        return tooLargeBlob();
      }
      let off = 0;
      while (off < value.byteLength) {
        const take = Math.min(BLOB_CHUNK - fill, value.byteLength - off);
        buf.set(value.subarray(off, off + take), fill);
        fill += take;
        off += take;
        if (fill === BLOB_CHUNK) await flush();
      }
    }
    if (fill > 0) await flush();
    if (size === 0) {
      await channel.blobDrop(blob);
      return badRequest("the body is the blob's bytes, at least one");
    }
    // A body that ends short of its declared length is a put cut off, not a
    // smaller blob: nothing of it becomes readable.
    if (Number.isFinite(declared) && declared !== size) {
      await channel.blobDrop(blob);
      return badRequest(`the body ended at ${size} bytes of the ${declared} declared`);
    }
    if (!(await channel.blobFinish(blob, size, chunks))) throw new Error("the blob was dropped during its put");
  } catch (e) {
    await channel.blobDrop(blob);
    throw e;
  }
  return answer({ blob, size });
}

// GET /peer/c/<id>/blobs/<blob>: the bytes as put, streamed a chunk at a time.
async function getBlob(channel: DurableObjectStub<PeerChannel>, hash: string, blob: string): Promise<Response> {
  const opened = await channel.blobOpen(hash, blob);
  if ("refused" in opened) return refused(opened);
  // A fixed length, so the answer carries content-length and a read cut
  // short — the alarm dropping the blob mid-read — fails at the client
  // instead of looking like a shorter blob.
  const { readable, writable } = new FixedLengthStream(opened.size);
  const pump = async () => {
    const writer = writable.getWriter();
    try {
      for (let n = 0; n < opened.chunks; n++) {
        const data = await channel.blobChunk(blob, n);
        if (data === null) throw new Error("the blob expired during its read");
        await writer.write(new Uint8Array(data));
      }
      await writer.close();
    } catch (e) {
      await writer.abort(e);
    }
  };
  void pump();
  return new Response(readable, {
    headers: { "content-type": "application/octet-stream", "content-length": String(opened.size), "x-content-type-options": "nosniff" },
  });
}
