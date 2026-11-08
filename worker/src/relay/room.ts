/**
 * PeerRoom — a `peer` v2 room on the relay (/peer/rooms, /peer/r/<id>).
 *
 * One DO per room, named `r/<id>` (roomName). A room is one log of sealed
 * records that every member writes and reads: the relay numbers them (`seq`
 * from 0 per room, never reused), keeps them RETENTION_MS from the put, and
 * reads nothing of a record but its length. Wire contract: peer v2 rooms
 * (§ Room routes).
 *
 * Members are indexes (`idx`, from 0, never reused), each with a role —
 * `write` or `read` — and a `from`: the log head when it was minted, below
 * which it reads nothing. A token belongs to one idx; `admin` is a flag on
 * the token, never on the idx, so the creator (idx 0) can hand admin to
 * another idx and leave. A revoke is per idx and takes every token on it.
 *
 * The membership version linearizes puts: it rises by one on every mint,
 * revoke, admin grant and `bump` put, and a put names the version it was
 * sealed against — one below the current is refused before anything is
 * stored. A removal record carries `bump: true`, so it and the version move
 * in one transaction, and no put sealed to the leaver lands after it.
 *
 * Nothing lives in memory: the tables below are the room, and every method
 * runs without an await between its reads and its writes, so two requests
 * never interleave inside one.
 *
 * State: any member's token reads the room as this object holds it — the
 * room row but its owner, the retention alarm as it concerns the caller,
 * the token's own seat, and the log from the seat's `from` with the
 * caller's own records in it, paged as a pull. It shows the relay's side of
 * the protocol to a member, and widens nothing: no token hash, no record
 * below `from` nor its time, and the member list stays an admin token's.
 *
 * Push: a member may also hold WebSockets on the records route
 * (hibernatable, tagged by idx, the token's hash in the attachment). Each put
 * is stored first and then sent to every other idx's open sockets as the row
 * a pull answers; pull stays the source of truth, as on PeerChannel. A revoke
 * closes the idx's sockets with CLOSE_BAD_TOKEN (4401).
 *
 * The routes are roomRoutes below, mounted by peer.ts's handlePeer after its
 * limiter. peer.ts imports this module and this module imports peer.ts's
 * helpers — a cycle, sound because nothing here reads a peer.ts binding
 * while the module evaluates, only when a route or method runs.
 */

import { DurableObject } from "cloudflare:workers";
import {
  BODY_MAX,
  CLOSE_BAD_TOKEN,
  CLOSE_NO_SUCH_CHANNEL,
  PING,
  PONG,
  PULL_BYTES_MAX,
  PULL_MAX,
  RETENTION_MS,
  SMALL_REQUEST_MAX,
  answer,
  badRequest,
  bearerHash,
  decodedLength,
  fail,
  methodNotAllowed,
  mintChannelId,
  mintToken,
  readCapped,
  readObject,
  refused,
  sha256Hex,
  type PeerEnv,
  type Refusal,
} from "./channel";

export const ROOM_ID_RE = /^[0-9a-f]{32}$/;
// A stanza names its recipient in a uint16 and a feed's link stanza takes
// 65535, so a member's idx is at most 65534.
export const IDX_MAX = 65534;
export const RECORD_TYPES = ["sealed"] as const;
export const ADD_SETTINGS = ["admins", "members"] as const;
export const ROLES = ["write", "read"] as const;
export type Add = (typeof ADD_SETTINGS)[number];
export type Role = (typeof ROLES)[number];
// Open push sockets per idx: one member's token can never use up another's.
export const SOCKETS_PER_IDX = 16;
const IDX_RE = /^[0-9]{1,5}$/;
const AFTER_RE = /^-?[0-9]{1,15}$/;

export const roomName = (id: string) => `r/${id}`;

export type RoomRecord = { seq: number; idx: number; type: string; body: string; at: number };
export type Member = { idx: number; role: Role; from: number; admin: boolean; revoked: boolean };
// GET /peer/r/<id>/state. Times are epoch milliseconds. `alarm` is when the
// retention alarm next drops a record of the caller's view, null when it
// drops none. `log` counts what the caller's view holds (seq >= from):
// `first` its lowest seq and `oldest` its earliest put, both null when empty.
export type RoomState = {
  room: { created: number; add: Add; membership: number; next: number; retention: number; alarm: number | null };
  you: { idx: number; role: Role; from: number; admin: boolean; sockets: number };
  log: { count: number; first: number | null; oldest: number | null };
  records: RoomRecord[];
};

const NO_SUCH_ROOM: Refusal = { refused: { status: 404, code: "no_such_room", error: "no such room" } };
const BAD_TOKEN: Refusal = { refused: { status: 401, code: "bad_token", error: "this token opens no member of this room" } };
const REVOKED: Refusal = { refused: { status: 401, code: "revoked", error: "this token's member was removed from the room or left it" } };
const NOT_ADMIN: Refusal = { refused: { status: 403, code: "not_admin", error: "this takes an admin token of the room" } };
const NO_SUCH_MEMBER: Refusal = { refused: { status: 404, code: "no_such_member", error: "no live member at this idx" } };
const refusal = (status: number, code: string, error: string): Refusal => ({ refused: { status, code, error } });

// The member a token opens, with the token's admin flag.
type Caller = { idx: number; role: Role; from: number; admin: boolean };

// A push socket's attachment: its idx (also its tag) and the hash of the
// token that opened it. `gone` marks a socket this object closed —
// getWebSockets keeps it until the far end answers, and it must receive
// nothing more.
type SocketAtt = { idx: number; hash: string; gone?: true };
const tagOf = (idx: number) => `idx:${idx}`;

export class PeerRoom extends DurableObject<PeerEnv> {
  constructor(ctx: DurableObjectState, env: PeerEnv) {
    super(ctx, env);
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair(PING, PONG));
    // Only a created room gets tables: a request naming an id nobody created
    // reads, and writes nothing.
    if (this.created()) this.ensureSchema();
  }

  private ensureSchema(): void {
    const sql = this.ctx.storage.sql;
    // add_by: the room's `add` setting, kept from its creation. next_seq is
    // a counter, not max(seq): the alarm may empty the log, and a number
    // handed out once is never reused.
    sql.exec(
      "CREATE TABLE IF NOT EXISTS room (" +
        "one INTEGER PRIMARY KEY CHECK (one = 1), owner TEXT NOT NULL, created INTEGER NOT NULL, add_by TEXT NOT NULL, " +
        "membership INTEGER NOT NULL DEFAULT 0, next_seq INTEGER NOT NULL DEFAULT 0)",
    );
    // A member row is never deleted, so max(idx) + 1 is never an idx that was
    // handed out. `revoked` is when the idx was removed or left.
    sql.exec("CREATE TABLE IF NOT EXISTS members (idx INTEGER PRIMARY KEY, role TEXT NOT NULL, from_seq INTEGER NOT NULL, created INTEGER NOT NULL, revoked INTEGER)");
    // hash: SHA-256 hex of the token. A revoked idx keeps its tokens' rows, so
    // they answer `revoked` rather than `bad_token`.
    sql.exec("CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, idx INTEGER NOT NULL, admin INTEGER NOT NULL, created INTEGER NOT NULL)");
    sql.exec("CREATE TABLE IF NOT EXISTS records (seq INTEGER PRIMARY KEY, idx INTEGER NOT NULL, type TEXT NOT NULL, body TEXT NOT NULL, at INTEGER NOT NULL)");
    sql.exec("CREATE INDEX IF NOT EXISTS records_by_at ON records (at)");
  }

  private created(): boolean {
    const sql = this.ctx.storage.sql;
    if (sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'room'").toArray().length === 0) return false;
    return sql.exec("SELECT 1 FROM room").toArray().length > 0;
  }

  private room(): { add: Add; membership: number; next: number } {
    const row = this.ctx.storage.sql.exec<{ add_by: Add; membership: number; next_seq: number }>("SELECT add_by, membership, next_seq FROM room").one();
    return { add: row.add_by, membership: Number(row.membership), next: Number(row.next_seq) };
  }

  // The member a token hash opens. Found through the primary key, not
  // compared in constant time against every row as PeerChannel's two tokens
  // are: a room holds a token per member and per grant, and what a lookup's
  // timing could tell is a prefix of a stored digest, which leads to no
  // token — that takes a preimage of SHA-256.
  private caller(hash: string): Caller | Refusal {
    const row = this.ctx.storage.sql
      .exec<{ idx: number; admin: number; role: Role; from_seq: number; revoked: number | null }>(
        "SELECT t.idx, t.admin, m.role, m.from_seq, m.revoked FROM tokens t JOIN members m ON m.idx = t.idx WHERE t.hash = ?",
        hash,
      )
      .toArray()[0];
    if (!row) return BAD_TOKEN;
    if (row.revoked !== null) return REVOKED;
    return { idx: Number(row.idx), role: row.role, from: Number(row.from_seq), admin: Number(row.admin) === 1 };
  }

  private member(idx: number): { role: Role; revoked: boolean } | null {
    const row = this.ctx.storage.sql.exec<{ role: Role; revoked: number | null }>("SELECT role, revoked FROM members WHERE idx = ?", idx).toArray()[0];
    return row ? { role: row.role, revoked: row.revoked !== null } : null;
  }

  private bumpMembership(): number {
    return Number(this.ctx.storage.sql.exec<{ m: number }>("UPDATE room SET membership = membership + 1 RETURNING membership AS m").one().m);
  }

  // Arms the retention alarm when none is: every record is younger than the
  // one an armed alarm is waiting for.
  private async armAlarm(at: number): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(at + RETENTION_MS + 1);
  }

  // POST /peer/rooms, after the Worker checked the owner login: the creator
  // is idx 0, a `write` member from 0, and its token is admin.
  async create(owner: string, add: Add, adminHash: string): Promise<{ membership: number } | Refusal> {
    // 128 random bits: a collision is a broken random source, not a client error.
    if (this.created()) return refusal(500, "internal_error", "the minted room id is taken; nothing was created");
    this.ensureSchema();
    const now = Date.now();
    const sql = this.ctx.storage.sql;
    this.ctx.storage.transactionSync(() => {
      sql.exec("INSERT INTO room (one, owner, created, add_by) VALUES (1, ?, ?, ?)", owner, now, add);
      sql.exec("INSERT INTO members (idx, role, from_seq, created) VALUES (0, 'write', 0, ?)", now);
      sql.exec("INSERT INTO tokens (hash, idx, admin, created) VALUES (?, 0, 1, ?)", adminHash, now);
    });
    return { membership: 0 };
  }

  // POST /peer/r/<id>/members: a new idx reading from the log head. An admin
  // token mints; under `add: members` so does any `write` member's.
  async mint(hash: string, role: Role, tokenHash: string): Promise<{ idx: number; from: number; membership: number } | Refusal> {
    if (!this.created()) return NO_SUCH_ROOM;
    const caller = this.caller(hash);
    if ("refused" in caller) return caller;
    const room = this.room();
    if (!caller.admin && !(room.add === "members" && caller.role === "write")) return NOT_ADMIN;
    const sql = this.ctx.storage.sql;
    const idx = Number(sql.exec<{ n: number }>("SELECT max(idx) + 1 AS n FROM members").one().n);
    if (idx > IDX_MAX) return refusal(413, "too_large", `a room holds at most ${IDX_MAX + 1} members, removed ones included`);
    const now = Date.now();
    const membership = this.ctx.storage.transactionSync(() => {
      sql.exec("INSERT INTO members (idx, role, from_seq, created) VALUES (?, ?, ?, ?)", idx, role, room.next, now);
      sql.exec("INSERT INTO tokens (hash, idx, admin, created) VALUES (?, ?, 0, ?)", tokenHash, idx, now);
      return this.bumpMembership();
    });
    return { idx, from: room.next, membership };
  }

  // DELETE /peer/r/<id>/members/<idx> (an admin token) or …/members/self
  // (`target` null, any member's token): every token on the idx stops
  // opening the room. Revoking an idx already revoked changes nothing and
  // answers the current version, so a retried removal is safe.
  async revoke(hash: string, target: number | null): Promise<{ membership: number } | Refusal> {
    if (!this.created()) return NO_SUCH_ROOM;
    const caller = this.caller(hash);
    if ("refused" in caller) return caller;
    let idx = caller.idx;
    if (target !== null) {
      if (!caller.admin) return NOT_ADMIN;
      const member = this.member(target);
      if (member === null) return NO_SUCH_MEMBER;
      if (member.revoked) return { membership: this.room().membership };
      idx = target;
    }
    const sql = this.ctx.storage.sql;
    const membership = this.ctx.storage.transactionSync(() => {
      sql.exec("UPDATE members SET revoked = ? WHERE idx = ?", Date.now(), idx);
      return this.bumpMembership();
    });
    for (const ws of this.ctx.getWebSockets(tagOf(idx))) this.closeAs(ws, CLOSE_BAD_TOKEN, "revoked");
    return { membership };
  }

  // GET /peer/r/<id>/members: every idx ever minted, for an admin token.
  // `admin` is whether any token on the idx carries the flag.
  async members(hash: string): Promise<{ membership: number; members: Member[] } | Refusal> {
    if (!this.created()) return NO_SUCH_ROOM;
    const caller = this.caller(hash);
    if ("refused" in caller) return caller;
    if (!caller.admin) return NOT_ADMIN;
    const rows = this.ctx.storage.sql
      .exec<{ idx: number; role: Role; from_seq: number; revoked: number | null; admin: number }>(
        "SELECT m.idx, m.role, m.from_seq, m.revoked, EXISTS (SELECT 1 FROM tokens t WHERE t.idx = m.idx AND t.admin = 1) AS admin FROM members m ORDER BY m.idx",
      )
      .toArray();
    return {
      membership: this.room().membership,
      members: rows.map((r) => ({ idx: Number(r.idx), role: r.role, from: Number(r.from_seq), admin: Number(r.admin) === 1, revoked: r.revoked !== null })),
    };
  }

  // POST /peer/r/<id>/admin: a new admin-flagged token for a live `write` idx.
  async grantAdmin(hash: string, idx: number, tokenHash: string): Promise<{ membership: number } | Refusal> {
    if (!this.created()) return NO_SUCH_ROOM;
    const caller = this.caller(hash);
    if ("refused" in caller) return caller;
    if (!caller.admin) return NOT_ADMIN;
    const member = this.member(idx);
    if (member === null || member.revoked) return NO_SUCH_MEMBER;
    if (member.role !== "write") return refusal(403, "read_only", "admin goes to a write member; this idx reads only");
    const sql = this.ctx.storage.sql;
    const membership = this.ctx.storage.transactionSync(() => {
      sql.exec("INSERT INTO tokens (hash, idx, admin, created) VALUES (?, ?, 1, ?)", tokenHash, idx, Date.now());
      return this.bumpMembership();
    });
    return { membership };
  }

  // POST /peer/r/<id>/records. The Worker checked type and body. `membership`
  // is the version the record was sealed against.
  async put(hash: string, type: string, body: string, membership: number, bump: boolean): Promise<{ seq: number; membership: number } | Refusal> {
    if (!this.created()) return NO_SUCH_ROOM;
    const caller = this.caller(hash);
    if ("refused" in caller) return caller;
    if (caller.role !== "write") return refusal(403, "read_only", "a read member puts nothing");
    if (bump && !caller.admin) return refusal(403, "read_only", "bump takes an admin token");
    const room = this.room();
    if (membership < room.membership)
      return refusal(409, "stale_membership", `the room's membership is ${room.membership}, past the ${membership} this record was sealed for: fold the roster, seal again, put again`);
    if (membership > room.membership) return refusal(400, "bad_request", `the room's membership is ${room.membership}; no record is sealed for ${membership}`);
    const sql = this.ctx.storage.sql;
    const at = Date.now();
    // The counters move first and the row lands last, in one transaction: a
    // record that fails to land takes its number and its bump back with it.
    const landed = this.ctx.storage.transactionSync(() => {
      const seq = Number(sql.exec<{ n: number }>("SELECT next_seq AS n FROM room").one().n);
      const m = Number(
        sql.exec<{ m: number }>("UPDATE room SET next_seq = ?, membership = membership + ? RETURNING membership AS m", seq + 1, bump ? 1 : 0).one().m,
      );
      sql.exec("INSERT INTO records (seq, idx, type, body, at) VALUES (?, ?, ?, ?, ?)", seq, caller.idx, type, body, at);
      return { seq, membership: m };
    });
    // Stored first, sent after: the output gate holds the frames until the row
    // is durable, so a frame never names a row a pull cannot read.
    this.push(caller.idx, { seq: landed.seq, idx: caller.idx, type, body, at });
    await this.armAlarm(at);
    return landed;
  }

  // GET /peer/r/<id>/records?after=<n>: other members' records, seq > after,
  // none below the caller's `from`, ascending; at most PULL_MAX records and
  // PULL_BYTES_MAX of body, and always one when any qualifies.
  async pull(hash: string, after: number): Promise<{ membership: number; records: RoomRecord[] } | Refusal> {
    if (!this.created()) return NO_SUCH_ROOM;
    const caller = this.caller(hash);
    if ("refused" in caller) return caller;
    return { membership: this.room().membership, records: this.page(caller.from, after, caller.idx) };
  }

  // GET /peer/r/<id>/state?after=<n>: the room as this object holds it, for
  // any member's token (the header's State), with one page of the log from
  // the caller's `from` — every idx's records, the caller's own included.
  async state(hash: string, after: number): Promise<RoomState | Refusal> {
    if (!this.created()) return NO_SUCH_ROOM;
    const caller = this.caller(hash);
    if ("refused" in caller) return caller;
    const sql = this.ctx.storage.sql;
    const row = sql
      .exec<{ created: number; add_by: Add; membership: number; next_seq: number }>("SELECT created, add_by, membership, next_seq FROM room")
      .one();
    const held = sql
      .exec<{ n: number; first: number | null; oldest: number | null }>("SELECT count(*) AS n, min(seq) AS first, min(at) AS oldest FROM records WHERE seq >= ?", caller.from)
      .one();
    const records = this.page(caller.from, after, null);
    const sockets = this.open(tagOf(caller.idx)).length;
    const oldest = held.oldest === null ? null : Number(held.oldest);
    // The alarm is armed for the room's oldest record, which may lie below
    // the caller's from; answered as it is, its every re-arm would time a
    // record the caller cannot read. So it is answered as it concerns the
    // caller's view: when the relay next drops one of the caller's records.
    const armed = await this.ctx.storage.getAlarm();
    const alarm = armed === null || oldest === null ? null : Math.max(armed, oldest + RETENTION_MS + 1);
    return {
      room: { created: Number(row.created), add: row.add_by, membership: Number(row.membership), next: Number(row.next_seq), retention: RETENTION_MS, alarm },
      you: { idx: caller.idx, role: caller.role, from: caller.from, admin: caller.admin, sockets },
      log: { count: Number(held.n), first: held.first === null ? null : Number(held.first), oldest },
      records,
    };
  }

  // One page of the log: seq > after and >= from, ascending, without `skip`'s
  // records (null skips none); at most PULL_MAX records and PULL_BYTES_MAX of
  // body, and always one when any qualifies.
  private page(from: number, after: number, skip: number | null): RoomRecord[] {
    const sql = this.ctx.storage.sql;
    const floor = Math.max(after + 1, from);
    // No idx is -1: `idx != -1` keeps every writer's records.
    const not = skip ?? -1;
    // Sizes first, so a page of large bodies is never read whole into memory.
    const sizes = sql
      .exec<{ seq: number; n: number }>("SELECT seq, length(body) AS n FROM records WHERE seq >= ? AND idx != ? ORDER BY seq LIMIT ?", floor, not, PULL_MAX)
      .toArray();
    let last: number | null = null;
    let budget = PULL_BYTES_MAX;
    for (const row of sizes) {
      budget -= row.n;
      if (budget < 0 && last !== null) break;
      last = Number(row.seq);
    }
    if (last === null) return [];
    return sql
      .exec<RoomRecord>("SELECT seq, idx, type, body, at FROM records WHERE seq >= ? AND seq <= ? AND idx != ? ORDER BY seq", floor, last, not)
      .toArray()
      .map((r) => ({ seq: Number(r.seq), idx: Number(r.idx), type: r.type, body: r.body, at: Number(r.at) }));
  }

  // The push upgrade on GET /peer/r/<id>/records, after the Worker hashed the
  // bearer token (`x-peer-hash`): refused as the pull refuses, or a 101. The
  // socket is tagged by its idx and carries nothing but the idx and the hash.
  async fetch(req: Request): Promise<Response> {
    if (!this.created()) return refused(NO_SUCH_ROOM);
    const hash = req.headers.get("x-peer-hash") ?? "";
    const caller = this.caller(hash);
    if ("refused" in caller) return refused(caller);
    // No await from the count to the accept: two upgrades cannot both take the last place.
    const held = this.open(tagOf(caller.idx)).length;
    if (held >= SOCKETS_PER_IDX)
      return fail(429, "too_many_sockets", `this member already holds ${held} sockets on this room; the cap is ${SOCKETS_PER_IDX}`);
    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, [tagOf(caller.idx)]);
    server.serializeAttachment({ idx: caller.idx, hash } satisfies SocketAtt);
    return new Response(null, { status: 101, webSocket: client });
  }

  // A client frame the runtime did not answer (anything but PING). The relay
  // reads nothing from a socket; the frame is only the moment to check that
  // the socket's token still opens a live member of a room that exists.
  async webSocketMessage(ws: WebSocket): Promise<void> {
    const att = ws.deserializeAttachment() as SocketAtt | null;
    if (att === null || att.gone) return;
    if (!this.created()) return this.closeAs(ws, CLOSE_NO_SUCH_CHANNEL, "no_such_room");
    const caller = this.caller(att.hash);
    if ("refused" in caller) return this.closeAs(ws, CLOSE_BAD_TOKEN, caller.refused.code);
  }

  // The runtime does not answer a client's close frame for a hibernated
  // socket; echoing it completes the handshake (as PeerChannel).
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

  // One frame per record, the row a pull answers, to every idx but the
  // writer's. A socket that cannot take it never fails the put: its client
  // reads the row on its next pull.
  private push(from: number, row: RoomRecord): void {
    const frame = JSON.stringify(row);
    for (const ws of this.open()) {
      if ((ws.deserializeAttachment() as SocketAtt).idx === from) continue;
      try {
        ws.send(frame);
      } catch {
        // gone between the listing and the send
      }
    }
  }

  // The sockets (of one tag, or all) that are OPEN and not closed by this
  // object (getWebSockets keeps CLOSING sockets).
  private open(tag?: string): WebSocket[] {
    return this.ctx.getWebSockets(tag).filter((ws) => {
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

  // Retention: records put more than RETENTION_MS ago go, and the alarm is
  // set again for the oldest left. Members and tokens stay with the room.
  async alarm(): Promise<void> {
    if (!this.created()) return;
    const sql = this.ctx.storage.sql;
    sql.exec("DELETE FROM records WHERE at < ?", Date.now() - RETENTION_MS);
    const oldest = sql.exec<{ at: number | null }>("SELECT min(at) AS at FROM records").one().at;
    if (oldest !== null) await this.ctx.storage.setAlarm(Number(oldest) + RETENTION_MS + 1);
  }
}

// --- the routes (/peer/rooms, /peer/r/<id>, /peer/f/<id>) ---

const FEED_LANDING = `peer — a link to an end-to-end encrypted feed

Someone sent you this link so that your agent can follow a peer feed. Follow
it with the peer CLI, passing the WHOLE link, the part after '#' included:

  peer room follow '<the link>'

The part after '#' carries the feed's read token and keys; a browser never
sends it to this server. This relay stores only ciphertext and cannot read
what passes through it.
`;

const noSuchRoom = () => refused(NO_SUCH_ROOM);
const badToken = () => refused(BAD_TOKEN);

// Called by handlePeer for `route` = parts after `peer`, its first part one
// of rooms, r, f; the limiter has already counted the request.
export async function roomRoutes(
  req: Request,
  env: PeerEnv,
  route: string[],
  ownerOf: (req: Request) => Promise<string | null>,
): Promise<Response> {
  if (route.length === 1 && route[0] === "rooms") {
    if (req.method !== "POST") return methodNotAllowed();
    const owner = await ownerOf(req);
    if (owner === null) return fail(401, "bad_token", "opening a room takes the owner login: Bearer <user>:<token>");
    // The body is optional: none, or {}, opens an `add: admins` room.
    const text = await readCapped(req, SMALL_REQUEST_MAX);
    if (text === null) return fail(413, "too_large", `request body over ${SMALL_REQUEST_MAX} bytes`);
    let add: unknown = "admins";
    if (text.trim() !== "") {
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        return badRequest("the body is not JSON");
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) return badRequest("the body is a JSON object");
      add = (body as Record<string, unknown>).add ?? "admins";
    }
    if (typeof add !== "string" || !(ADD_SETTINGS as readonly string[]).includes(add)) return badRequest(`add is one of ${ADD_SETTINGS.join(", ")}`);
    const id = mintChannelId();
    const adminToken = mintToken();
    const made = await env.PEER_ROOM.getByName(roomName(id)).create(owner, add as Add, await sha256Hex(adminToken));
    if ("refused" in made) return refused(made);
    return answer({ id, adminToken, membership: made.membership });
  }

  if (route.length === 2 && route[0] === "f") {
    if (req.method !== "GET" && req.method !== "HEAD") return methodNotAllowed();
    if (!ROOM_ID_RE.test(route[1]!)) return noSuchRoom();
    return new Response(req.method === "HEAD" ? null : FEED_LANDING, {
      headers: { "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" },
    });
  }

  if (route.length < 3 || route[0] !== "r") return fail(404, "no_such_route", "no such route");
  const id = route[1]!;
  if (!ROOM_ID_RE.test(id)) return noSuchRoom();
  const room = env.PEER_ROOM.getByName(roomName(id));
  const op = route.slice(2);

  if (op.length === 1 && op[0] === "members") {
    if (req.method !== "POST" && req.method !== "GET") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    if (req.method === "GET") {
      const listed = await room.members(hash);
      return "refused" in listed ? refused(listed) : answer(listed);
    }
    const body = await readObject(req, SMALL_REQUEST_MAX);
    if (body instanceof Response) return body;
    const role = body.role;
    if (typeof role !== "string" || !(ROLES as readonly string[]).includes(role)) return badRequest(`role is one of ${ROLES.join(", ")}`);
    const token = mintToken();
    const minted = await room.mint(hash, role as Role, await sha256Hex(token));
    if ("refused" in minted) return refused(minted);
    return answer({ idx: minted.idx, token, from: minted.from, membership: minted.membership });
  }

  if (op.length === 2 && op[0] === "members") {
    if (req.method !== "DELETE") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    let target: number | null = null;
    if (op[1] !== "self") {
      if (!IDX_RE.test(op[1]!) || Number(op[1]) > IDX_MAX) return refused(NO_SUCH_MEMBER);
      target = Number(op[1]);
    }
    const revoked = await room.revoke(hash, target);
    return "refused" in revoked ? refused(revoked) : answer(revoked);
  }

  if (op.length === 1 && op[0] === "admin") {
    if (req.method !== "POST") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    const body = await readObject(req, SMALL_REQUEST_MAX);
    if (body instanceof Response) return body;
    const idx = body.idx;
    if (typeof idx !== "number" || !Number.isInteger(idx) || idx < 0 || idx > IDX_MAX) return badRequest(`idx is a member's index, 0 to ${IDX_MAX}`);
    const token = mintToken();
    const granted = await room.grantAdmin(hash, idx, await sha256Hex(token));
    if ("refused" in granted) return refused(granted);
    return answer({ token, membership: granted.membership });
  }

  if (op.length === 1 && op[0] === "records") {
    if (req.method !== "POST" && req.method !== "GET") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    if (req.method === "GET" && req.headers.get("upgrade")?.toLowerCase() === "websocket")
      return room.fetch(new Request("https://peer/push", { headers: { upgrade: "websocket", "x-peer-hash": hash } }));
    if (req.method === "GET") {
      const after = afterOf(req);
      if (after instanceof Response) return after;
      const pulled = await room.pull(hash, after);
      return "refused" in pulled ? refused(pulled) : answer(pulled);
    }
    // The largest record's base64 plus its JSON frame.
    const body = await readObject(req, 4 * Math.ceil(BODY_MAX / 3) + 4096);
    if (body instanceof Response) return body;
    const { type, body: data, membership, bump } = body;
    if (typeof type !== "string" || !(RECORD_TYPES as readonly string[]).includes(type)) return badRequest(`type is one of ${RECORD_TYPES.join(", ")}`);
    if (typeof data !== "string") return badRequest("body is a standard base64 string");
    const n = decodedLength(data);
    if (n === null || n === 0) return badRequest("body is non-empty standard base64 with padding");
    if (n > BODY_MAX) return fail(413, "too_large", `a record's body is at most ${BODY_MAX} bytes decoded`);
    if (typeof membership !== "number" || !Number.isSafeInteger(membership) || membership < 0)
      return badRequest("membership is the room's membership version the record was sealed for, a whole number");
    if (bump !== undefined && typeof bump !== "boolean") return badRequest("bump is true or absent");
    const landed = await room.put(hash, type, data, membership, bump === true);
    return "refused" in landed ? refused(landed) : answer(landed);
  }

  if (op.length === 1 && op[0] === "state") {
    if (req.method !== "GET") return methodNotAllowed();
    const hash = await bearerHash(req);
    if (hash === null) return badToken();
    const after = afterOf(req);
    if (after instanceof Response) return after;
    const state = await room.state(hash, after);
    return "refused" in state ? refused(state) : answer(state);
  }

  return fail(404, "no_such_route", "no such route");
}

// A log read's `after`: omitted it is -1, the whole view.
function afterOf(req: Request): number | Response {
  const raw = new URL(req.url).searchParams.get("after");
  if (raw !== null && !AFTER_RE.test(raw)) return badRequest("after is a whole number, -1 or more");
  const after = raw === null ? -1 : Number(raw);
  if (after < -1) return badRequest("after is a whole number, -1 or more");
  return after;
}
