/**
 * PeerFeed — a party's live reader feed: one Durable Object per party id,
 * named `feed/<party id>`, where the party's hosts (sources) and its reader
 * pages (viewers) meet over WebSockets. It stores no record and no key: the
 * only row is the party's signed config, which holds hashes alone — the
 * source secret's and each reader token's.
 *
 * A socket is accepted on upgrade and must say who it is in its first text
 * frame within HELLO_MS:
 *   source  {"hello":"source","secret":"<source secret>","host":"<name>"}
 *   viewer  {"hello":"viewer","token":"<reader token>","key":"x25519:…"?}
 * answered {"ok":true,"sources":<n>}, or closed CLOSE_BAD_TOKEN.
 * Then:
 *   source {"rec":…,"n":k}            → every viewer {"rec":…}; the source {"ack":k}
 *   viewer joins                       → every source {"replay":{"viewer","reader","key"?}}
 *   source {"rec":…,"to":"<viewer>"}  → that viewer alone, bytes unchanged
 *   source {"replay_done":"<viewer>","readers":[…]} → that viewer alone, bytes unchanged
 * A broadcast rec's string body is cut at BODY_CUT bytes with "truncated":true.
 * `ping` is answered `pong` by the runtime, as on the relay.
 *
 * The role is known only from the hello, after the accept has fixed a
 * socket's tags, so a socket is tagged `s:<id>` alone and its role, host,
 * reader hash and key live in its attachment.
 *
 * The routes (handleFeed, behind PEER_HITS as every /peer route):
 *   GET /feed/<party id>           + Upgrade: websocket → the Object
 *   PUT /feed/<party id>/config    the signed config (src/sign.ts) → {ok, at, readers}
 *   GET /feed/<party id>/config    signed over X-Peer-At → the config held, hashes only
 */

import { DurableObject } from "cloudflare:workers";
import { CLOSE_BAD_TOKEN, PING, PONG, sha256Hex } from "./relay/channel";
import { type FeedConfig, PARTY_RE, signedConfig, signedRead } from "./sign";

export interface FeedEnv {
  PEER_FEED: DurableObjectNamespace<PeerFeed>;
  PEER_HITS: RateLimit;
}

// A signed config is one JSON object of hashes: 64 readers fit in a few KiB.
export const CONFIG_MAX = 16 * 1024;

const fail = (status: number, code: string, error: string) =>
  new Response(JSON.stringify({ error, code }, null, 2) + "\n", {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
  });
const answer = (data: unknown) =>
  new Response(JSON.stringify(data, null, 2) + "\n", { headers: { "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" } });

// `parts` is the path split: ["feed", <party id>] or ["feed", <party id>, "config"].
export async function handleFeed(req: Request, env: FeedEnv, parts: string[]): Promise<Response> {
  const party = parts[1];
  if (party === undefined || !PARTY_RE.test(party) || parts.length > 3 || (parts.length === 3 && parts[2] !== "config"))
    return fail(404, "no_such_route", "the feed routes are /feed/<party id> and /feed/<party id>/config");
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  if (!(await env.PEER_HITS.limit({ key: ip })).success) return fail(429, "rate_limited", "too many requests from this address; retry in a few seconds");
  const feed = env.PEER_FEED.getByName(feedName(party));
  if (parts.length === 2) {
    if (req.method !== "GET") return fail(405, "method_not_allowed", "GET with Upgrade: websocket");
    if (req.headers.get("upgrade")?.toLowerCase() !== "websocket") return fail(426, "upgrade_required", "the feed is a WebSocket: GET with Upgrade: websocket");
    return feed.fetch(req);
  }
  const sig = req.headers.get("x-peer-signature");
  if (req.method === "PUT") {
    const body = new Uint8Array(await req.arrayBuffer());
    if (body.length > CONFIG_MAX) return fail(413, "too_large", "a feed config is one JSON object of hashes");
    const c = await signedConfig(party, body, sig);
    if ("status" in c) return fail(c.status, c.code, c.error);
    const put = await feed.putConfig(c);
    if ("refused" in put) return fail(409, "stale", put.refused);
    return answer({ ok: true, at: c.at, readers: c.readers.length });
  }
  if (req.method === "GET") {
    const refused = await signedRead(party, req.headers.get("x-peer-at"), sig);
    if (refused !== null) return fail(refused.status, refused.code, refused.error);
    const c = await feed.config();
    if (c === null) return fail(404, "no_config", "this party has no feed config yet");
    return answer(c);
  }
  return fail(405, "method_not_allowed", "PUT or GET");
}

export const HELLO_MS = 5_000;
export const BODY_CUT = 60_000;
export const FRAME_MAX = 512 * 1024;
export const SOURCES_MAX = 16;
export const VIEWERS_MAX = 64;
const KEY_RE = /^x25519:[A-Za-z0-9_-]{43}$/;
const HOST_RE = /^[A-Za-z0-9._-]{1,64}$/;

type Att =
  | { role: "pending"; id: string; born: number }
  | { role: "source"; id: string; host: string; hash: string }
  | { role: "viewer"; id: string; reader: string; key?: string };

export const feedName = (party: string) => `feed/${party}`;

const enc = new TextEncoder();

// A string cut to at most `max` UTF-8 bytes, never inside a character.
export function cutUtf8(s: string, max: number): string {
  const b = enc.encode(s);
  if (b.length <= max) return s;
  let end = max;
  while (end > 0 && (b[end]! & 0xc0) === 0x80) end--;
  return new TextDecoder().decode(b.subarray(0, end));
}

export class PeerFeed extends DurableObject<FeedEnv> {
  constructor(ctx: DurableObjectState, env: FeedEnv) {
    super(ctx, env);
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair(PING, PONG));
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS config (k INTEGER PRIMARY KEY CHECK (k = 1), party TEXT NOT NULL, source TEXT NOT NULL, readers TEXT NOT NULL, at TEXT NOT NULL)",
    );
  }

  config(): FeedConfig | null {
    const row = this.ctx.storage.sql.exec<{ party: string; source: string; readers: string; at: string }>("SELECT party, source, readers, at FROM config").toArray()[0];
    return row ? { v: 1, party: row.party, at: row.at, source: row.source, readers: JSON.parse(row.readers) } : null;
  }

  // A verified config (src/sign.ts) stored when it is newer than the one held;
  // a socket the new one no longer admits is closed.
  async putConfig(c: FeedConfig): Promise<{ ok: true } | { refused: string }> {
    const held = this.config();
    if (held !== null && Date.parse(c.at) <= Date.parse(held.at)) return { refused: "an equal or newer config is held" };
    this.ctx.storage.sql.exec(
      "INSERT INTO config (k, party, source, readers, at) VALUES (1, ?, ?, ?, ?) ON CONFLICT (k) DO UPDATE SET party = excluded.party, source = excluded.source, readers = excluded.readers, at = excluded.at",
      c.party,
      c.source,
      JSON.stringify(c.readers),
      c.at,
    );
    for (const [ws, att] of this.open()) {
      if (att.role === "source" && att.hash !== c.source) this.closeAs(ws, CLOSE_BAD_TOKEN, "bad_token");
      if (att.role === "viewer" && !c.readers.includes(att.reader)) this.closeAs(ws, CLOSE_BAD_TOKEN, "bad_token");
    }
    return { ok: true };
  }

  async fetch(req: Request): Promise<Response> {
    if (req.headers.get("upgrade")?.toLowerCase() !== "websocket") return new Response("upgrade required", { status: 426 });
    const id = [...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(16).padStart(2, "0")).join("");
    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, [`s:${id}`]);
    server.serializeAttachment({ role: "pending", id, born: Date.now() } satisfies Att);
    const alarm = await this.ctx.storage.getAlarm();
    if (alarm === null) await this.ctx.storage.setAlarm(Date.now() + HELLO_MS);
    return new Response(null, { status: 101, webSocket: client });
  }

  // Every socket still without a hello past HELLO_MS is closed.
  async alarm(): Promise<void> {
    const now = Date.now();
    let next = Infinity;
    for (const [ws, att] of this.open()) {
      if (att.role !== "pending") continue;
      if (now - att.born >= HELLO_MS) this.closeAs(ws, CLOSE_BAD_TOKEN, "no_hello");
      else next = Math.min(next, att.born + HELLO_MS);
    }
    if (next !== Infinity) await this.ctx.storage.setAlarm(next);
  }

  async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer): Promise<void> {
    const att = ws.deserializeAttachment() as Att | null;
    if (att === null) return;
    if (typeof msg !== "string" || msg.length > FRAME_MAX) return this.closeAs(ws, 1009, "text frames under 512 KiB");
    let m: Record<string, unknown>;
    try {
      m = JSON.parse(msg);
    } catch {
      return this.closeAs(ws, 1007, "not JSON");
    }
    if (att.role === "pending") return this.hello(ws, att.id, m);
    if (att.role === "source") return this.fromSource(ws, msg, m);
    // A viewer only listens.
  }

  private async hello(ws: WebSocket, id: string, m: Record<string, unknown>): Promise<void> {
    const c = this.config();
    const bad = () => this.closeAs(ws, CLOSE_BAD_TOKEN, "bad_token");
    if (c === null) return bad();
    const open = this.open();
    const sources = open.filter(([, a]) => a.role === "source").length;
    if (m.hello === "source") {
      if (typeof m.secret !== "string" || typeof m.host !== "string" || !HOST_RE.test(m.host)) return bad();
      const hash = "sha256:" + (await sha256Hex(m.secret));
      if (hash !== c.source) return bad();
      if (sources >= SOURCES_MAX) return this.closeAs(ws, 4429, "too_many_sources");
      ws.serializeAttachment({ role: "source", id, host: m.host, hash } satisfies Att);
      this.send(ws, { ok: true, sources: sources + 1 });
      return;
    }
    if (m.hello === "viewer") {
      if (typeof m.token !== "string" || (m.key !== undefined && (typeof m.key !== "string" || !KEY_RE.test(m.key)))) return bad();
      const reader = "sha256:" + (await sha256Hex(m.token));
      if (!c.readers.includes(reader)) return bad();
      if (open.filter(([, a]) => a.role === "viewer").length >= VIEWERS_MAX) return this.closeAs(ws, 4429, "too_many_viewers");
      const key = m.key as string | undefined;
      ws.serializeAttachment({ role: "viewer", id, reader, ...(key ? { key } : {}) } satisfies Att);
      this.send(ws, { ok: true, sources });
      const replay = { replay: { viewer: id, reader, ...(key ? { key } : {}) } };
      for (const [s, a] of this.open()) if (a.role === "source") this.send(s, replay);
      return;
    }
    return bad();
  }

  private fromSource(ws: WebSocket, raw: string, m: Record<string, unknown>): void {
    if (typeof m.replay_done === "string") return this.toViewer(m.replay_done, raw);
    if (typeof m.rec !== "object" || m.rec === null) return;
    if (typeof m.to === "string") return this.toViewer(m.to, raw);
    const rec = { ...(m.rec as Record<string, unknown>) };
    if (typeof rec.body === "string" && enc.encode(rec.body).length > BODY_CUT) {
      rec.body = cutUtf8(rec.body, BODY_CUT);
      rec.truncated = true;
    }
    const frame = JSON.stringify({ rec });
    for (const [v, a] of this.open()) if (a.role === "viewer") this.sendRaw(v, frame);
    if (Number.isSafeInteger(m.n)) this.send(ws, { ack: m.n });
  }

  private toViewer(id: string, raw: string): void {
    for (const ws of this.ctx.getWebSockets(`s:${id}`)) {
      const att = ws.deserializeAttachment() as Att | null;
      if (att?.role === "viewer" && ws.readyState === WebSocket.OPEN) this.sendRaw(ws, raw);
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    try {
      ws.close(code === 1005 || code === 1006 || code === 1015 ? 1000 : code, reason);
    } catch {
      // already closed
    }
  }

  async webSocketError(): Promise<void> {}

  private open(): [WebSocket, Att][] {
    const out: [WebSocket, Att][] = [];
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const att = ws.deserializeAttachment() as Att | null;
      if (att !== null) out.push([ws, att]);
    }
    return out;
  }

  private send(ws: WebSocket, data: unknown): void {
    this.sendRaw(ws, JSON.stringify(data));
  }

  private sendRaw(ws: WebSocket, frame: string): void {
    try {
      ws.send(frame);
    } catch {
      // gone between the listing and the send
    }
  }

  private closeAs(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.serializeAttachment(null);
      ws.close(code, reason);
    } catch {
      // already gone
    }
  }
}
