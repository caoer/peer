/**
 * peer — the peer protocol's own Worker on peer.0xtau.com.
 *
 * /peer/* is the relay: the routes and the PeerChannel and PeerRoom Durable
 * Objects of src/relay/channel.ts and src/relay/room.ts. No D1, no R2:
 * everything a channel or room holds lives in its Object's SQLite.
 *
 * Its owner login is the secret RELAY_LOGIN, `<user>:<token>`: it opens a
 * channel or a room (`Authorization: Bearer <user>:<token>`). Every other
 * route is authorised by the channel's side tokens or the room's member
 * tokens. Unset, nothing can be opened.
 *
 * POST /forward sends one timeline record to its party's Telegram topic
 * (src/forward.ts). GET / is the reader page, worker/reader/index.html
 * (src/reader.ts). `/feed/*` (the reader feed) answers 404 `not_yet` until
 * it is built.
 */

import { PeerChannel, type PeerEnv, handlePeer, secretMatches } from "./relay/channel";
import { PeerRoom } from "./relay/room";
import { type ForwardEnv, handleForward } from "./forward";
import { handleReader } from "./reader";

export { PeerChannel, PeerRoom };

export interface Env extends PeerEnv, ForwardEnv {
  RELAY_LOGIN?: string;
}

const PRIVATE = {
  "cache-control": "private, no-store",
  "referrer-policy": "no-referrer",
  "x-robots-tag": "noindex",
};

const USAGE = `peer relay — store-and-forward for the peer protocol

It holds ciphertext and the parties' cards only; it cannot read a message.
Every route answers JSON; errors are {error, code}.

  POST /peer/channels               open a channel (Bearer <user>:<token>, the
                                    relay's owner login) → {id, hostToken, inviteToken}
  POST /peer/c/<id>/join            spend the invite once {inviteToken} → {guestToken}
  POST /peer/c/<id>/envelopes       put one envelope {type, body} → {dir, seq}
  GET  /peer/c/<id>/envelopes?after=<n>  the other side's envelopes past n
  WS   /peer/c/<id>/envelopes       push: each envelope the other side puts
  PUT  /peer/c/<id>/prekeys         add own one-time prekeys {keys: [{id, pub}]}
  POST /peer/c/<id>/prekeys/take    take one of the other side's → {id, pub} or {}
  POST /peer/c/<id>/blobs           put an attachment's ciphertext (body = the raw
                                    bytes, ≤ 64 MiB) → {blob, size}
  GET  /peer/c/<id>/blobs/<blob>    the bytes of a blob the other side put
  GET  /peer/i/<id>                 an invite link's landing text

  POST /peer/rooms                  open a room (Bearer <user>:<token>, the owner
                                    login) {add?: admins|members} → {id, adminToken, membership}
  POST /peer/r/<id>/members         mint a member {role: write|read} → {idx, token, from, membership}
  GET  /peer/r/<id>/members         every member {idx, role, from, admin, revoked} (admin)
  DELETE /peer/r/<id>/members/<idx> revoke an idx (admin) → {membership}
  DELETE /peer/r/<id>/members/self  leave → {membership}
  POST /peer/r/<id>/admin           an admin token for a write idx {idx} → {token, membership}
  POST /peer/r/<id>/records         put one sealed record {type, body, membership, bump?}
                                    → {seq, membership}; 409 stale_membership
  GET  /peer/r/<id>/records?after=<n>  other members' records past n, from your from
  WS   /peer/r/<id>/records         push: each record another member puts; closed 4401 on revoke
  GET  /peer/r/<id>/state?after=<n>  the room as the relay holds it {room, you, log} and
                                    every member's records past n, yours included, from your from
  GET  /peer/f/<id>                 a feed link's landing text

Every /peer route but the landings and join takes Bearer <side token> or
<member token>; every /peer route counts toward 100 requests per 10 s per
address.
`;

// The owner a `Bearer <user>:<token>` names when it is RELAY_LOGIN, else null.
async function ownerOf(req: Request, env: Env): Promise<string | null> {
  const login = env.RELAY_LOGIN ?? "";
  const colon = login.indexOf(":");
  if (colon <= 0 || colon === login.length - 1) return null;
  const h = req.headers.get("authorization") ?? "";
  if (!h.startsWith("Bearer ")) return null;
  return (await secretMatches(h.slice(7).trim(), login)) ? login.slice(0, colon) : null;
}

const json = (status: number, code: string, error: string) =>
  new Response(JSON.stringify({ error, code }, null, 2) + "\n", {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff", ...PRIVATE },
  });

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts[0] === "forward" && parts.length === 1) {
      try {
        const res = await handleForward(req, env);
        for (const [k, v] of Object.entries(PRIVATE)) res.headers.set(k, v);
        return res;
      } catch (e) {
        return json(500, "internal_error", e instanceof Error ? e.message : "internal error");
      }
    }
    if (parts.length === 0) return handleReader(req);
    if (parts[0] === "feed") return json(404, "not_yet", "not served yet");
    if (parts[0] !== "peer") return json(404, "no_such_route", "no such route");
    if (parts.length === 1)
      return new Response(req.method === "HEAD" ? null : USAGE, { headers: { "content-type": "text/plain; charset=utf-8" } });
    try {
      // Every non-socket answer is private: tokens, ciphertext, or a channel's invite.
      const res = await handlePeer(req, env, parts, (r) => ownerOf(r, env));
      if (res.status === 101) return res;
      const out = new Response(res.body, res);
      for (const [k, v] of Object.entries(PRIVATE)) out.headers.set(k, v);
      return out;
    } catch (e) {
      return json(500, "internal_error", e instanceof Error ? e.message : "internal error");
    }
  },
} satisfies ExportedHandler<Env>;
