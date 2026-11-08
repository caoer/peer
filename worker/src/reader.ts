/**
 * GET / — the Peer Protocol reader, worker/reader/index.html, served as the
 * bytes checked into the repo (docs/protocol.md quotes their sha256). The
 * page's own <meta http-equiv="Content-Security-Policy"> is repeated as the
 * response header, so the policy holds before the parser reaches the meta.
 */

import html from "../reader/index.html";

export const READER_CACHE = "public, max-age=300";

const csp = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i.exec(html)?.[1];
if (csp === undefined) throw new Error("worker/reader/index.html has no Content-Security-Policy meta");
export const READER_CSP: string = csp;

export function handleReader(req: Request): Response {
  if (req.method !== "GET" && req.method !== "HEAD")
    return new Response(JSON.stringify({ error: "GET only", code: "method_not_allowed" }) + "\n", {
      status: 405,
      headers: { "content-type": "application/json; charset=utf-8", allow: "GET, HEAD" },
    });
  return new Response(req.method === "HEAD" ? null : html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": READER_CSP,
      "cache-control": READER_CACHE,
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}
