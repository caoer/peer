// handler.js — a peer chat page's forward to Telegram, on the request lane
// (`/h/<slug>`), published beside index.html and
// handler.json {"request":{"private":true,"outbound":["https://api.telegram.org"]}}.
//
// `peer serve` POSTs each received timeline record to the URL in its
// config.json `timelines.<peer>.forward`, which is this lane's
// `/h/<slug>/peer/<path secret>`. The handler sends one Telegram line per
// record to the configured chat and topic, with no agent seat in the path.
//
//   PUT  /config               the owner sets any of the private keys below;
//                              the body is {"<key>": <value>, …}, the answer
//                              names the keys written, never their values
//   POST /peer/<path secret>   the body is the record as the page stores it:
//                              {"schema":"peer-timeline@1","data":{id, dir,
//                              kind, from, to, at, body, e2e?, truncated?}}
//
// The private rows, by app key (the host stores each under `private.`):
//   tg.token      the bot token
//   tg.chat       the chat id
//   tg.topic      the topic's message_thread_id; absent sends to the chat
//   forward.path  the path secret, compared in constant time
//   page.url      the page's share URL, quoted when a line is cut
//   fwd.<id>      {message_id, at}, the receipt: written only after Telegram
//                 accepted the line, so a retried POST of the same id answers
//                 200 and sends nothing
//
// Answers: 200 delivered (or delivered before); 403 wrong path secret;
// 502 Telegram failed, no receipt, so the sender retries; 503 not configured.
// No answer and no thrown message carries a record's text or a secret.
import { WorkerEntrypoint } from "cloudflare:workers";

const SCHEMA = "peer-timeline@1";
const CUT = 3500;
const E2E_LINE = "加密消息，在页面解密";
const CONFIG_KEYS = ["tg.token", "tg.chat", "tg.topic", "forward.path", "page.url"];
const ID = /^[A-Za-z0-9_-]{1,100}$/;
const SUITE = /^[A-Za-z0-9._-]{1,64}$/;

const answer = (status, body) => ({ status, body });
const refuse = (status, code, message) => answer(status, { error: message, code });

// Equal-length digests compared byte by byte with no early exit: the time
// taken says nothing about how much of the secret a guess got right.
async function sameSecret(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([a, b].map(async (s) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))));
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// The protocol's detection rule: a body that, leading whitespace trimmed,
// starts {"e2e": and parses with e2e = 1 and a valid suite is an envelope.
function isEnvelope(body) {
  if (typeof body !== "string") return false;
  const t = body.trimStart();
  if (!t.startsWith('{"e2e":')) return false;
  try {
    const v = JSON.parse(t);
    return v.e2e === 1 && typeof v.suite === "string" && SUITE.test(v.suite);
  } catch {
    return false;
  }
}

// One Telegram line: a header, then the text, cut at CUT characters (code
// points, never half a pair) with the page URL when cut or when the sender
// already cut it; an encrypted record is never quoted, only pointed to.
function lineOf(rec, url) {
  const head = `${rec.from} · ${rec.kind} · ${rec.at}`;
  if (rec.e2e === true || isEnvelope(rec.body)) return `${head}\n${E2E_LINE}\n${url}`;
  const text = typeof rec.body === "string" ? rec.body : JSON.stringify(rec.body);
  const chars = Array.from(text);
  if (chars.length > CUT) return `${head}\n${chars.slice(0, CUT).join("")}\n…\n${url}`;
  if (rec.truncated === true) return `${head}\n${text}\n…\n${url}`;
  return `${head}\n${text}`;
}

export default class extends WorkerEntrypoint {
  // Inbox events on the page are kept as they would be with no handler.
  async fold() {
    return { action: "keep" };
  }

  async request(req, ctx) {
    const { STORE } = this.env;

    if (req.path === "/config") {
      if (req.method !== "PUT") return refuse(405, "method", "PUT only");
      if (ctx.identity.via !== "owner") return refuse(403, "owner_only", "only the page owner sets the config");
      let cfg;
      try { cfg = JSON.parse(req.body); } catch { return refuse(400, "bad_json", "the body is not JSON"); }
      if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) return refuse(400, "bad_config", "the body is an object of config keys");
      const keys = Object.keys(cfg);
      const unknown = keys.filter((k) => !CONFIG_KEYS.includes(k));
      if (!keys.length || unknown.length) return refuse(400, "bad_config", `keys are ${CONFIG_KEYS.join(", ")}`);
      const bad = keys.filter((k) => {
        const v = cfg[k];
        if (k === "tg.topic") return !Number.isSafeInteger(v) || v <= 0;
        if (k === "tg.chat") return !(Number.isSafeInteger(v) || (typeof v === "string" && /^-?[0-9]{1,20}$|^@[A-Za-z0-9_]{5,32}$/.test(v)));
        if (k === "forward.path") return typeof v !== "string" || !/^[A-Za-z0-9_-]{32,128}$/.test(v);
        if (k === "page.url") return typeof v !== "string" || !v.startsWith("https://");
        return typeof v !== "string" || !v;
      });
      if (bad.length) return refuse(400, "bad_config", `invalid: ${bad.join(", ")}`);
      for (const k of keys) {
        const put = await STORE.put(k, cfg[k]);
        if (!put.ok) return refuse(503, put.code, `store refused ${k}`);
      }
      return answer(200, { ok: true, set: keys });
    }

    if (req.path.startsWith("/peer/")) {
      if (req.method !== "POST") return refuse(405, "method", "POST only");
      const got = await STORE.getMany(CONFIG_KEYS);
      if (!got.ok) return refuse(503, got.code, "store unavailable");
      const cfg = Object.fromEntries(CONFIG_KEYS.map((k) => [k, got.objects[k]?.value]));
      if (!cfg["forward.path"] || !cfg["tg.token"] || cfg["tg.chat"] === undefined || !cfg["page.url"])
        return refuse(503, "not_configured", "the forward is not configured");
      if (!(await sameSecret(req.path.slice("/peer/".length), cfg["forward.path"])))
        return refuse(403, "forbidden", "wrong path");

      let env;
      try { env = JSON.parse(req.body); } catch { return refuse(400, "bad_json", "the body is not JSON"); }
      if (!env || env.schema !== SCHEMA || !env.data || typeof env.data !== "object")
        return refuse(400, "bad_record", `the body is a ${SCHEMA} record`);
      const rec = {
        ...env.data,
        e2e: env.data.e2e === true || env.e2e === true,
        truncated: env.data.truncated === true || env.truncated === true,
      };
      if (typeof rec.id !== "string" || !ID.test(rec.id)) return refuse(400, "bad_id", "the record has no valid id");

      const key = `fwd.${rec.id}`;
      const seen = await STORE.get(key);
      if (!seen.ok) return refuse(503, seen.code, "store unavailable");
      if (seen.object) return answer(200, { ok: true, duplicate: true, message_id: seen.object.value.message_id });

      const msg = {
        chat_id: cfg["tg.chat"],
        text: lineOf(rec, cfg["page.url"]),
        disable_web_page_preview: true,
        ...(cfg["tg.topic"] ? { message_thread_id: cfg["tg.topic"] } : {}),
      };
      let sent;
      try {
        const res = await fetch(`https://api.telegram.org/bot${cfg["tg.token"]}/sendMessage`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(msg),
        });
        const out = await res.json().catch(() => null);
        if (!res.ok || !out?.ok || !Number.isSafeInteger(out.result?.message_id))
          return refuse(502, "telegram", `telegram answered ${res.status}${out?.description ? `: ${out.description}` : ""}`);
        sent = out.result.message_id;
      } catch {
        return refuse(502, "telegram", "telegram unreachable");
      }
      // Create-only: two concurrent POSTs of one id that both passed the
      // check above both sent; the second receipt loses the CAS and the
      // answer still names its own line.
      await STORE.cas(key, { message_id: sent, at: ctx.at }, 0);
      return answer(200, { ok: true, message_id: sent });
    }

    return refuse(404, "no_route", "no such route");
  }
}
