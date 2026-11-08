/**
 * POST /forward — one peer-timeline@1 record to the Telegram topic of its
 * counterpart party, sent by `peer serve` (received) and `peer send` (sent).
 *
 * The host names the counterpart party, never a chat: the Worker maps it
 * through the secret FORWARD_TARGETS, `{"<party id>": {"chat": <int>,
 * "topic": <int>}, …}`, and a party the map lacks answers 204 with nothing
 * sent. Authorised by `Bearer <FORWARD_SECRET>`. Nothing is stored: the
 * record passes through this request's memory to one Telegram call.
 */

import { secretMatches } from "./relay/channel";

export interface ForwardEnv {
  FORWARD_SECRET?: string;
  FORWARD_TARGETS?: string;
  TG_BOT_TOKEN?: string;
}

export const READER_URL = "https://peer.0xtau.com/";
export const LINE_BODY_MAX = 3_500;
export const ENCRYPTED_LINE = "加密消息，在页面解密";
export const CUT_MARK = "「…」";
// A forward body is one record, its body cut at 60,000 bytes, plus its
// envelope; JSON escaping can grow the cut body up to sixfold.
const REQUEST_MAX = 512 * 1024;

type Target = { chat: number; topic: number };

// FORWARD_TARGETS parsed once per isolate, keyed on the secret's text so a
// changed secret is parsed again.
let parsed: { raw: string; map: Map<string, Target> } | null = null;

export function targetsOf(raw: string | undefined): Map<string, Target> {
  const text = raw ?? "";
  if (parsed?.raw === text) return parsed.map;
  const map = new Map<string, Target>();
  if (text !== "") {
    const obj = JSON.parse(text) as Record<string, unknown>;
    for (const [party, t] of Object.entries(obj)) {
      const { chat, topic } = (t ?? {}) as Record<string, unknown>;
      if (!Number.isSafeInteger(chat) || !Number.isSafeInteger(topic)) throw new Error(`FORWARD_TARGETS: ${party} needs integer chat and topic`);
      map.set(party, { chat: chat as number, topic: topic as number });
    }
  }
  parsed = { raw: text, map };
  return map;
}

export type TimelineData = {
  id?: string;
  dir?: string;
  kind?: string;
  from?: string;
  to?: string;
  at?: string;
  body?: unknown;
  e2e?: boolean;
  truncated?: boolean;
};

// The Telegram text of one record: `<from> · <kind> · <at>`, then the body
// cut at LINE_BODY_MAX characters (CUT_MARK when cut), then the reader URL.
// An encrypted record carries ENCRYPTED_LINE in place of its body.
export function lineOf(d: TimelineData): string {
  const head = `${d.from ?? "?"} · ${d.kind ?? "?"} · ${d.at ?? "?"}`;
  if (d.e2e) return [head, ENCRYPTED_LINE, READER_URL].join("\n");
  const text = typeof d.body === "string" ? d.body : JSON.stringify(d.body ?? null);
  const chars = Array.from(text);
  const cut = chars.length > LINE_BODY_MAX || d.truncated === true;
  const lines = [head, chars.slice(0, LINE_BODY_MAX).join("")];
  if (cut) lines.push(CUT_MARK);
  lines.push(READER_URL);
  return lines.join("\n");
}

const reply = (status: number, data?: unknown) =>
  new Response(data === undefined ? null : JSON.stringify(data) + "\n", {
    status,
    headers: data === undefined ? {} : { "content-type": "application/json; charset=utf-8" },
  });
const fail = (status: number, code: string, error: string) => reply(status, { error, code });

export async function handleForward(req: Request, env: ForwardEnv): Promise<Response> {
  if (req.method !== "POST") return fail(405, "method_not_allowed", "POST only");
  const secret = env.FORWARD_SECRET ?? "";
  const h = req.headers.get("authorization") ?? "";
  if (secret === "" || !h.startsWith("Bearer ") || !(await secretMatches(h.slice(7).trim(), secret)))
    return fail(401, "bad_token", "forward takes Bearer <forward secret>");
  const raw = await req.text();
  if (raw.length > REQUEST_MAX) return fail(413, "too_large", "a forward body is one record");
  let body: { peer?: unknown; record?: { schema?: unknown; data?: unknown } };
  try {
    body = JSON.parse(raw);
  } catch {
    return fail(400, "bad_request", "body is not JSON");
  }
  if (typeof body?.peer !== "string" || body.record?.schema !== "peer-timeline@1" || typeof body.record.data !== "object" || body.record.data === null)
    return fail(400, "bad_request", 'body is {"peer": "<party id>", "record": {"schema": "peer-timeline@1", "data": {…}}}');
  const target = targetsOf(env.FORWARD_TARGETS).get(body.peer);
  if (target === undefined) return reply(204);
  const tg = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN ?? ""}/sendMessage`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      chat_id: target.chat,
      message_thread_id: target.topic,
      text: lineOf(body.record.data as TimelineData),
      link_preview_options: { is_disabled: true },
    }),
  });
  const answer = (await tg.json().catch(() => null)) as { ok?: boolean; result?: { message_id?: number } } | null;
  if (!tg.ok || answer?.ok !== true || typeof answer.result?.message_id !== "number")
    return fail(502, "telegram_failed", `telegram answered ${tg.status}`);
  return reply(200, { message_id: answer.result.message_id });
}
