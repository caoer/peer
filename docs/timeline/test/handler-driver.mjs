// handler-driver.mjs — runs docs/timeline/handler.js's request lane under
// node with a stubbed STORE and fetch: config owner-only, the path secret,
// the Telegram payload, dedupe by receipt, the 3,500-character cut, an e2e
// record's text, and 502 with no receipt when Telegram fails.
//
//   node docs/timeline/test/handler-driver.mjs     # exit 0 when every check passes
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const src = await readFile(new URL("../handler.js", import.meta.url), "utf8");
const stub = "class WorkerEntrypoint { constructor(env) { this.env = env; } }";
const code = src.replace(/^import \{ WorkerEntrypoint \} from "cloudflare:workers";$/m, stub);
assert.notEqual(code, src, "handler.js imports WorkerEntrypoint from cloudflare:workers");
const Handler = (await import(`data:text/javascript,${encodeURIComponent(code)}`)).default;

// env.STORE's answers, over a Map.
function store() {
  const rows = new Map();
  const object = (key) => (rows.has(key) ? { key, ...rows.get(key) } : null);
  return {
    rows,
    async get(key) { return { ok: true, object: object(key) }; },
    async getMany(keys) { return { ok: true, objects: Object.fromEntries(keys.map((k) => [k, object(k)])) }; },
    async put(key, value) {
      const version = (rows.get(key)?.version ?? 0) + 1;
      rows.set(key, { value, version, updated_at: "t" });
      return { ok: true, key, version, updated_at: "t" };
    },
    async cas(key, value, expected) {
      const version = rows.get(key)?.version ?? 0;
      if (version !== expected) return { ok: false, code: "version_conflict", version };
      return this.put(key, value);
    },
  };
}

// fetch: each call recorded; the answer is the test's.
let calls = [];
let reply = () => ({ status: 200, json: { ok: true, result: { message_id: 100 + calls.length } } });
globalThis.fetch = async (url, init) => {
  calls.push({ url, body: JSON.parse(init.body) });
  const r = reply();
  if (r instanceof Error) throw r;
  return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.json };
};

const STORE = store();
const h = new Handler({ STORE });
const owner = { slug: "s", identity: { via: "owner", owner: "zitao" }, at: "2026-11-08T00:00:00Z" };
const grant = { slug: "s", identity: { via: "grant", tokens: [{ id: "t1", role: "viewer", expires_at: null }] }, at: owner.at };
const none = { slug: "s", identity: { via: "none" }, at: owner.at };
const SECRET = "A".repeat(20) + "secret_path-0123456789";
const URL_ = "https://page.example/a/s";
const call = (method, path, body, ctx = none) => h.request({ method, path, query: {}, body: body === undefined ? "" : JSON.stringify(body) }, ctx);
const record = (data, extra = {}) => ({ schema: "peer-timeline@1", data: { id: "m1", dir: "in", kind: "text", from: "yujing", to: "zt", at: "2026-11-08T12:00:00Z", body: "hello", ...data }, ...extra });
const results = [];
const check = async (name, fn) => { await fn(); results.push(name); console.log(`ok   ${name}`); };

await check("not configured: 503 before any send", async () => {
  const r = await call("POST", `/peer/${SECRET}`, record({}));
  assert.equal(r.status, 503);
  assert.equal(calls.length, 0);
});

await check("config refused for a grant and for nobody, accepted for the owner", async () => {
  const cfg = { "tg.token": "123:tok", "tg.chat": "-1001", "tg.topic": 77, "forward.path": SECRET, "page.url": URL_ };
  for (const ctx of [grant, none]) {
    const r = await call("PUT", "/config", cfg, ctx);
    assert.equal(r.status, 403);
    assert.equal(r.body.code, "owner_only");
  }
  assert.equal(STORE.rows.size, 0, "a refused config writes nothing");
  assert.equal((await call("PUT", "/config", { "tg.secret": "x" }, owner)).status, 400);
  assert.equal((await call("PUT", "/config", { "forward.path": "short" }, owner)).status, 400);
  const r = await call("PUT", "/config", cfg, owner);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.set, Object.keys(cfg));
  assert.ok(!JSON.stringify(r.body).includes("123:tok"), "the answer carries no value");
});

await check("wrong path secret: 403, nothing sent", async () => {
  for (const p of ["/peer/wrong", `/peer/${SECRET}x`, "/peer/", `/peer/${SECRET.slice(0, -1)}`]) {
    const r = await call("POST", p, record({}));
    assert.equal(r.status, 403, p);
  }
  assert.equal(calls.length, 0);
});

await check("payload: one sendMessage to the chat and topic, header and text", async () => {
  const r = await call("POST", `/peer/${SECRET}`, record({}));
  assert.equal(r.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://api.telegram.org/bot123:tok/sendMessage");
  assert.deepEqual(calls[0].body, { chat_id: "-1001", text: "yujing · text · 2026-11-08T12:00:00Z\nhello", disable_web_page_preview: true, message_thread_id: 77 });
  assert.equal(r.body.message_id, 101);
  assert.deepEqual(STORE.rows.get("fwd.m1").value, { message_id: 101, at: owner.at });
});

await check("dedupe: the same id again answers 200 and sends nothing", async () => {
  const r = await call("POST", `/peer/${SECRET}`, record({ body: "hello again" }));
  assert.equal(r.status, 200);
  assert.equal(r.body.duplicate, true);
  assert.equal(r.body.message_id, 101);
  assert.equal(calls.length, 1);
});

await check("cut: first 3,500 characters (code points) and the page URL", async () => {
  const body = "😀".repeat(3499) + "ab" + "TAIL";
  await call("POST", `/peer/${SECRET}`, record({ id: "m2", body }));
  const text = calls.at(-1).body.text;
  assert.equal(text, `yujing · text · 2026-11-08T12:00:00Z\n${"😀".repeat(3499)}a\n…\n${URL_}`);
  await call("POST", `/peer/${SECRET}`, record({ id: "m3", body: "x".repeat(3500) }));
  assert.equal(calls.at(-1).body.text, `yujing · text · 2026-11-08T12:00:00Z\n${"x".repeat(3500)}`, "3,500 exactly is not cut");
  await call("POST", `/peer/${SECRET}`, record({ id: "m4", body: "short", truncated: true }));
  assert.equal(calls.at(-1).body.text, `yujing · text · 2026-11-08T12:00:00Z\nshort\n…\n${URL_}`, "a sender's truncated flag quotes the URL");
  await call("POST", `/peer/${SECRET}`, record({ id: "m4b", body: "short" }, { truncated: true }));
  assert.ok(calls.at(-1).body.text.endsWith(URL_), "the flag at the top level counts too");
});

await check("e2e record: 「加密消息，在页面解密」 and the URL, never the envelope", async () => {
  const envelope = '{"e2e":1,"suite":"peer-e2e-v1","to":[{"key":"x25519:k","enc":"ZW5j","ct":"Y3Q="}],"body":"U0VDUkVU"}';
  await call("POST", `/peer/${SECRET}`, record({ id: "m5", body: envelope, e2e: true }));
  assert.equal(calls.at(-1).body.text, `yujing · text · 2026-11-08T12:00:00Z\n加密消息，在页面解密\n${URL_}`);
  await call("POST", `/peer/${SECRET}`, record({ id: "m6", body: `  ${envelope}` }));
  assert.equal(calls.at(-1).body.text, `yujing · text · 2026-11-08T12:00:00Z\n加密消息，在页面解密\n${URL_}`, "detected by the body when the flag is absent");
  await call("POST", `/peer/${SECRET}`, record({ id: "m7", body: '{"e2e":2,"suite":"x"}' }));
  assert.ok(calls.at(-1).body.text.endsWith('{"e2e":2,"suite":"x"}'), "e2e other than 1 is plain text");
});

await check("non-text body: the descriptor as JSON", async () => {
  await call("POST", `/peer/${SECRET}`, record({ id: "m8", kind: "file", body: { name: "a.pdf", size: 3, sha256: "ab" } }));
  assert.equal(calls.at(-1).body.text, 'yujing · file · 2026-11-08T12:00:00Z\n{"name":"a.pdf","size":3,"sha256":"ab"}');
});

await check("502 when Telegram fails, no receipt; the retry sends once and stores it", async () => {
  const before = calls.length;
  reply = () => ({ status: 500, json: { ok: false, description: "Internal Server Error" } });
  let r = await call("POST", `/peer/${SECRET}`, record({ id: "m9" }));
  assert.equal(r.status, 502);
  assert.ok(!STORE.rows.has("fwd.m9"));
  reply = () => ({ status: 200, json: { ok: false, description: "Bad Request: chat not found" } });
  r = await call("POST", `/peer/${SECRET}`, record({ id: "m9" }));
  assert.equal(r.status, 502);
  reply = () => new Error("network down");
  r = await call("POST", `/peer/${SECRET}`, record({ id: "m9" }));
  assert.equal(r.status, 502);
  assert.ok(!STORE.rows.has("fwd.m9"));
  reply = () => ({ status: 200, json: { ok: true, result: { message_id: 999 } } });
  r = await call("POST", `/peer/${SECRET}`, record({ id: "m9" }));
  assert.equal(r.status, 200);
  assert.equal(STORE.rows.get("fwd.m9").value.message_id, 999);
  assert.equal(calls.length, before + 4);
  assert.ok(calls.slice(before).every((c) => !JSON.stringify(c.body).includes("network")));
});

await check("bad bodies: 400 and nothing sent; other routes 404/405", async () => {
  const before = calls.length;
  assert.equal((await h.request({ method: "POST", path: `/peer/${SECRET}`, query: {}, body: "not json" }, none)).status, 400);
  assert.equal((await call("POST", `/peer/${SECRET}`, { schema: "other@1", data: {} })).status, 400);
  assert.equal((await call("POST", `/peer/${SECRET}`, record({ id: "a/b" }))).status, 400);
  assert.equal((await call("GET", `/peer/${SECRET}`)).status, 405);
  assert.equal((await call("GET", "/config", undefined, owner)).status, 405);
  assert.equal((await call("GET", "/")).status, 404);
  assert.equal(calls.length, before);
});

await check("fold keeps every inbox event", async () => {
  assert.deepEqual(await h.fold({}, {}, { keys: {}, lists: {} }), { action: "keep" });
});

console.log(`PASS ${results.length} checks`);
