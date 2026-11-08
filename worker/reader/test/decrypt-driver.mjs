// decrypt-driver.mjs — drives worker/reader/index.html in headless Chromium
// over CDP. A local server serves the page at http://localhost:<port>/ and a
// stand-in /feed/<party id> socket that speaks the frames docs/protocol.md
// fixes (Reader feed and forward): it records every hello, checks the token,
// replays the fixture records and the card's reader keys, and sends frames
// live. The driver prints each record's line as the page shows it — locked,
// with a wrong secret and with the vector's secret — the key state as the fake
// registers the key, the hellos the feed received, then the page's whole
// request log.
//
//   node worker/reader/test/decrypt-driver.mjs
//
// Exit 0 when every check passes, 1 when one fails, 2 when no browser runs.
// CCC_CHROME names the browser (a wrapper script is how to add --no-sandbox).
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { file, live, me, other, peer, records, replay, truncated, vector } from "./fixtures/records.mjs";

const candidates = [
  process.env.CCC_CHROME,
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  ...["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"].flatMap((name) =>
    (process.env.PATH || "").split(delimiter).filter(Boolean).map((dir) => join(dir, name))),
].filter(Boolean);
const chromePath = candidates.find((p) => existsSync(p));
if (!chromePath) {
  console.error("CANNOT RUN: no Chromium. Set CCC_CHROME=/path/to/chrome.");
  process.exit(2);
}

const html = readFileSync(new URL("../index.html", import.meta.url));

// Every line the page shows that a check reads, as index.html spells it.
const T = {
  badLink: "链接不完整：地址里要有 #p=<主体 id>&t=<读者令牌>",
  waitingHost: "等待主机",
  expired: "链接已失效",
  live: (n) => "已连接 · " + n + " 条消息",
  truncated: "已截断",
  checking: "钥匙在本浏览器里，等待主机核对名片",
  registered: "钥匙已登记到名片",
  pending: "钥匙已生成，等待登记到名片",
  noX25519: "此浏览器不能解密：缺少 X25519（Chrome 133+、Firefox 130+、Safari 17+）",
  newKey: "这是新钥匙",
  imported: "已导入，替换了本浏览器原来的钥匙",
  notSecret: "这不是私钥：私钥以 x25519-secret: 开头，后面还有 43 个字符。",
};
const lockedLine = (n) => "已锁定 · 加密给 " + n + " 把钥匙，本浏览器的钥匙不在其中";
const lockedNoKey = (n) => "已锁定 · 加密给 " + n + " 把钥匙，本浏览器没有钥匙";
const WRONG = "这把钥匙打不开";
const BAD = "无法读取的加密消息";
const DECRYPTED = "已在本机解密";
const MINE = "本浏览器的钥匙";
const EMPTY_WAITING = "主机还没连上。连上以后，它保存的消息会在这里补出来。";
const shortId = (id) => id.slice(0, 12) + "…" + id.slice(-4);
const KEY_RE = /^x25519:[A-Za-z0-9_-]{43}$/;

// PEER_READER_SHOTS=<dir> saves a screenshot of each named state at desktop
// and phone widths, light and dark (ccc-design Pass 2); unset, none is taken.
const shotsDir = process.env.PEER_READER_SHOTS;
if (shotsDir) mkdirSync(shotsDir, { recursive: true });

// --- The fake feed: a party per scenario, each with a token and a source count.

const partyId = () => "ed25519:" + randomBytes(32).toString("base64url");
const tokenOf = () => randomBytes(32).toString("base64url");
const P1 = me, P2 = partyId(), P3 = partyId();
const feeds = {
  [P1]: { token: tokenOf(), sources: 1, readers: [], sockets: new Set() },
  [P2]: { token: tokenOf(), sources: 0, readers: [], sockets: new Set() },
  [P3]: { token: tokenOf(), sources: 1, readers: [], sockets: new Set() },
};
const hellos = [];   // {party, viewer, hello, text}: the first frame of every socket
let viewers = 0;

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const len8 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

// One accepted WebSocket (RFC 6455): masked frames in, unmasked text out.
class Socket {
  constructor(conn, head) {
    this.conn = conn;
    this.buf = head;
    this.closed = false;
    this.closing = false;
    this.onText = () => {};
    this.onClose = () => {};
    conn.on("data", (d) => { this.buf = Buffer.concat([this.buf, d]); this.drain(); });
    conn.on("close", () => { this.closed = true; this.onClose(); });
    conn.on("error", () => {});
  }
  drain() {
    for (;;) {
      if (this.buf.length < 2) return;
      const fin = this.buf[0] & 0x80, op = this.buf[0] & 0x0f, masked = this.buf[1] & 0x80;
      let len = this.buf[1] & 0x7f, at = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); at = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; len = Number(this.buf.readBigUInt64BE(2)); at = 10; }
      const end = at + (masked ? 4 : 0) + len;
      if (this.buf.length < end) return;
      const payload = Buffer.from(this.buf.subarray(end - len, end));
      if (masked) { const mask = this.buf.subarray(at, at + 4); for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3]; }
      this.buf = this.buf.subarray(end);
      if (op === 1 && fin) this.onText(payload.toString("utf8"));
      else if (op === 8) { if (!this.closing) this.frame(8, payload.subarray(0, 2)); this.conn.end(); }
      else if (op === 9) this.frame(10, payload);
      // The page sends no binary, fragmented or pong frame.
    }
  }
  frame(op, payload) {
    if (this.closed) return;
    const n = payload.length;
    const head = n < 126 ? Buffer.from([0x80 | op, n])
      : n < 65536 ? Buffer.from([0x80 | op, 126, n >> 8, n & 255])
      : Buffer.concat([Buffer.from([0x80 | op, 127]), len8(n)]);
    this.conn.write(Buffer.concat([head, payload]));
  }
  send(text) { this.frame(1, Buffer.from(text, "utf8")); }
  // Starts the closing handshake with a code; the connection ends when the
  // client answers, or after half a second.
  close(code) {
    if (this.closed || this.closing) return;
    this.closing = true;
    this.frame(8, Buffer.from([code >> 8, code & 255]));
    setTimeout(() => this.conn.destroy(), 500).unref();
  }
}

const served = [];
const server = createServer((req, res) => {
  served.push(`${req.method} ${req.url}`);
  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    return res.end(html);
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});
server.on("upgrade", (req, conn, head) => {
  served.push(`UPGRADE ${req.url}`);
  const m = /^\/feed\/([^/?#]+)$/.exec(req.url);
  const feed = m && feeds[m[1]];
  const key = req.headers["sec-websocket-key"];
  if (!feed || !key) { conn.end("HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n"); return; }
  const accept = createHash("sha1").update(key + GUID).digest("base64");
  conn.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  const sock = new Socket(conn, head);
  const viewer = `v${++viewers}`;
  sock.onClose = () => feed.sockets.delete(sock);
  sock.onText = (text) => {
    if (text === "ping") { sock.send("pong"); return; }
    let hello = null;
    try { hello = JSON.parse(text); } catch (e) { /* recorded as null */ }
    hellos.push({ party: m[1], viewer, hello, text });
    if (!hello || hello.hello !== "viewer" || hello.token !== feed.token) { sock.close(4401); return; }
    feed.sockets.add(sock);
    sock.send(JSON.stringify({ ok: true, sources: feed.sources }));
    if (feed.sources > 0) for (const f of replay(viewer, feed.readers)) sock.send(JSON.stringify(f));
  };
  sock.drain();
});
// What the Object relays to every viewer of a party when its source sends.
const push = (party, frame) => { for (const s of feeds[party].sockets) s.send(JSON.stringify(frame)); };

// A second origin on the same host, which nothing should ever reach.
const sinkHits = [];
const sink = createServer((req, res) => {
  sinkHits.push(req.url);
  res.writeHead(200, { "access-control-allow-origin": "*" });
  res.end("ok");
});
sink.on("upgrade", (req, conn) => { sinkHits.push("ws " + req.url); conn.destroy(); });
await new Promise((r) => server.listen(0, "localhost", r));
await new Promise((r) => sink.listen(0, "localhost", r));
const origin = `http://localhost:${server.address().port}`;
const sinkOrigin = `http://localhost:${sink.address().port}`;
const link = (party, token) => `${origin}/#p=${party}&t=${token}`;

const profile = mkdtempSync(join(tmpdir(), "peer-decrypt-driver-"));
const chrome = spawn(chromePath, [
  "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
  "--disable-extensions", "--disable-background-networking", "--remote-debugging-port=0",
  `--user-data-dir=${profile}`, "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });
let chromeError = "";
chrome.stderr.on("data", (d) => { chromeError += d; });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0, checks = 0;
const check = (ok, label) => {
  checks++;
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${label}`);
};

const requests = [], sockets = [], frames = [], exceptions = [], security = [];
let ws, send, evaluate, loads = 0;

async function until(fn, ms = 10000) {
  for (const end = Date.now() + ms; Date.now() < end;) {
    if (await fn()) return true;
    await sleep(40);
  }
  return false;
}
// An evaluate that fails while a document is being replaced counts as false.
const waitFor = (expression, ms) => until(async () => { try { return await evaluate(expression); } catch (e) { return false; } }, ms);

const text = (id) => evaluate(`document.getElementById(${JSON.stringify(id)}).textContent`);
// Message rows by id; a day divider is an li without a body.
const rows = async () => Object.fromEntries(await evaluate(
  "[...document.querySelectorAll('#list li.msg')].map((li) => [li.dataset.id, li.querySelector('.body').textContent])",
));
const inRow = (id, selector, what = "textContent") =>
  evaluate(`(() => { const e = document.querySelector('#list li[data-id=${JSON.stringify(id)}] ${selector}'); return e ? e.${what} : null; })()`);

async function shots(name) {
  if (!shotsDir) return;
  for (const [device, width, height, mobile] of [["desk", 1440, 900, false], ["phone", 390, 844, true]]) {
    await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile });
    for (const scheme of ["light", "dark"]) {
      await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: scheme }] });
      await sleep(150);
      const { data } = await send("Page.captureScreenshot", { format: "png" });
      writeFileSync(join(shotsDir, `${name}-${device}-${scheme}.png`), Buffer.from(data, "base64"));
    }
  }
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "" }] });
  await send("Emulation.clearDeviceMetricsOverride");
}
function print(title, row) {
  console.log(`--- ${title}`);
  for (const r of records) console.log(`  ${r.id.padEnd(12)} ${row[r.id]}`);
}
function expectRows(row, want, title) {
  for (const [id, body] of Object.entries(want)) check(row[id] === body, `${title}: ${id} shows "${body}"`);
}
const is = (id, want) => `document.getElementById(${JSON.stringify(id)}).textContent === ${JSON.stringify(want)}`;
const rendered = (n) => waitFor(`document.querySelectorAll('#list li.msg').length === ${n}`);
// The replay's last frame has been handled: the key state names the card.
const settled = () => waitFor("/^钥匙已/.test(document.getElementById('keystate').textContent)");
async function enterSecret(secret) {
  await evaluate(`document.getElementById('secret').value = ${JSON.stringify(secret)}; document.getElementById('import').click(); true`);
}
// The page's stored key for a party, and what exportKey says to it.
const stored = (party) => evaluate(`(async () => {
  const db = await new Promise((res, rej) => { const r = indexedDB.open("peer-reader", 1); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  const rec = await new Promise((res, rej) => { const r = db.transaction("keys").objectStore("keys").get(${JSON.stringify(party)}); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  db.close();
  const exports = [];
  for (const f of ["pkcs8", "jwk", "raw"]) exports.push(await crypto.subtle.exportKey(f, rec.key).then(() => "exported", (e) => f + ":" + e.name));
  return { type: rec.key.type, alg: rec.key.algorithm.name, extractable: rec.key.extractable, pub: rec.pub, exports };
})()`);

// Loads a link in a fresh document, through about:blank: a fragment change on
// the same document would be the page's own hashchange reload instead.
async function load(url) {
  await send("Page.navigate", { url: "about:blank" });
  await waitFor("location.href === 'about:blank'");
  loads++;
  await send("Page.navigate", { url });
}
async function reload() {
  await evaluate("window.__old = true; true");
  loads++;
  await send("Page.reload");
  await waitFor("!window.__old && document.readyState === 'complete'");
}

async function connect() {
  let port;
  for (const end = Date.now() + 60000; Date.now() < end;) {
    const f = join(profile, "DevToolsActivePort");
    if (existsSync(f)) { port = Number(readFileSync(f, "utf8").split("\n")[0]); break; }
    if (chrome.exitCode !== null) throw new Error("Chromium exited: " + chromeError);
    await sleep(100);
  }
  if (!port) throw new Error("Chromium did not start: " + chromeError);
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", reject, { once: true });
  });
  let id = 0;
  const pending = new Map();
  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const [resolve, reject] = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error))); else resolve(msg.result);
    }
    if (msg.method === "Network.requestWillBeSent") {
      const { method, url, headers, postData } = msg.params.request;
      requests.push({ method, url, headers, postData });
    }
    if (msg.method === "Network.webSocketCreated") sockets.push(msg.params.url);
    if (msg.method === "Network.webSocketFrameSent") frames.push(msg.params.response.payloadData);
    if (msg.method === "Runtime.exceptionThrown") exceptions.push(msg.params.exceptionDetails.text);
    if (msg.method === "Log.entryAdded" && msg.params.entry.source === "security") security.push(msg.params.entry.text);
  });
  send = (method, params = {}) => new Promise((resolve, reject) => {
    const key = ++id;
    pending.set(key, [resolve, reject]);
    ws.send(JSON.stringify({ id: key, method, params }));
  });
  evaluate = async (expression) => {
    const result = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true, userGesture: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  };
  await Promise.all(["Page", "Runtime", "Network", "Log"].map((d) => send(`${d}.enable`)));
}

async function run() {
  await connect();
  console.log(`page ${origin}/`);
  const [real] = JSON.parse(vector.envelope).to;
  const vectorLocked = lockedLine(1);
  const plain = records.find((r) => r.id === "plain").body;
  const e2eTwo = records.find((r) => r.id === "e2e-two").body;
  const keyOf = (i) => hellos[i] && hellos[i].hello && hellos[i].hello.key;
  const locked = {
    plain, vector: vectorLocked, "two-keys": lockedLine(2), indented: vectorLocked,
    tampered: vectorLocked, "bad-enc": vectorLocked, "other-key": lockedLine(1),
    "other-suite": BAD, "no-stanzas": BAD, "e2e-two": e2eTwo,
    file: file.name + " · 179.1\u00a0KB · " + file.mime,
  };

  // 1. A first open: a key is born, the hello carries it, the card does not list it yet.
  await load(link(P1, feeds[P1].token));
  check(await rendered(records.length) && await settled(), "the replay renders");
  check(hellos.length === 1 && hellos[0].party === P1, "one hello reached the feed");
  const K1 = keyOf(0);
  check(KEY_RE.test(K1 || ""), "the hello carries a public key of the x25519:<43 base64url> form");
  check(hellos[0].hello.hello === "viewer" && hellos[0].hello.token === feeds[P1].token, "the hello is a viewer hello with the link's token");
  check(await text("keynote") === T.newKey, "a first open says 这是新钥匙");
  console.log("  keystate: " + await text("keystate"));
  check((await text("keystate")).startsWith(T.pending), "the key is reported as not yet on the card");
  check((await text("keystate")).includes("0 / 8"), "no encrypted record opens with a fresh key");
  check(await text("state") === T.live(records.length), "the state line counts the replayed records");
  check(requests.length === 1 && sockets.length === 1, "a plain load is one document and one socket");
  check(await evaluate("!document.getElementById('secret').disabled && !document.getElementById('import').disabled"), "the import field is enabled when X25519 is present");
  let row = await rows();
  print("locked", row);
  expectRows(row, locked, "locked");
  check(!Object.values(row).includes(vector.plaintext), "locked: the plaintext is not on the page");
  // The row as a person reads it: side and agent from dir, the counterpart's id, the time, 详情.
  check(await inRow("plain", ".who") === "对方 · legal", "a received record reads 对方 · <their agent>");
  check(await inRow("vector", ".who") === "我方 · advisor", "a sent record reads 我方 · <our agent>");
  check(await inRow("vector", "", "className") === "msg own" && await inRow("plain", "", "className") === "msg", "a sent row carries the own surface");
  check(await inRow("plain", ".id") === shortId(peer) && await inRow("plain", ".id", "title") === peer, "the counterpart party id is shortened with the full id as title");
  check(await inRow("vector", ".id") === shortId(peer), "a sent row names the counterpart, not us");
  check(/^\d{2}:\d{2}$/.test(await inRow("plain", "time")) && await inRow("plain", "time", "dateTime") === records[0].at, "the time is HH:mm with the record's at as datetime");
  check(await evaluate("document.querySelectorAll('#list li.day').length") === 1, "one day divider for one day of records");
  check(await inRow("plain", ".kind") === null && await inRow("file", ".kind") === "文件", "a kind word appears only when the kind is not text");
  check(await inRow("file", ".body.file .name") === file.name, "a file record shows its name");
  check(await inRow("vector", ".note") === null, "a locked record carries no decrypted note");
  const vectorDetails = await inRow("vector", "details");
  check(vectorDetails.includes("详情") && vectorDetails.includes(records[1].from) && vectorDetails.includes(records[1].to) && vectorDetails.includes("vector"), "详情 lists id, sender and recipient addresses");
  check(vectorDetails.includes(real.key) && vectorDetails.includes(JSON.parse(vector.envelope).body) && vectorDetails.includes("peer-e2e-v1"), "详情 lists the suite, the recipient keys and the ciphertext");
  check(await inRow("vector", "details .mine") === null, "a key this browser does not hold is not marked as its own");
  check((await inRow("file", "details")).includes(file.sha256), "a file's sha256 is in 详情");
  check(await evaluate("document.getElementById('empty').hidden"), "the empty line is hidden when records show");
  await shots("locked");
  const rec = await stored(P1);
  check(rec.type === "private" && rec.alg === "X25519" && rec.extractable === false, `the stored key is a non-extractable X25519 private key (${JSON.stringify(rec)})`);
  check(rec.pub === K1, "the stored public string is the one in the hello");
  check(rec.exports.length === 3 && rec.exports.every((e) => e !== "exported"), `exportKey rejects the stored key (${rec.exports.join(", ")})`);

  // 2. Frames sent while the page is open.
  push(P1, { rec: live });
  push(P1, { rec: truncated });
  check(await rendered(records.length + 2), "a live record renders without a reload");
  row = await rows();
  check(row.live === live.body, "the live record's body is shown");
  check(await evaluate(`document.querySelector('#list li[data-id="cut"] .cut').textContent`) === T.truncated, "a truncated record is marked 已截断");
  check(await text("state") === T.live(records.length + 2), "the state line counts the live records");

  // 3. The card lists the key: a reload sends the same key and reads 已登记.
  feeds[P1].readers = [K1];
  await reload();
  check(await rendered(records.length) && await settled(), "the page reloads onto the feed");
  check(hellos.length === 2 && keyOf(1) === K1, "the second load sends the same key");
  console.log("  keystate: " + await text("keystate"));
  check((await text("keystate")).startsWith(T.registered), "the key is reported as on the card once readers lists it");
  check(await text("keynote") === "", "a second load does not say 这是新钥匙");

  // 4. The advanced import.
  await enterSecret("x25519-secret:not-a-key");
  check(await waitFor(is("keynote", T.notSecret)), "a malformed secret is refused");
  check(!(await evaluate("document.body.textContent")).includes("not-a-key"), "the refusal does not quote what was typed");
  check(hellos.length === 2, "a refused import opens no socket");

  await enterSecret(other.secret);
  check(await until(() => hellos.length === 3), "an import reconnects with a new hello");
  check(keyOf(2) === other.public, "the hello carries the imported secret's public key");
  check(await rendered(records.length) && await settled(), "the replay renders after the import");
  check(await text("keynote") === T.imported, "the import is noted");
  row = await rows();
  print("wrong secret (a valid key, not the vector's)", row);
  expectRows(row, { ...locked, "two-keys": WRONG, "other-key": WRONG }, "wrong secret");
  check(!Object.values(row).includes(vector.plaintext), "wrong secret: the plaintext is not on the page");

  await enterSecret(vector.secret);
  check(await until(() => hellos.length === 4), "the vector's secret reconnects");
  check(keyOf(3) === vector.public, "the hello carries the vector's public key, derived from its secret through the base point");
  check(await rendered(records.length) && await settled(), "the replay renders after the vector's secret");
  row = await rows();
  print("the vector's secret", row);
  expectRows(row, {
    ...locked, vector: vector.plaintext, "two-keys": vector.plaintext, indented: vector.plaintext,
    tampered: WRONG, "bad-enc": BAD,
  }, "vector's secret");
  check(await evaluate("document.getElementById('secret').value === ''"), "the key field is emptied once read");
  console.log("  keystate: " + await text("keystate"));
  check((await text("keystate")).includes("3 / 8"), "three encrypted records open with the vector's key");
  check(await inRow("vector", ".note") === DECRYPTED && await inRow("two-keys", ".note") === DECRYPTED, "an opened record says 已在本机解密 under its text");
  check(await inRow("tampered", ".note") === null && await inRow("plain", ".note") === null, "a failed or plain record carries no decrypted note");
  check(await inRow("vector", "details .mine") === MINE, "详情 marks this browser's key among the recipients");
  await shots("decrypted");
  await evaluate(`document.querySelector('#list li[data-id="vector"] details').open = true; document.querySelector('#list li[data-id="vector"]').scrollIntoView(); true`);
  await sleep(100);
  await shots("details");
  push(P1, { rec: live });
  check(await rendered(records.length + 1), "a live record renders after an import");
  check(await evaluate(`document.querySelector('#list li[data-id="vector"] details').open`), "an open 详情 stays open across a rebuild");
  await evaluate(`document.querySelector('#list li[data-id="vector"] details').open = false; true`);

  await reload();
  check(await rendered(records.length) && await settled(), "the page reloads after an import");
  check(hellos.length === 5 && keyOf(4) === vector.public, "the imported key survives a reload");
  check((await rows()).vector === vector.plaintext, "the plaintext survives a reload");
  check(await text("keynote") === "", "a reload with an imported key notes nothing");

  // 5. Cleared storage: a new key.
  await send("Storage.clearDataForOrigin", { origin, storageTypes: "all" });
  await reload();
  check(await rendered(records.length) && await settled(), "the page reloads after its storage is cleared");
  const K2 = keyOf(5);
  check(hellos.length === 6 && KEY_RE.test(K2 || "") && K2 !== K1 && K2 !== vector.public, "a cleared browser sends a new key");
  check(await text("keynote") === T.newKey, "a cleared browser says 这是新钥匙 again");
  check((await rows()).vector === vectorLocked, "the records lock again under the new key");

  // 6. No source connected.
  await load(link(P2, feeds[P2].token));
  check(await waitFor(is("state", T.waitingHost)), "with no source the state line reads 等待主机");
  check(hellos.length === 7 && hellos[6].party === P2 && KEY_RE.test(keyOf(6) || ""), "the hello to a party without a source still carries a key");
  check(await text("keystate") === T.checking, "without a replay the card state is unknown");
  check(await evaluate("!document.getElementById('empty').hidden") && await text("empty") === EMPTY_WAITING, "with no source and no record the empty line says the host is not connected");
  await shots("waiting");

  // 7. A wrong token.
  const socketsBefore = sockets.length;
  await load(link(P1, tokenOf()));
  check(await waitFor(is("state", T.expired)), "a wrong token reads 链接已失效");
  check(hellos.length === 8 && hellos[7].hello.token !== feeds[P1].token, "the wrong token reached the feed and was refused");
  await sleep(3000);
  check(sockets.length === socketsBefore + 1, "an expired link is not retried");

  // 8. A link without its parts.
  const socketsBeforeBad = sockets.length;
  await load(`${origin}/#p=bad`);
  check(await waitFor(is("state", T.badLink)), "a link without its parts says what it needs");
  await sleep(300);
  check(sockets.length === socketsBeforeBad && hellos.length === 8, "a bad link opens no socket");
  check(await text("keystate") === "", "a bad link shows no key state");

  // 9. Storage.
  check(await evaluate("localStorage.length === 0 && sessionStorage.length === 0 && document.cookie === ''"), "nothing in localStorage, sessionStorage or cookies");
  check(JSON.stringify(await evaluate("indexedDB.databases().then((d) => d.map((x) => x.name))")) === '["peer-reader"]', "the only IndexedDB database is peer-reader");

  // 10. The request log, before the checks below provoke blocked requests.
  await sleep(300);
  console.log("--- hellos the feed received");
  for (const h of hellos) {
    const ok = h.hello && h.hello.token === feeds[h.party].token;
    console.log(`  ${h.party.slice(0, 20)}… ${h.viewer.padEnd(3)} token ${ok ? "ok   " : "WRONG"} key ${h.hello && "key" in h.hello ? h.hello.key : "(none)"}`);
  }
  console.log("--- request log (every request and socket the page made)");
  for (const r of requests) console.log(`  ${r.method} ${r.url}`);
  for (const s of sockets) console.log(`  WS ${s}`);
  check(requests.length === loads && requests.every((r) => r.method === "GET" && r.url === `${origin}/`), `the log holds one same-origin document GET per load (${requests.length} of ${loads})`);
  check(requests.every((r) => r.postData === undefined), "no request carries a body");
  const feedUrl = new RegExp(`^${origin.replace("http", "ws")}/feed/ed25519:[A-Za-z0-9_-]{43}$`);
  check(sockets.length === hellos.length && sockets.every((s) => feedUrl.test(s)), `every socket is the same-origin feed socket (${sockets.length})`);
  const isHello = (f) => {
    try {
      const o = JSON.parse(f);
      return o.hello === "viewer" && typeof o.token === "string" && Object.keys(o).every((k) => ["hello", "token", "key"].includes(k));
    } catch (e) { return false; }
  };
  check(frames.length === hellos.length || frames.some((f) => f === "ping"), `the page sent one hello per socket (${frames.length} frames)`);
  check(frames.every((f) => f === "ping" || isHello(f)), "every frame the page sent is a viewer hello or a ping");
  const everywhere = JSON.stringify({ requests, sockets, frames, served });
  for (const [name, secret] of [["the vector's", vector.secret], ["the wrong", other.secret]]) {
    check(!everywhere.includes(secret), `${name} secret is in no request or frame`);
    check(!everywhere.includes(secret.slice("x25519-secret:".length)), `${name} secret's bytes are in no request or frame`);
  }
  const outsideHellos = JSON.stringify({ requests, sockets, served });
  check(Object.values(feeds).every((f) => !outsideHellos.includes(f.token)), "a reader token travels in hello frames only");
  check(served.every((s) => s === "GET /" || s.startsWith("UPGRADE /feed/")), "the server saw only GET / and feed upgrades");
  check(exceptions.length === 0, `no exception in the page (${exceptions.join(" | ")})`);
  check(security.length === 0, `no CSP violation in normal use (${security.join(" | ")})`);

  // 11. The policy is what makes "one connection" checkable, so prove it binds.
  check((await evaluate(`fetch(${JSON.stringify(sinkOrigin + "/fetch")}).then(() => "sent", () => "blocked")`)) === "blocked", "CSP blocks fetch to another origin");
  await evaluate(`(() => { const i = new Image(); i.src = ${JSON.stringify(sinkOrigin + "/img")}; document.body.append(i); })()`);
  await evaluate(`(() => { const s = document.createElement("script"); s.textContent = "window.injected = 1"; document.head.append(s); })()`);
  await evaluate(`(() => { const s = document.createElement("script"); s.src = ${JSON.stringify(sinkOrigin + "/script.js")}; document.head.append(s); })()`);
  const sinkSocket = await evaluate(`new Promise((r) => {
    try {
      const w = new WebSocket(${JSON.stringify(sinkOrigin.replace("http", "ws") + "/ws")});
      w.onopen = () => r("open"); w.onerror = () => r("error"); w.onclose = () => r("closed");
      setTimeout(() => r("silent"), 2000);
    } catch (e) { r("thrown " + e.name); }
  })`);
  check(sinkSocket !== "open", `CSP blocks a WebSocket to another origin (${sinkSocket})`);
  await sleep(500);
  check(await evaluate("window.injected === undefined"), "CSP blocks an injected inline script");
  check(sinkHits.length === 0, `nothing reached the other origin (${sinkHits.join(" ")})`);
  check(security.length > 0, `the blocks were reported as policy violations (${security.length})`);

  // 12. A browser without X25519.
  const stub = await send("Page.addScriptToEvaluateOnNewDocument", {
    source: 'crypto.subtle.generateKey = () => Promise.reject(new DOMException("no", "NotSupportedError"));',
  });
  await load(link(P3, feeds[P3].token));
  check(await waitFor(is("keystate", T.noX25519)), "without X25519 the page says so");
  console.log("  keystate: " + await text("keystate"));
  check(await evaluate("document.getElementById('secret').disabled && document.getElementById('import').disabled"), "without X25519 the import stays disabled");
  check(await until(() => hellos.length === 9), "the page still connects without a key");
  check(hellos[8].party === P3 && hellos[8].hello && !("key" in hellos[8].hello), "the hello has no key member when the browser holds none");
  check(await rendered(records.length) && (await rows()).vector === lockedNoKey(1), "the records show locked, with no key, without a key");
  await shots("nokey");
  await send("Page.removeScriptToEvaluateOnNewDocument", { identifier: stub.identifier });
}

try {
  await run();
} catch (e) {
  check(false, "driver: " + (e && e.stack || e));
} finally {
  chrome.kill();
  ws?.close();
  for (const f of Object.values(feeds)) for (const s of f.sockets) s.conn.destroy();
  server.close();
  sink.close();
  await sleep(200);
  rmSync(profile, { recursive: true, force: true, maxRetries: 3 });
}
console.log(`${failures ? "FAILED" : "OK"}: ${checks - failures} of ${checks} checks passed`);
process.exit(failures ? 1 : 0);
