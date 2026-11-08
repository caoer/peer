// decrypt-driver.mjs — drives docs/timeline/index.html in headless Chromium
// over CDP, with the page served at http://localhost/a/<slug>/ and a stand-in
// /d/<slug> listing built from the test vector. It prints each record's line
// locked, with a wrong secret and with the vector's secret, then the page's
// whole request log.
//
//   node docs/timeline/test/decrypt-driver.mjs
//
// Exit 0 when every check passes, 1 when one fails, 2 when no browser runs.
// CCC_CHROME names the browser (a wrapper script is how to add --no-sandbox).
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { listing, other, records, vector } from "./fixtures/records.mjs";

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

const SLUG = "peer-e2e-driver-0123456789abcdef";
const PAGE = `/a/${SLUG}/`;
const LISTING = `/d/${SLUG}?prefix=tl.&values=1`;
const html = readFileSync(new URL("../index.html", import.meta.url));

const served = [];
const server = createServer((req, res) => {
  served.push(`${req.method} ${req.url}`);
  const send = (code, type, body) => {
    res.writeHead(code, { "content-type": type });
    res.end(body);
  };
  if (req.method === "GET" && req.url === PAGE) return send(200, "text/html; charset=utf-8", html);
  if (req.method === "GET" && req.url === LISTING) return send(200, "application/json", JSON.stringify(listing()));
  send(404, "text/plain", "not found");
});
// A second origin on the same host, which nothing should ever reach.
const sinkHits = [];
const sink = createServer((req, res) => {
  sinkHits.push(req.url);
  res.writeHead(200, { "access-control-allow-origin": "*" });
  res.end("ok");
});
await new Promise((r) => server.listen(0, "localhost", r));
await new Promise((r) => sink.listen(0, "localhost", r));
const origin = `http://localhost:${server.address().port}`;
const sinkOrigin = `http://localhost:${sink.address().port}`;

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

const requests = [], exceptions = [], security = [];
let ws, send, evaluate;

const lockedLine = (...keys) => "locked — encrypted to " + keys.join(", ");
const WRONG = "does not open with this key";
const BAD = "unreadable encrypted record";

async function waitFor(expression, ms = 10000) {
  for (const end = Date.now() + ms; Date.now() < end;) {
    if (await evaluate(expression)) return true;
    await sleep(40);
  }
  return false;
}

const rows = async () => Object.fromEntries(await evaluate(
  "[...document.querySelectorAll('#list li')].map((li) => [li.dataset.id, li.querySelector('.body').textContent])",
));
function print(title, row) {
  console.log(`--- ${title}`);
  for (const r of records) console.log(`  ${r.id.padEnd(12)} ${row[r.id]}`);
}
function expectRows(row, want, title) {
  for (const [id, text] of Object.entries(want)) check(row[id] === text, `${title}: ${id} shows "${text}"`);
}
const keystate = () => evaluate("document.getElementById('keystate').textContent");
async function enterSecret(secret) {
  await evaluate(`document.getElementById('secret').value = ${JSON.stringify(secret)}; document.getElementById('unlock').click(); true`);
}
const leaked = (needle) => requests.filter((r) => JSON.stringify(r).includes(needle));

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
  console.log(`page ${origin}${PAGE}`);
  const [real] = JSON.parse(vector.envelope).to;
  const vectorLocked = lockedLine(real.key);
  const plain = records.find((r) => r.id === "plain").body;
  const e2eTwo = records.find((r) => r.id === "e2e-two").body;

  await send("Page.navigate", { url: origin + PAGE });
  check(await waitFor("/^\\d+ messages/.test(document.getElementById('state').textContent)"), "the listing renders");
  check(await waitFor("!document.getElementById('secret').disabled"), "the key field is enabled when X25519 is present");

  let row = await rows();
  print("locked", row);
  expectRows(row, {
    plain,
    vector: vectorLocked,
    "two-keys": lockedLine(other.public, real.key),
    indented: vectorLocked,
    "other-key": lockedLine(other.public),
    "other-suite": BAD,
    "no-stanzas": BAD,
    "e2e-two": e2eTwo,
  }, "locked");
  check(!Object.values(row).includes(vector.plaintext), "locked: the plaintext is not on the page");

  await enterSecret("x25519-secret:not-a-key");
  check(await waitFor("document.getElementById('keynote').textContent.startsWith('That is not a secret key')"), "a malformed secret is refused");
  check(!(await evaluate("document.body.textContent")).includes("not-a-key"), "the refusal does not quote what was typed");

  await enterSecret(other.secret);
  check(await waitFor(`document.getElementById('keystate').textContent.includes(${JSON.stringify(other.public)})`), "a wrong secret loads as its own key");
  row = await rows();
  print("wrong secret (a valid key, not the vector's)", row);
  expectRows(row, {
    plain,
    vector: vectorLocked,
    "two-keys": WRONG,
    indented: vectorLocked,
    tampered: vectorLocked,
    "bad-enc": vectorLocked,
    "other-key": WRONG,
    "other-suite": BAD,
  }, "wrong secret");
  check(!Object.values(row).includes(vector.plaintext), "wrong secret: the plaintext is not on the page");

  await enterSecret(vector.secret);
  check(await waitFor(`document.getElementById('keystate').textContent.includes(${JSON.stringify(vector.public)})`), "the vector's secret loads and its derived public key is the vector's");
  row = await rows();
  print("the vector's secret", row);
  expectRows(row, {
    plain,
    vector: vector.plaintext,
    "two-keys": vector.plaintext,
    indented: vector.plaintext,
    tampered: WRONG,
    "bad-enc": BAD,
    "other-key": lockedLine(other.public),
    "other-suite": BAD,
    "no-stanzas": BAD,
    "e2e-two": e2eTwo,
  }, "vector's secret");
  check(await evaluate("document.getElementById('secret').value === ''"), "the key field is emptied once read");
  console.log("  keystate: " + await keystate());

  const pollsBefore = served.filter((s) => s === `GET ${LISTING}`).length;
  await evaluate("document.getElementById('reload').click(); true");
  const polls = () => served.filter((s) => s === `GET ${LISTING}`).length;
  for (const end = Date.now() + 5000; polls() === pollsBefore && Date.now() < end;) await sleep(40);
  check(polls() > pollsBefore, "Reload polls the store again with a key held");
  await waitFor("/^\\d+ messages/.test(document.getElementById('state').textContent)");
  check((await rows()).vector === vector.plaintext, "the plaintext survives a poll");

  check(await evaluate("localStorage.length === 0 && sessionStorage.length === 0 && document.cookie === ''"), "nothing in localStorage, sessionStorage or cookies");
  check((await evaluate("indexedDB.databases().then((d) => d.length)")) === 0, "no IndexedDB database");

  await evaluate("document.getElementById('forget').click(); true");
  check(await waitFor("document.getElementById('keystate').textContent.startsWith('No key entered')"), "Forget key returns to no key");
  row = await rows();
  check(row.vector === vectorLocked && !Object.values(row).includes(vector.plaintext), "after Forget key the plaintext is off the page");

  await evaluate("document.getElementById('generate').click(); true");
  check(await waitFor("document.getElementById('gen-secret').textContent !== ''"), "Generate my key prints the strings");
  const gen = await evaluate("({pub: document.getElementById('gen-public').textContent, sec: document.getElementById('gen-secret').textContent, hidden: document.getElementById('generated').hidden, text: document.getElementById('generated').textContent})");
  check(/^x25519:[A-Za-z0-9_-]{43}$/.test(gen.pub), "generated public key has the x25519:<43 base64url> form");
  check(/^x25519-secret:[A-Za-z0-9_-]{43}$/.test(gen.sec), "generated secret key has the x25519-secret:<43 base64url> form");
  check(!gen.hidden && gen.text.includes("party's admin"), "the instruction to hand the public key to the party's admin is shown");
  await enterSecret(gen.sec);
  check(await waitFor(`document.getElementById('keystate').textContent.includes(${JSON.stringify(gen.pub)})`), "the generated secret loads back as the generated public key");
  await evaluate("document.getElementById('forget').click(); true");
  await waitFor("document.getElementById('keystate').textContent.startsWith('No key entered')");

  // The request log, before the check below provokes blocked requests.
  await sleep(300);
  console.log("--- request log (every request the page made)");
  for (const r of requests) console.log(`  ${r.method} ${r.url}`);
  const docs = requests.filter((r) => r.url === origin + PAGE);
  const data = requests.filter((r) => r.url === origin + LISTING);
  check(docs.length === 1 && docs[0].method === "GET", "the page's own document is loaded once");
  check(data.length >= 2 && data.every((r) => r.method === "GET"), `the listing is a same-origin GET (${data.length} of them)`);
  check(requests.length === docs.length + data.length, "the log holds nothing but the document and same-origin /d/ GETs");
  check(requests.every((r) => r.postData === undefined), "no request carries a body");
  for (const [name, secret] of [["the vector's", vector.secret], ["the wrong", other.secret], ["the generated", gen.sec]]) {
    check(leaked(secret).length === 0, `${name} secret is in no request`);
    check(leaked(secret.slice("x25519-secret:".length)).length === 0, `${name} secret's bytes are in no request`);
  }
  check(served.every((s) => s === `GET ${PAGE}` || s === `GET ${LISTING}`), "the server saw only those two URLs");
  check(exceptions.length === 0, `no exception in the page (${exceptions.join(" | ")})`);
  check(security.length === 0, `no CSP violation in normal use (${security.join(" | ")})`);

  // The policy is what makes "no network" checkable, so prove it binds.
  check((await evaluate(`fetch(${JSON.stringify(sinkOrigin + "/fetch")}).then(() => "sent", () => "blocked")`)) === "blocked", "CSP blocks fetch to another origin");
  await evaluate(`(() => { const i = new Image(); i.src = ${JSON.stringify(sinkOrigin + "/img")}; document.body.append(i); })()`);
  await evaluate(`(() => { const s = document.createElement("script"); s.textContent = "window.injected = 1"; document.head.append(s); })()`);
  await evaluate(`(() => { const s = document.createElement("script"); s.src = ${JSON.stringify(sinkOrigin + "/script.js")}; document.head.append(s); })()`);
  await sleep(500);
  check((await evaluate("window.injected === undefined")), "CSP blocks an injected inline script");
  check(sinkHits.length === 0, `nothing reached the other origin (${sinkHits.join(" ")})`);

  // A browser without X25519.
  const stub = await send("Page.addScriptToEvaluateOnNewDocument", {
    source: 'crypto.subtle.generateKey = () => Promise.reject(new DOMException("no", "NotSupportedError"));',
  });
  await send("Page.navigate", { url: origin + PAGE });
  check(await waitFor("document.getElementById('keystate').textContent.startsWith('cannot decrypt')"), "without X25519 the page says so");
  console.log("  keystate: " + await keystate());
  check(await keystate() === "cannot decrypt here: X25519 missing (Chrome 133+, Firefox 130+, Safari 17+)", "the text is the planned one");
  check(await evaluate("document.getElementById('secret').disabled && document.getElementById('unlock').disabled && document.getElementById('generate').disabled"), "without X25519 the key controls stay disabled");
  await send("Page.removeScriptToEvaluateOnNewDocument", { identifier: stub.identifier });
}

try {
  await run();
} catch (e) {
  check(false, "driver: " + (e && e.stack || e));
} finally {
  chrome.kill();
  ws?.close();
  server.close();
  sink.close();
  await sleep(200);
  rmSync(profile, { recursive: true, force: true, maxRetries: 3 });
}
console.log(`${failures ? "FAILED" : "OK"}: ${checks - failures} of ${checks} checks passed`);
process.exit(failures ? 1 : 0);
