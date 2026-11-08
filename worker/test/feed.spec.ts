// PeerFeed through the Worker: the signed config at /feed/<party>/config, then
// sources and viewers over /feed/<party>. The configs come from
// test/fixtures/card-cases.json (test/fixtures/gen): two throwaway parties,
// each with its root-signed card and bodies signed by its identity key at a
// fixed `at`, so the config calls go through handleFeed with that clock while
// the sockets go through SELF. Every request speaks from its own address
// because PEER_HITS counts per address.

import { env, SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { sha256Hex, CLOSE_BAD_TOKEN } from "../src/relay/channel";
import { BODY_CUT, type FeedEnv, handleFeed } from "../src/feed";
import { sleep } from "./helpers/sleep";
import { FRAME_WAIT_MS } from "./helpers/ws";
import cases from "./fixtures/card-cases.json";

const ORIGIN = "https://peer.0xtau.com";
// The secret and tokens whose hashes the fixtures' configs carry (gen/main.go).
const SECRET = "src_" + "7".repeat(43);
const TOKEN_A = "tok_" + "a".repeat(43);
const TOKEN_B = "tok_" + "b".repeat(43);
const KEY = "x25519:" + "k".repeat(43);
type Fx = typeof cases.p1;
const p1: Fx = cases.p1;
const p2: Fx = cases.p2;
let ip = 0;
const addr = () => ({ "CF-Connecting-IP": `203.0.113.${(ip++ % 200) + 10}` });
const atOf = (body: string) => Date.parse((JSON.parse(body) as { at: string }).at);
const feedEnv = env as unknown as FeedEnv;

type Frame = Record<string, any>;

// One client socket on a party's feed: frames parsed as they arrive, a wait
// for the first frame a predicate accepts, a check that none arrived, the close.
async function open(party: string) {
	const res = await SELF.fetch(`${ORIGIN}/feed/${party}`, { headers: { upgrade: "websocket", ...addr() } });
	expect(res.status, res.status === 101 ? "" : await res.clone().text()).toBe(101);
	const ws = res.webSocket!;
	const frames: Frame[] = [];
	const raw: string[] = [];
	let onClose!: (v: { code: number; reason: string }) => void;
	const closed = new Promise<{ code: number; reason: string }>((r) => (onClose = r));
	ws.addEventListener("message", (e) => {
		raw.push(e.data as string);
		frames.push(JSON.parse(e.data as string));
	});
	ws.addEventListener("close", (e) => onClose({ code: e.code, reason: e.reason }));
	ws.accept();
	const next = async (where: (m: Frame) => boolean, ms = FRAME_WAIT_MS): Promise<Frame> => {
		const until = Date.now() + ms;
		for (;;) {
			const i = frames.findIndex(where);
			if (i >= 0) return frames.splice(i, 1)[0]!;
			if (Date.now() >= until) throw new Error(`no such frame; saw ${JSON.stringify(frames).slice(0, 2000)}`);
			await sleep(10);
		}
	};
	const none = async (ms = 200) => {
		await sleep(ms);
		expect(frames).toEqual([]);
	};
	const send = (m: unknown) => ws.send(JSON.stringify(m));
	return { ws, frames, raw, next, none, send, closed, close: () => ws.close(1000, "bye") };
}

async function source(party: string, host = "h1", secret = SECRET) {
	const s = await open(party);
	s.send({ hello: "source", secret, host });
	return s;
}
async function viewer(party: string, token = TOKEN_A, key?: string) {
	const v = await open(party);
	v.send({ hello: "viewer", token, ...(key ? { key } : {}) });
	return v;
}

// The config routes through handleFeed, judged at the fixture's own clock.
const configCall = (party: string, method: string, headers: Record<string, string>, now: number, body?: string) =>
	handleFeed(new Request(`${ORIGIN}/feed/${party}/config`, { method, headers: { ...headers, ...addr() }, body }), feedEnv, ["feed", party, "config"], now);
const putConfig = (p: Fx, which: "initial" | "update", opts: { card?: string; signature?: string; body?: string } = {}) => {
	const c = p.configs[which];
	const body = opts.body ?? c.body;
	return configCall(p.party, "PUT", { "x-peer-card": opts.card ?? p.card, "x-peer-signature": opts.signature ?? c.signature }, atOf(c.body), body);
};
const getConfig = (p: Fx, opts: { card?: string; signature?: string } = {}) =>
	configCall(p.party, "GET", { "x-peer-at": p.read.at, "x-peer-card": opts.card ?? p.card, "x-peer-signature": opts.signature ?? p.read.signature }, Date.parse(p.read.at));

describe("the config", () => {
	it("is absent until the party PUTs it under its card, then reads back as hashes to a signed GET", async () => {
		expect((await getConfig(p1)).status).toBe(404);
		const bare = await SELF.fetch(`${ORIGIN}/feed/${p1.party}/config`, { headers: addr() });
		expect(bare.status).toBe(401);
		expect(await bare.json()).toMatchObject({ code: "bad_card" });
		expect(bare.headers.get("cache-control")).toBe("private, no-store");

		const res = await putConfig(p1, "initial");
		expect(res.status, await res.clone().text()).toBe(200);
		expect(await res.json()).toMatchObject({ ok: true, readers: 2 });

		const read = await getConfig(p1);
		expect(read.status).toBe(200);
		const got = await read.json();
		expect(got).toEqual(JSON.parse(p1.configs.initial.body));
		expect(JSON.stringify(got)).not.toContain(SECRET);
		expect(JSON.stringify(got)).not.toContain(TOKEN_A);
	});

	it("refuses another party's card, a root-signed body, a tampered body, a replayed config, and a GET signed over empty bytes", async () => {
		const bad = async (res: Promise<Response>, status: number, code: string) => {
			const r = await res;
			expect(r.status, await r.clone().text()).toBe(status);
			expect(await r.json()).toMatchObject({ code });
		};
		// The newer config first, so the older one below is a replay whatever ran before.
		expect((await putConfig(p1, "update")).status).toBe(200);
		await bad(putConfig(p1, "update", { card: p2.card }), 401, "bad_card");
		await bad(putConfig(p1, "initial", { signature: p1.rootSigned.signature }), 401, "root_signed");
		await bad(putConfig(p1, "update", { body: p1.configs.update.body + " " }), 401, "bad_signature");
		await bad(putConfig(p1, "initial"), 409, "stale");
		await bad(getConfig(p1, { signature: p1.read.emptySignature }), 401, "bad_signature");
		await bad(getConfig(p1, { card: p2.card }), 401, "bad_card");
	});

	it("is the only route shape under /feed", async () => {
		for (const path of ["/feed", "/feed/not-a-party", `/feed/${p1.party}/other`, `/feed/${p1.party}/config/x`]) {
			const res = await SELF.fetch(`${ORIGIN}${path}`, { headers: addr() });
			expect(res.status, path).toBe(404);
			expect(await res.json()).toMatchObject({ code: "no_such_route" });
		}
		expect((await SELF.fetch(`${ORIGIN}/feed/${p1.party}`, { headers: addr() })).status).toBe(426);
		expect((await SELF.fetch(`${ORIGIN}/feed/${p1.party}`, { method: "POST", headers: addr() })).status).toBe(405);
	});
});

describe("sources and viewers", () => {
	const p = { id: p2.party };
	beforeAll(async () => {
		expect((await putConfig(p2, "initial")).status).toBe(200);
	});

	it("closes a source with the wrong secret, a viewer with an unknown token, and a hello to a party without a config", async () => {
		const bad = await source(p.id, "h1", "wrong");
		expect((await bad.closed).code).toBe(CLOSE_BAD_TOKEN);
		const nobody = await viewer(p.id, "tok_" + "z".repeat(39));
		expect((await nobody.closed).code).toBe(CLOSE_BAD_TOKEN);
		const nobodyParty = "ed25519:" + btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		const s = await source(nobodyParty);
		expect((await s.closed).code).toBe(CLOSE_BAD_TOKEN);
	});

	it("fans a source's rec out to every viewer once, acks the source, and cuts a long body", async () => {
		const s = await source(p.id);
		expect(await s.next((m) => m.ok === true)).toEqual({ ok: true, sources: 1 });
		const v1 = await viewer(p.id, TOKEN_A);
		const v2 = await viewer(p.id, TOKEN_B);
		expect(await v1.next((m) => m.ok === true)).toEqual({ ok: true, sources: 1 });
		expect(await v2.next((m) => m.ok === true)).toEqual({ ok: true, sources: 1 });
		await s.next((m) => "replay" in m);
		await s.next((m) => "replay" in m);

		const rec = { id: "m1", dir: "in", kind: "text", from: "b", to: "a", at: "2026-11-08T15:00:00Z", body: "你好" };
		s.send({ rec, n: 7 });
		expect(await s.next((m) => "ack" in m)).toEqual({ ack: 7 });
		expect(await v1.next((m) => "rec" in m)).toEqual({ rec });
		expect(await v2.next((m) => "rec" in m)).toEqual({ rec });
		await v1.none();

		s.send({ rec: { ...rec, id: "m2", body: "字".repeat(30_000) }, n: 8 });
		const cut = await v1.next((m) => m.rec?.id === "m2");
		expect(cut.rec.truncated).toBe(true);
		expect(new TextEncoder().encode(cut.rec.body).length).toBeLessThanOrEqual(BODY_CUT);
		expect(cut.rec.body.length).toBeGreaterThan(BODY_CUT / 3 - 1);
		s.close();
		v1.close();
		v2.close();
	});

	it("tells every source about a new viewer with its key and token hash, and routes the replay to that viewer alone", async () => {
		const s1 = await source(p.id, "h1");
		const s2 = await source(p.id, "h2");
		await s1.next((m) => m.ok === true);
		await s2.next((m) => m.ok === true);
		const other = await viewer(p.id, TOKEN_B);
		await other.next((m) => m.ok === true);
		await s1.next((m) => "replay" in m);
		await s2.next((m) => "replay" in m);

		const v = await viewer(p.id, TOKEN_A, KEY);
		expect(await v.next((m) => m.ok === true)).toEqual({ ok: true, sources: 2 });
		const reader = "sha256:" + (await sha256Hex(TOKEN_A));
		const r1 = await s1.next((m) => "replay" in m);
		const r2 = await s2.next((m) => "replay" in m);
		expect(r1).toEqual({ replay: { viewer: expect.any(String), reader, key: KEY } });
		expect(r2).toEqual(r1);
		await s1.none();

		const id = r1.replay.viewer;
		const old = { rec: { id: "m0", dir: "out", kind: "text", from: "a", to: "b", at: "2026-11-07T00:00:00Z", body: "old" }, to: id };
		s1.send(old);
		const done = { replay_done: id, readers: [KEY] };
		s1.send(done);
		expect(await v.next((m) => m.rec?.id === "m0")).toEqual(old);
		expect(await v.next((m) => "replay_done" in m)).toEqual(done);
		await other.none();
		s1.close();
		s2.close();
		v.close();
		other.close();
	});

	it("closes a viewer whose token a new config drops", async () => {
		const v = await viewer(p.id, TOKEN_B);
		await v.next((m) => m.ok === true);
		expect((await putConfig(p2, "update")).status).toBe(200);
		expect((await v.closed).code).toBe(CLOSE_BAD_TOKEN);
	});
});
