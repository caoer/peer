// PeerFeed through the Worker: the signed config at /feed/<party>/config, then
// sources and viewers over /feed/<party>. Every describe signs for its own
// party born here (helpers/party.ts), so each has its own Object; every
// request speaks from its own address because PEER_HITS counts per address.

import { SELF } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { sha256Hex, CLOSE_BAD_TOKEN } from "../src/relay/channel";
import { BODY_CUT } from "../src/feed";
import { sleep } from "./helpers/sleep";
import { FRAME_WAIT_MS } from "./helpers/ws";
import { newParty, type Party } from "./helpers/party";

const ORIGIN = "https://peer.0xtau.com";
const SECRET = "src_" + "7".repeat(39);
const TOKEN_A = "tok_" + "a".repeat(39);
const TOKEN_B = "tok_" + "b".repeat(39);
const KEY = "x25519:" + "k".repeat(43);
let ip = 0;
const addr = () => ({ "CF-Connecting-IP": `203.0.113.${(ip++ % 200) + 10}` });

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

const configBody = async (party: string, readers = [TOKEN_A, TOKEN_B], at = new Date().toISOString()) =>
	JSON.stringify({ v: 1, party, at, source: "sha256:" + (await sha256Hex(SECRET)), readers: await Promise.all(readers.map(async (t) => "sha256:" + (await sha256Hex(t)))) });

const putConfig = async (p: Party, body: string, sig?: string) =>
	SELF.fetch(`${ORIGIN}/feed/${p.id}/config`, { method: "PUT", headers: { "x-peer-signature": sig ?? (await p.sign(body)), ...addr() }, body });

const getConfig = async (p: Party, at = new Date().toISOString(), sig?: string) =>
	SELF.fetch(`${ORIGIN}/feed/${p.id}/config`, { headers: { "x-peer-at": at, "x-peer-signature": sig ?? (await p.sign(at)), ...addr() } });

describe("the config", () => {
	let p: Party;
	beforeAll(async () => (p = await newParty()));

	it("is absent until the party PUTs it signed, then reads back as hashes to a signed GET", async () => {
		expect((await getConfig(p)).status).toBe(404);
		const bare = await SELF.fetch(`${ORIGIN}/feed/${p.id}/config`, { headers: addr() });
		expect(bare.status).toBe(401);
		expect(bare.headers.get("cache-control")).toBe("private, no-store");

		const body = await configBody(p.id);
		const res = await putConfig(p, body);
		expect(res.status, await res.clone().text()).toBe(200);
		expect(await res.json()).toMatchObject({ ok: true, readers: 2 });

		const read = await getConfig(p);
		expect(read.status).toBe(200);
		const got = await read.json();
		expect(got).toEqual(JSON.parse(body));
		expect(JSON.stringify(got)).not.toContain(SECRET);
		expect(JSON.stringify(got)).not.toContain(TOKEN_A);
	});

	it("refuses a bad signature, a replayed or older config, and a GET signed over the empty body", async () => {
		const other = await newParty();
		const body = await configBody(p.id);
		expect((await putConfig(p, body, await other.sign(body))).status).toBe(401);
		const older = await configBody(p.id, [TOKEN_A], new Date(Date.now() - 60_000).toISOString());
		const res = await putConfig(p, older);
		expect(res.status).toBe(409);
		expect(await res.json()).toMatchObject({ code: "stale" });
		const at = new Date().toISOString();
		expect((await getConfig(p, at, await p.sign(new Uint8Array(0)))).status).toBe(401);
	});

	it("is the only route shape under /feed", async () => {
		for (const path of ["/feed", "/feed/not-a-party", `/feed/${p.id}/other`, `/feed/${p.id}/config/x`]) {
			const res = await SELF.fetch(`${ORIGIN}${path}`, { headers: addr() });
			expect(res.status, path).toBe(404);
			expect(await res.json()).toMatchObject({ code: "no_such_route" });
		}
		expect((await SELF.fetch(`${ORIGIN}/feed/${p.id}`, { headers: addr() })).status).toBe(426);
		expect((await SELF.fetch(`${ORIGIN}/feed/${p.id}`, { method: "POST", headers: addr() })).status).toBe(405);
	});
});

describe("sources and viewers", () => {
	let p: Party;
	beforeAll(async () => {
		p = await newParty();
		expect((await putConfig(p, await configBody(p.id))).status).toBe(200);
	});

	it("closes a source with the wrong secret, a viewer with an unknown token, and a hello to a party without a config", async () => {
		const bad = await source(p.id, "h1", "wrong");
		expect((await bad.closed).code).toBe(CLOSE_BAD_TOKEN);
		const nobody = await viewer(p.id, "tok_" + "z".repeat(39));
		expect((await nobody.closed).code).toBe(CLOSE_BAD_TOKEN);
		const empty = await newParty();
		const s = await source(empty.id);
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
		expect((await putConfig(p, await configBody(p.id, [TOKEN_A]))).status).toBe(200);
		expect((await v.closed).code).toBe(CLOSE_BAD_TOKEN);
	});
});
