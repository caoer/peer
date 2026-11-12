// PeerChannel — /peer: the `peer` protocol's store-and-forward relay.
//
// A host opens a channel with the owner login, a guest joins it once with the
// invite token, and each side puts envelopes the other pulls by seq. Every
// test opens its own channel (its own object) and speaks from its own client
// address, because PEER_HITS counts every /peer request per address.
//
// The Worker under test is src/index.ts, its owner login RELAY_LOGIN bound to
// USER:TOKEN below by vitest.config.mts: every case goes through the wire
// contract alone.

import { env, SELF, runInDurableObject, runDurableObjectAlarm } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { sleep } from "./helpers/sleep";
import { limiter } from "./helpers/ratelimit";
import { FRAME_WAIT_MS } from "./helpers/ws";
import {
	BLOB_CHUNK,
	BLOB_ID_RE,
	BLOB_MAX,
	BODY_MAX,
	CLOSE_BAD_TOKEN,
	CLOSE_NO_SUCH_CHANNEL,
	CLOSE_SILENT,
	PING,
	PONG,
	PREKEYS_HELD_MAX,
	PREKEYS_PER_PUT,
	PULL_MAX,
	RELEASE_TAG,
	RETENTION_MS,
	SILENT_MS,
	SOCKETS_PER_SIDE,
	TOKEN_RE,
	peerName,
} from "../src/relay/channel";

const USER = "peerowner";
const TOKEN = "tok_" + "8".repeat(16);
const BEARER = `Bearer ${USER}:${TOKEN}`;
const ORIGIN = "https://peer.0xtau.com";


let n = 0;
let ip = "";
beforeEach(() => {
	n++;
	ip = `198.51.100.${n}`;
});

const call = (path: string, init: RequestInit & { token?: string } = {}) => {
	const headers = new Headers(init.headers);
	headers.set("CF-Connecting-IP", ip);
	if (init.token !== undefined) headers.set("authorization", `Bearer ${init.token}`);
	return SELF.fetch(`${ORIGIN}${path}`, { ...init, headers });
};
const post = (path: string, body: unknown, token?: string) =>
	call(path, { method: "POST", token, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

const ok = async <T>(res: Response): Promise<T> => {
	expect(res.status, await res.clone().text()).toBe(200);
	return (await res.json()) as T;
};
const refused = async (res: Response, status: number, code: string, label = "") => {
	expect(res.status, `${label} ${await res.clone().text()}`).toBe(status);
	expect(await res.json(), label).toMatchObject({ code });
};

// Standard padded base64 of `bytes` decoded bytes, without building the bytes.
const b64Of = (bytes: number) => "AAAA".repeat(Math.floor(bytes / 3)) + ["", "AA==", "AAA="][bytes % 3];
const b64 = (text: string) => btoa(text);
// A blob answer's bytes as text, after checking it was a 200.
const bytesOf = async (res: Response) => {
	expect(res.status).toBe(200);
	return new TextDecoder().decode(await res.arrayBuffer());
};

type Opened = { id: string; hostToken: string; inviteToken: string };
type Envelope = { seq: number; type: string; body: string; at: number };

const open = async () => ok<Opened>(await call("/peer/channels", { method: "POST", headers: { authorization: BEARER } }));
const join = async (c: Opened) => (await ok<{ guestToken: string }>(await post(`/peer/c/${c.id}/join`, { inviteToken: c.inviteToken }))).guestToken;
const put = (id: string, token: string, type: string, body: string) => post(`/peer/c/${id}/envelopes`, { type, body }, token);
const pull = async (id: string, token: string, after?: number) =>
	ok<Envelope[]>(await call(`/peer/c/${id}/envelopes${after === undefined ? "" : `?after=${after}`}`, { token }));

const channel = (id: string) => env.PEER_CHANNEL.getByName(peerName(id));
const sqlOf = <T>(id: string, query: string, ...binds: unknown[]) =>
	runInDurableObject(channel(id), (_i, state) => state.storage.sql.exec(query, ...binds).toArray() as T[]);

describe("peer relay", () => {
	it("opens, joins once, and carries envelopes each way with a seq per direction", async () => {
		const c = await open();
		expect(c.id).toMatch(/^[0-9a-f]{32}$/);
		expect(c.hostToken).toMatch(TOKEN_RE);
		expect(c.inviteToken).toMatch(TOKEN_RE);

		// #0 is the host's card, there before the guest arrives.
		expect(await ok(await put(c.id, c.hostToken, "card", b64("host card")))).toEqual({ dir: "h2g", seq: 0 });
		const guestToken = await join(c);
		expect(guestToken).toMatch(TOKEN_RE);
		await refused(await post(`/peer/c/${c.id}/join`, { inviteToken: c.inviteToken }), 409, "token_used");

		expect(await ok(await put(c.id, guestToken, "prekey", b64("guest card in session")))).toEqual({ dir: "g2h", seq: 0 });
		expect(await ok(await put(c.id, c.hostToken, "msg", b64("h1")))).toEqual({ dir: "h2g", seq: 1 });
		expect(await ok(await put(c.id, guestToken, "msg", b64("g1")))).toEqual({ dir: "g2h", seq: 1 });
		expect(await ok(await put(c.id, c.hostToken, "msg", b64("h2")))).toEqual({ dir: "h2g", seq: 2 });

		// Each side reads the other's direction only; `after` omitted is -1.
		const toGuest = await pull(c.id, guestToken);
		expect(toGuest.map((e) => [e.seq, e.type, atob(e.body)])).toEqual([
			[0, "card", "host card"],
			[1, "msg", "h1"],
			[2, "msg", "h2"],
		]);
		expect(await pull(c.id, guestToken, -1)).toEqual(toGuest);
		for (const e of toGuest) expect(Math.abs(e.at - Date.now())).toBeLessThan(60_000);
		expect((await pull(c.id, guestToken, 1)).map((e) => e.seq)).toEqual([2]);
		expect(await pull(c.id, guestToken, 2)).toEqual([]);
		expect((await pull(c.id, c.hostToken)).map((e) => [e.seq, e.type, atob(e.body)])).toEqual([
			[0, "prekey", "guest card in session"],
			[1, "msg", "g1"],
		]);
		// A read deletes nothing: a second host reading the same channel sees it all.
		expect((await pull(c.id, c.hostToken, -1)).length).toBe(2);
	});

	it("refuses a wrong, missing or other channel's token, and an unknown channel", async () => {
		const c = await open();
		const other = await open();
		const guestToken = await join(c);
		for (const [what, token] of [
			["another channel's host token", other.hostToken],
			["the invite token", c.inviteToken],
			["a random token", "A".repeat(43)],
			["a malformed token", "not-a-token"],
		] as const) {
			await refused(await put(c.id, token, "msg", b64("x")), 401, "bad_token", what);
			await refused(await call(`/peer/c/${c.id}/envelopes`, { token }), 401, "bad_token", what);
			await refused(await call(`/peer/c/${c.id}/prekeys/take`, { method: "POST", token }), 401, "bad_token", what);
		}
		await refused(await call(`/peer/c/${c.id}/envelopes`), 401, "bad_token");
		await refused(await post(`/peer/c/${other.id}/join`, { inviteToken: c.inviteToken }), 401, "bad_token");
		// A guest token opens its own channel and no other.
		await refused(await put(other.id, guestToken, "msg", b64("x")), 401, "bad_token");
		await refused(await call(`/peer/c/${"0".repeat(32)}/envelopes`, { token: c.hostToken }), 404, "no_such_channel");
		await refused(await call("/peer/c/NOT-AN-ID/envelopes", { token: c.hostToken }), 404, "no_such_channel");
		// Opening one takes the owner login.
		await refused(await call("/peer/channels", { method: "POST" }), 401, "bad_token");
		await refused(await call("/peer/channels", { method: "POST", headers: { authorization: `Bearer ${USER}:tok_wrong` } }), 401, "bad_token");
		// Nothing was written for the id nobody created.
		expect(await sqlOf("0".repeat(32), "SELECT name FROM sqlite_master WHERE name = 'channel'")).toEqual([]);
	});

	it("caps a body at 1 MiB decoded and refuses what is not base64 or a known type", async () => {
		const c = await open();
		expect(await ok(await put(c.id, c.hostToken, "msg", b64Of(BODY_MAX)))).toEqual({ dir: "h2g", seq: 0 });
		await refused(await put(c.id, c.hostToken, "msg", b64Of(BODY_MAX + 1)), 413, "too_large");
		for (const body of ["", "abc", "ab=c", "ab c", "YQ", "a===", 42]) await refused(await put(c.id, c.hostToken, "msg", body as string), 400, "bad_request");
		await refused(await put(c.id, c.hostToken, "text", b64("x")), 400, "bad_request");
		await refused(await call(`/peer/c/${c.id}/envelopes`, { method: "POST", token: c.hostToken, body: "{not json" }), 400, "bad_request");
		// Nothing refused took a number.
		expect(await ok(await put(c.id, c.hostToken, "msg", b64("next")))).toEqual({ dir: "h2g", seq: 1 });
	});

	it("pages a pull by count and by body size, and the client re-pulls until []", async () => {
		const c = await open();
		const guestToken = await join(c);
		// Three bodies near the cap: two fit the byte budget, the third is the next page.
		for (let i = 0; i < 3; i++) await ok(await put(c.id, c.hostToken, "msg", b64Of(BODY_MAX)));
		const first = await pull(c.id, guestToken, -1);
		expect(first.map((e) => e.seq)).toEqual([0, 1]);
		expect((await pull(c.id, guestToken, 1)).map((e) => e.seq)).toEqual([2]);
		expect(await pull(c.id, guestToken, 2)).toEqual([]);

		// More small rows than one page holds, written straight into the table.
		await runInDurableObject(channel(c.id), (_i, state) => {
			for (let seq = 0; seq < PULL_MAX + 20; seq++)
				state.storage.sql.exec("INSERT INTO envelopes (dir, seq, type, body, at) VALUES ('g2h', ?, 'msg', 'AA==', ?)", seq, Date.now());
		});
		const page = await pull(c.id, c.hostToken, -1);
		expect(page.length).toBe(PULL_MAX);
		expect((await pull(c.id, c.hostToken, page.at(-1)!.seq)).map((e) => e.seq)[0]).toBe(PULL_MAX);
		for (const after of ["x", "-2", "1.5"]) await refused(await call(`/peer/c/${c.id}/envelopes?after=${after}`, { token: guestToken }), 400, "bad_request");
	});

	it("drops envelopes older than 30 days on the alarm, and never reuses a seq", async () => {
		const c = await open();
		const guestToken = await join(c);
		await ok(await put(c.id, c.hostToken, "card", b64("card")));
		await ok(await put(c.id, c.hostToken, "msg", b64("kept")));
		await ok(await put(c.id, guestToken, "msg", b64("old")));
		const old = Date.now() - RETENTION_MS - 60_000;
		await sqlOf(c.id, "UPDATE envelopes SET at = ? WHERE (dir = 'h2g' AND seq = 0) OR dir = 'g2h'", old);

		expect(await runDurableObjectAlarm(channel(c.id))).toBe(true);
		expect(await sqlOf(c.id, "SELECT dir, seq FROM envelopes ORDER BY dir, seq")).toEqual([{ dir: "h2g", seq: 1 }]);
		const kept = (await sqlOf<{ at: number }>(c.id, "SELECT at FROM envelopes"))[0]!.at;
		expect(await runInDurableObject(channel(c.id), (_i, state) => state.storage.getAlarm())).toBe(kept + RETENTION_MS + 1);
		expect((await pull(c.id, guestToken)).map((e) => atob(e.body))).toEqual(["kept"]);

		// The guest's direction is empty now; its next envelope is #1, not #0 again.
		expect(await ok(await put(c.id, guestToken, "msg", b64("new")))).toEqual({ dir: "g2h", seq: 1 });
		expect((await pull(c.id, c.hostToken, 0)).map((e) => atob(e.body))).toEqual(["new"]);
	});

	it("stores each side's prekeys for the other side to take once, oldest first", async () => {
		const c = await open();
		const guestToken = await join(c);
		const keys = (from: number, count: number) => Array.from({ length: count }, (_, i) => ({ id: from + i, pub: b64(`pub-${from + i}`) }));
		const putKeys = (token: string, body: unknown) => call(`/peer/c/${c.id}/prekeys`, { method: "PUT", token, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
		const take = async (token: string) => ok<{ id?: number; pub?: string }>(await call(`/peer/c/${c.id}/prekeys/take`, { method: "POST", token }));

		expect(await ok(await putKeys(c.hostToken, { keys: keys(7, 3) }))).toEqual({ count: 3 });
		// A retried batch lands once.
		expect(await ok(await putKeys(c.hostToken, { keys: keys(8, 3) }))).toEqual({ count: 4 });
		expect(await ok(await putKeys(guestToken, { keys: keys(1, 1) }))).toEqual({ count: 1 });

		expect(await take(guestToken)).toEqual({ id: 7, pub: b64("pub-7") });
		expect(await take(guestToken)).toEqual({ id: 8, pub: b64("pub-8") });
		// A batch retried after a take lands as nothing: a taken key is never handed out again.
		expect(await ok(await putKeys(c.hostToken, { keys: keys(7, 3) }))).toEqual({ count: 2 });
		expect(await take(c.hostToken)).toEqual({ id: 1, pub: b64("pub-1") });
		expect(await take(c.hostToken)).toEqual({});
		expect((await take(guestToken)).id).toBe(9);
		expect((await take(guestToken)).id).toBe(10);
		expect(await take(guestToken)).toEqual({});

		await refused(await putKeys(c.hostToken, { keys: keys(100, PREKEYS_PER_PUT + 1) }), 413, "too_large");
		await ok(await putKeys(c.hostToken, { keys: keys(1000, PREKEYS_PER_PUT) }));
		await ok(await putKeys(c.hostToken, { keys: keys(2000, PREKEYS_HELD_MAX - PREKEYS_PER_PUT) }));
		await refused(await putKeys(c.hostToken, { keys: keys(3000, 1) }), 413, "too_large");
		expect((await sqlOf<{ n: number }>(c.id, "SELECT count(*) AS n FROM prekeys WHERE side = 'host' AND taken IS NULL"))[0]!.n).toBe(PREKEYS_HELD_MAX);
		for (const bad of [{ keys: [] }, { keys: [{ id: -1, pub: "AA==" }] }, { keys: [{ id: 2 ** 32, pub: "AA==" }] }, { keys: [{ id: 1, pub: "not base64" }] }, {}])
			await refused(await putKeys(c.hostToken, bad), 400, "bad_request");
	});

	it("stores a 5 MB blob in chunks and hands the other side the same bytes", async () => {
		const c = await open();
		const guestToken = await join(c);
		const size = 5_000_000;
		const bytes = new Uint8Array(size);
		for (let i = 0; i < size; i += 65536) crypto.getRandomValues(bytes.subarray(i, Math.min(i + 65536, size)));
		// Pieces that straddle the chunk boundary, as a network delivers them.
		const body = new ReadableStream<Uint8Array>({
			start(ctl) {
				for (let off = 0; off < size; off += 777_777) ctl.enqueue(bytes.slice(off, Math.min(off + 777_777, size)));
				ctl.close();
			},
		});
		const put = await ok<{ blob: string; size: number }>(
			await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: c.hostToken, headers: { "content-type": "application/octet-stream" }, body }),
		);
		expect(put.blob).toMatch(BLOB_ID_RE);
		expect(put.size).toBe(size);
		const rows = await sqlOf<{ n: number; len: number }>(c.id, "SELECT n, length(data) AS len FROM blob_chunks WHERE blob = ? ORDER BY n", put.blob);
		expect(rows.map((r) => r.n)).toEqual([0, 1, 2, 3, 4]);
		expect(rows.slice(0, 4).every((r) => r.len === BLOB_CHUNK)).toBe(true);
		expect(rows[4]!.len).toBe(size - 4 * BLOB_CHUNK);

		const got = await call(`/peer/c/${c.id}/blobs/${put.blob}`, { token: guestToken });
		expect(got.status).toBe(200);
		expect(got.headers.get("content-type")).toBe("application/octet-stream");
		expect(got.headers.get("content-length")).toBe(String(size));
		const back = new Uint8Array(await got.arrayBuffer());
		expect(back.length).toBe(size);
		expect(back.every((b, i) => b === bytes[i])).toBe(true);

		// The side that put it reads nothing: a token reads what was put for it.
		await refused(await call(`/peer/c/${c.id}/blobs/${put.blob}`, { token: c.hostToken }), 404, "no_such_blob");
		// And the guest's own blob goes the other way.
		const small = await ok<{ blob: string; size: number }>(await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: guestToken, body: "abc" }));
		expect(small.size).toBe(3);
		expect(await bytesOf(await call(`/peer/c/${c.id}/blobs/${small.blob}`, { token: c.hostToken }))).toBe("abc");
	});

	it("refuses a blob over the cap, an empty one, a missing one and a wrong token, keeping nothing", async () => {
		const c = await open();
		const guestToken = await join(c);
		// One byte over the cap, streamed with no length declared, so the
		// Worker counts it rather than trusting a header.
		const piece = new Uint8Array(BLOB_CHUNK);
		let sent = 0;
		const over = new ReadableStream<Uint8Array>({
			pull(ctl) {
				if (sent > BLOB_MAX) return ctl.close();
				const n = Math.min(piece.length, BLOB_MAX + 1 - sent);
				sent += n;
				ctl.enqueue(piece.slice(0, n));
			},
		});
		await refused(await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: c.hostToken, body: over }), 413, "too_large");
		await refused(await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: c.hostToken, body: "" }), 400, "bad_request");
		expect(await sqlOf(c.id, "SELECT id FROM blobs")).toEqual([]);
		expect(await sqlOf(c.id, "SELECT blob FROM blob_chunks")).toEqual([]);

		await refused(await call(`/peer/c/${c.id}/blobs/${"0".repeat(32)}`, { token: guestToken }), 404, "no_such_blob");
		await refused(await call(`/peer/c/${c.id}/blobs/not-a-blob`, { token: guestToken }), 404, "no_such_blob");
		await refused(await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: "A".repeat(43), body: "x" }), 401, "bad_token");
		await refused(await call(`/peer/c/${c.id}/blobs`, { method: "POST", body: "x" }), 401, "bad_token");
		const put = await ok<{ blob: string }>(await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: c.hostToken, body: "x" }));
		await refused(await call(`/peer/c/${c.id}/blobs/${put.blob}`, { token: c.inviteToken }), 401, "bad_token");
		// A blob id names nothing on another channel.
		const other = await open();
		await refused(await call(`/peer/c/${other.id}/blobs/${put.blob}`, { token: other.hostToken }), 404, "no_such_blob");
		await refused(await call(`/peer/c/${c.id}/blobs`, { token: c.hostToken }), 405, "method_not_allowed");
		await refused(await call(`/peer/c/${c.id}/blobs/${put.blob}`, { method: "DELETE", token: guestToken }), 405, "method_not_allowed");
	});

	it("drops a blob 30 days after its put on the alarm, and an abandoned put with it", async () => {
		const c = await open();
		const guestToken = await join(c);
		const old = await ok<{ blob: string }>(await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: c.hostToken, body: "old" }));
		const kept = await ok<{ blob: string }>(await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: c.hostToken, body: "kept" }));
		// A put whose Worker died part way: a row with no size and one chunk.
		await sqlOf(c.id, "INSERT INTO blobs (id, side, at) VALUES ('abandoned', 'host', ?)", Date.now() - RETENTION_MS - 60_000);
		await sqlOf(c.id, "INSERT INTO blob_chunks (blob, n, data) VALUES ('abandoned', 0, x'00')");
		await sqlOf(c.id, "UPDATE blobs SET at = ? WHERE id = ?", Date.now() - RETENTION_MS - 60_000, old.blob);

		expect(await runDurableObjectAlarm(channel(c.id))).toBe(true);
		expect(await sqlOf(c.id, "SELECT id FROM blobs")).toEqual([{ id: kept.blob }]);
		expect(await sqlOf(c.id, "SELECT DISTINCT blob FROM blob_chunks")).toEqual([{ blob: kept.blob }]);
		await refused(await call(`/peer/c/${c.id}/blobs/${old.blob}`, { token: guestToken }), 404, "no_such_blob");
		expect(await bytesOf(await call(`/peer/c/${c.id}/blobs/${kept.blob}`, { token: guestToken }))).toBe("kept");
		// The alarm waits for the oldest row left, a blob when no envelope is held.
		const at = (await sqlOf<{ at: number }>(c.id, "SELECT at FROM blobs"))[0]!.at;
		expect(await runInDurableObject(channel(c.id), (_i, state) => state.storage.getAlarm())).toBe(at + RETENTION_MS + 1);
	});

	it("answers the invite landing text and refuses what is not a route", async () => {
		const res = await call(`/peer/i/${"a".repeat(32)}`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toMatch(/^text\/plain/);
		const text = await res.text();
		expect(text).toContain(`go install github.com/caoer/peer/cmd/peer@${RELEASE_TAG}`);
		expect(text).toContain(`https://github.com/caoer/peer/releases/tag/${RELEASE_TAG}`);
		expect(text.indexOf("go install")).toBeLessThan(text.indexOf("peer accept '<the link>'"));
		await refused(await call("/peer/i/nope"), 404, "no_such_channel");
		await refused(await call("/peer/channels"), 405, "method_not_allowed");
		await refused(await call(`/peer/c/${"a".repeat(32)}/envelopes`, { method: "DELETE" }), 405, "method_not_allowed");
		await refused(await call("/peer/nowhere"), 404, "no_such_route");
		await refused(await call(`/peer/c/${"a".repeat(32)}/elsewhere`), 404, "no_such_route");
		expect((await SELF.fetch(`${ORIGIN}/peer/`)).ok).toBe(true);
		expect(await (await SELF.fetch(`${ORIGIN}/peer/`)).text()).toContain("POST /peer/channels");
	});

	it("answers a route that fails inside the relay as 500 internal_error, in the contract's shape", async () => {
		const c = await open();
		const guestToken = await join(c);
		// The fault: the channel's token table gone from under a live channel.
		await sqlOf(c.id, "DROP TABLE tokens");
		const res = await call(`/peer/c/${c.id}/envelopes`, { token: guestToken });
		expect(res.status).toBe(500);
		expect(await res.json()).toMatchObject({ code: "internal_error" });
	});

	it("refuses a blob put whose body ends short of its declared length, keeping nothing", async () => {
		const c = await open();
		const body = new ReadableStream<Uint8Array>({
			start(ctl) {
				ctl.enqueue(new Uint8Array(2 * BLOB_CHUNK));
				ctl.close();
			},
		});
		await refused(
			await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: c.hostToken, headers: { "content-length": String(3 * BLOB_CHUNK) }, body }),
			400,
			"bad_request",
		);
		expect(await sqlOf(c.id, "SELECT id FROM blobs")).toEqual([]);
		expect(await sqlOf(c.id, "SELECT blob FROM blob_chunks")).toEqual([]);
	});

	it("reads no blob whose put is unfinished, and hands out the oldest prekey first whatever its id", async () => {
		const c = await open();
		const guestToken = await join(c);
		const unfinished = "b".repeat(32);
		await sqlOf(c.id, "INSERT INTO blobs (id, side, at) VALUES (?, 'host', ?)", unfinished, Date.now());
		await refused(await call(`/peer/c/${c.id}/blobs/${unfinished}`, { token: guestToken }), 404, "no_such_blob");
		const putKeys = (body: unknown) =>
			call(`/peer/c/${c.id}/prekeys`, { method: "PUT", token: c.hostToken, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
		await ok(await putKeys({ keys: [{ id: 9, pub: b64("pub-9") }] }));
		await ok(await putKeys({ keys: [{ id: 3, pub: b64("pub-3") }] }));
		const take = async () => ok<{ id?: number }>(await call(`/peer/c/${c.id}/prekeys/take`, { method: "POST", token: guestToken }));
		expect((await take()).id).toBe(9);
		expect((await take()).id).toBe(3);
	});

	it("refuses an address past 100 requests per 10 s, and only that address", async () => {
		const { limit } = limiter("PEER_HITS");
		const landing = `/peer/i/${"b".repeat(32)}`;
		const results = await Promise.all(Array.from({ length: limit + 5 }, () => call(landing)));
		const over = results.filter((r) => r.status === 429);
		expect(over.length, results.map((r) => r.status).join(",")).toBe(results.length - limit);
		await refused(over[0]!, 429, "rate_limited");
		ip = "203.0.113.7";
		expect((await call(landing)).status).toBe(200);
	});
});

// A push socket on the envelopes route: every text frame kept as it arrives.
const upgrade = (id: string, token?: string) => call(`/peer/c/${id}/envelopes`, { token, headers: { upgrade: "websocket" } });
const connect = async (id: string, token: string) => {
	const res = await upgrade(id, token);
	expect(res.status, res.status === 101 ? "" : await res.clone().text()).toBe(101);
	const ws = res.webSocket!;
	const raw: string[] = [];
	const closed = new Promise<{ code: number; reason: string }>((r) => ws.addEventListener("close", (e) => r({ code: e.code, reason: e.reason })));
	ws.addEventListener("message", (e) => {
		raw.push(e.data as string);
	});
	ws.accept();
	const rows = () => raw.filter((f) => f !== PONG).map((f) => JSON.parse(f) as Envelope);
	// The first `count` rows, waiting for them.
	const take = async (count: number) => {
		const until = Date.now() + FRAME_WAIT_MS;
		while (rows().length < count && Date.now() < until) await sleep(10);
		expect(rows().length, JSON.stringify(raw).slice(0, 500)).toBeGreaterThanOrEqual(count);
		return rows().slice(0, count);
	};
	return { ws, raw, rows, take, closed };
};

describe("peer push", () => {
	it("pushes each envelope to the other side's sockets as the row a pull answers, readable by pull when it arrives", async () => {
		const c = await open();
		const guestToken = await join(c);
		const host = await connect(c.id, c.hostToken);
		const guest = await connect(c.id, guestToken);

		const landed = await ok<{ dir: string; seq: number }>(await put(c.id, guestToken, "msg", b64("g0")));
		const [frame] = await host.take(1);
		// The row is in the table by the time its frame arrives.
		expect(await pull(c.id, c.hostToken, -1)).toEqual([frame]);
		expect(frame).toEqual({ seq: landed.seq, type: "msg", body: b64("g0"), at: expect.any(Number) });

		await ok(await put(c.id, c.hostToken, "card", b64("h0")));
		await ok(await put(c.id, c.hostToken, "msg", b64("h1")));
		expect(await guest.take(2)).toEqual(await pull(c.id, guestToken, -1));

		// A side never hears its own puts.
		await sleep(200);
		expect(host.rows()).toEqual([frame]);
		expect(guest.rows().length).toBe(2);
	});

	it("resumes a socket opened with after: the rows a pull from there answers, then synced, then each put; without after, nothing and no header", async () => {
		const c = await open();
		const guestToken = await join(c);
		for (const s of ["a", "b", "c"]) await ok(await put(c.id, guestToken, "msg", b64(s)));
		const resume = async (after: string) => {
			const res = await call(`/peer/c/${c.id}/envelopes?after=${after}`, { token: c.hostToken, headers: { upgrade: "websocket" } });
			expect(res.status, res.status === 101 ? "" : await res.clone().text()).toBe(101);
			const ws = res.webSocket!;
			const raw: string[] = [];
			ws.addEventListener("message", (e) => raw.push(e.data as string));
			ws.accept();
			const frames = async (count: number) => {
				const until = Date.now() + FRAME_WAIT_MS;
				while (raw.length < count && Date.now() < until) await sleep(10);
				return raw.slice(0, count).map((f) => JSON.parse(f));
			};
			return { res, ws, raw, frames };
		};

		const one = await resume("0");
		expect(one.res.headers.get("x-peer-resume")).toBe("1");
		const rows = await pull(c.id, c.hostToken, 0);
		expect(await one.frames(3)).toEqual([...rows, { synced: 2, more: false }]);
		await ok(await put(c.id, guestToken, "msg", b64("d")));
		const [, , , live] = await one.frames(4);
		expect(live).toEqual({ seq: 3, type: "msg", body: b64("d"), at: expect.any(Number) });

		// At the end: synced at the cursor itself, no row.
		const atEnd = await resume("3");
		expect(await atEnd.frames(1)).toEqual([{ synced: 3, more: false }]);

		// Without after, as before: no header, nothing until a put.
		const plain = await connect(c.id, c.hostToken);
		await sleep(200);
		expect(plain.raw).toEqual([]);
		expect((await upgrade(c.id, c.hostToken)).headers.get("x-peer-resume")).toBeNull();

		await refused(await call(`/peer/c/${c.id}/envelopes?after=x`, { token: c.hostToken, headers: { upgrade: "websocket" } }), 400, "bad_request");
		for (const s of [one, atEnd]) s.ws.close(1000, "bye");
		plain.ws.close(1000, "bye");
	});

	it("resumes at most one pull page, and says more remains", async () => {
		const c = await open();
		await join(c);
		// More small rows than one page holds, written straight into the table.
		await runInDurableObject(channel(c.id), (_i, state) => {
			for (let seq = 0; seq <= PULL_MAX; seq++)
				state.storage.sql.exec("INSERT INTO envelopes (dir, seq, type, body, at) VALUES ('g2h', ?, 'msg', 'AA==', ?)", seq, Date.now());
		});
		const res = await call(`/peer/c/${c.id}/envelopes?after=-1`, { token: c.hostToken, headers: { upgrade: "websocket" } });
		expect(res.status).toBe(101);
		const raw: string[] = [];
		res.webSocket!.addEventListener("message", (e) => raw.push(e.data as string));
		res.webSocket!.accept();
		const until = Date.now() + FRAME_WAIT_MS;
		while (raw.length < PULL_MAX + 1 && Date.now() < until) await sleep(10);
		expect(raw.length).toBe(PULL_MAX + 1);
		expect(JSON.parse(raw.at(-1)!)).toEqual({ synced: PULL_MAX - 1, more: true });
		res.webSocket!.close(1000, "bye");
	});

	it("stores a put with no socket open, and after the only socket closed", async () => {
		const c = await open();
		const guestToken = await join(c);
		expect(await ok(await put(c.id, guestToken, "msg", b64("before")))).toEqual({ dir: "g2h", seq: 0 });
		const host = await connect(c.id, c.hostToken);
		host.ws.close(1000, "bye");
		await host.closed;
		expect(await ok(await put(c.id, guestToken, "msg", b64("after")))).toEqual({ dir: "g2h", seq: 1 });
		// A socket opened later gets only what is put while it is open; the rest is the re-pull.
		const again = await connect(c.id, c.hostToken);
		await ok(await put(c.id, guestToken, "msg", b64("live")));
		expect((await again.take(1)).map((e) => atob(e.body))).toEqual(["live"]);
		expect((await pull(c.id, c.hostToken, -1)).map((e) => atob(e.body))).toEqual(["before", "after", "live"]);
	});

	it("refuses an upgrade as the pull refuses: bad or missing token, unknown channel", async () => {
		const c = await open();
		const other = await open();
		for (const [what, token] of [
			["no token", undefined],
			["another channel's host token", other.hostToken],
			["the invite token", c.inviteToken],
			["a malformed token", "not-a-token"],
		] as const) {
			const res = await upgrade(c.id, token);
			expect(res.webSocket, what).toBeNull();
			await refused(res, 401, "bad_token", what);
		}
		await refused(await upgrade("0".repeat(32), c.hostToken), 404, "no_such_channel");
		await refused(await upgrade("NOT-AN-ID", c.hostToken), 404, "no_such_channel");
	});

	it(`holds at most ${SOCKETS_PER_SIDE} sockets per side and refuses the next with too_many_sockets`, async () => {
		const c = await open();
		const guestToken = await join(c);
		const held = [];
		for (let i = 0; i < SOCKETS_PER_SIDE; i++) held.push(await connect(c.id, c.hostToken));
		const over = await upgrade(c.id, c.hostToken);
		expect(over.webSocket).toBeNull();
		await refused(over, 429, "too_many_sockets");
		// The other side's places are its own.
		await connect(c.id, guestToken);
		// A closed socket gives its place back.
		held[0]!.ws.close(1000, "bye");
		await held[0]!.closed;
		await connect(c.id, c.hostToken);
		// Every held socket still receives.
		await ok(await put(c.id, guestToken, "msg", b64("all")));
		for (const s of held.slice(1)) expect((await s.take(1))[0]!.body).toBe(b64("all"));
	});

	it(`gives a socket silent past ${SILENT_MS / 1000} s its place back, and keeps one that pinged`, async () => {
		const c = await open();
		const guestToken = await join(c);
		const held = [];
		for (let i = 0; i < SOCKETS_PER_SIDE; i++) held.push(await connect(c.id, c.hostToken));
		// Connections lost without a close stay OPEN on the relay and fall
		// silent: every socket last heard before the silence began.
		await runInDurableObject(channel(c.id), (_i, state) => {
			for (const ws of state.getWebSockets("host"))
				ws.serializeAttachment({ ...(ws.deserializeAttachment() as object), at: Date.now() - SILENT_MS - 1 });
		});
		// One is alive: its ping is heard after that.
		const live = held[0]!;
		live.ws.send(PING);
		const until = Date.now() + FRAME_WAIT_MS;
		while (!live.raw.includes(PONG) && Date.now() < until) await sleep(10);
		expect(live.raw).toEqual([PONG]);

		// The reconnect gets a socket, not too_many_sockets.
		const again = await connect(c.id, c.hostToken);
		for (const s of held.slice(1)) expect(await s.closed).toMatchObject({ code: CLOSE_SILENT, reason: "silent" });
		await ok(await put(c.id, guestToken, "msg", b64("after")));
		for (const s of [live, again]) expect((await s.take(1))[0]!.body).toBe(b64("after"));
	});

	it("answers ping with pong, and closes a socket whose token or channel stopped existing", async () => {
		const c = await open();
		const guestToken = await join(c);
		const host = await connect(c.id, c.hostToken);
		host.ws.send(PING);
		const until = Date.now() + FRAME_WAIT_MS;
		while (!host.raw.includes(PONG) && Date.now() < until) await sleep(10);
		expect(host.raw).toEqual([PONG]);
		// Any other client frame is read as nothing while the token still opens its side.
		host.ws.send("hello");
		await sleep(200);
		expect(host.ws.readyState).toBe(WebSocket.OPEN);

		const guest = await connect(c.id, guestToken);
		await sqlOf(c.id, "UPDATE tokens SET hash = ? WHERE role = 'guest'", "0".repeat(64));
		guest.ws.send("hello");
		expect(await guest.closed).toMatchObject({ code: CLOSE_BAD_TOKEN, reason: "bad_token" });

		await sqlOf(c.id, "DELETE FROM channel");
		host.ws.send("hello");
		expect(await host.closed).toMatchObject({ code: CLOSE_NO_SUCH_CHANNEL, reason: "no_such_channel" });
	});
});

// What the relay holds: ciphertext and routing, never a word of what was said.
// The milestone-1 demo scanned a live channel for its messages' plaintext and
// found none (results/milestone-1.md § What the relay holds); this case locks
// it. The test is the client: it seals a card naming the sender's petname and
// a message and a file carrying the body text, as a peer client does, puts
// them through every write route, and then reads everything the relay keeps or
// serves — each table of the channel's SQLite, its key-value storage, the
// socket attachments, every GET answer and the push frame — for either
// marker, as text, inside any base64 run, and as hex. The bearer tokens are
// held to the same rule: the relay stores their hashes, never them.
describe("what the relay holds", () => {
	const BODY_MARKER = "relay-must-never-read-this-body";
	const PETNAME_MARKER = "petname-relay-must-never-read";
	const enc = new TextEncoder();
	const dec = new TextDecoder();
	const toB64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
	const fromB64 = (text: string): Uint8Array | null => {
		try {
			const s = text.replace(/-/g, "+").replace(/_/g, "/");
			return Uint8Array.from(atob(s + "=".repeat((4 - (s.length % 4)) % 4)), (ch) => ch.charCodeAt(0));
		} catch {
			return null;
		}
	};
	const hexOf = (text: string) => [...enc.encode(text)].map((b) => b.toString(16).padStart(2, "0")).join("");

	// The client's seal: AES-256-GCM under a key only the two ends hold.
	const seal = async (key: CryptoKey, plaintext: string): Promise<Uint8Array> => {
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext)));
		const out = new Uint8Array(iv.length + ct.length);
		out.set(iv);
		out.set(ct, iv.length);
		return out;
	};

	// Every way `marker` could sit in `text`: as itself, as hex, or inside a
	// base64 run (standard or url-safe, decoded at each of the four offsets so
	// a run that starts mid-quantum still decodes).
	const holds = (text: string, marker: string): boolean => {
		if (text.includes(marker) || text.toLowerCase().includes(hexOf(marker))) return true;
		for (const run of text.match(/[A-Za-z0-9+/_-]{8,}={0,2}/g) ?? [])
			for (let off = 0; off < 4; off++) {
				const bytes = fromB64(run.slice(off).replace(/=+$/, ""));
				if (bytes !== null && dec.decode(bytes).includes(marker)) return true;
			}
		return false;
	};

	// A storage value as text: strings as they are, bytes as latin-1 so every
	// byte survives (the marker is ASCII), objects as their JSON.
	const asText = (v: unknown): string => {
		if (v === null || v === undefined) return "";
		if (typeof v === "string") return v;
		if (v instanceof ArrayBuffer) return String.fromCharCode(...new Uint8Array(v));
		if (ArrayBuffer.isView(v)) return String.fromCharCode(...new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
		if (typeof v === "object") return JSON.stringify(v);
		return String(v);
	};

	// Everything the channel's object keeps: each SQLite table but the
	// runtime's own, the key-value storage, and each socket's attachment.
	const storageOf = (id: string) =>
		runInDurableObject(channel(id), async (_i, state) => {
			const surfaces: Record<string, string> = {};
			const tables = state.storage.sql
				.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'")
				.toArray();
			for (const { name } of tables) {
				const rows = state.storage.sql.exec(`SELECT * FROM "${name}"`).toArray();
				surfaces[`table ${name} (${rows.length} rows)`] = rows.map((r) => Object.values(r).map(asText).join("\u0001")).join("\n");
			}
			const kv = await state.storage.list();
			surfaces[`kv (${kv.size} keys)`] = [...kv].map(([k, v]) => `${k}\u0001${asText(v)}`).join("\n");
			surfaces["socket attachments"] = state.getWebSockets().map((ws) => asText(ws.deserializeAttachment())).join("\n");
			return surfaces;
		});

	it("stores and serves the sealed bytes as put, and no plaintext, petname or token anywhere", async () => {
		const key = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])) as CryptoKey;
		const c = await open();
		const card = toB64(await seal(key, JSON.stringify({ petname: PETNAME_MARKER, rootpub: "k".repeat(43) })));
		await ok(await put(c.id, c.hostToken, "card", card));
		const guestToken = await join(c);
		const guest = await connect(c.id, guestToken);

		// The prekey, the message and the file, each sealed; the message put
		// carries a field beside type and body naming the sender, as a leaky
		// client might, and the relay keeps the body alone.
		const prekeyPub = toB64(crypto.getRandomValues(new Uint8Array(32)));
		await ok(await call(`/peer/c/${c.id}/prekeys`, { method: "PUT", token: guestToken, headers: { "content-type": "application/json" }, body: JSON.stringify({ keys: [{ id: 7, pub: prekeyPub }] }) }));
		const prekeyEnv = toB64(await seal(key, `prekey bundle from ${PETNAME_MARKER}`));
		await ok(await put(c.id, guestToken, "prekey", prekeyEnv));
		const msg = toB64(await seal(key, `${PETNAME_MARKER} says: ${BODY_MARKER}`));
		await ok(await post(`/peer/c/${c.id}/envelopes`, { type: "msg", body: msg, from: PETNAME_MARKER }, c.hostToken));
		const file = await seal(key, `file text: ${BODY_MARKER}`);
		const blob = await ok<{ blob: string }>(await call(`/peer/c/${c.id}/blobs`, { method: "POST", token: c.hostToken, headers: { "content-type": "application/octet-stream" }, body: file }));

		// Every answer the relay serves for this channel.
		const pushed = await guest.take(1);
		const served: Record<string, string> = {
			"push frames to the guest": guest.raw.join("\n"),
			"GET envelopes as the guest": await (await call(`/peer/c/${c.id}/envelopes?after=-1`, { token: guestToken })).text(),
			"GET envelopes as the host": await (await call(`/peer/c/${c.id}/envelopes?after=-1`, { token: c.hostToken })).text(),
			"GET blob as the guest": asText(await (await call(`/peer/c/${c.id}/blobs/${blob.blob}`, { token: guestToken })).arrayBuffer()),
			"POST prekeys/take as the host": await (await call(`/peer/c/${c.id}/prekeys/take`, { method: "POST", token: c.hostToken })).text(),
			"GET invite landing": await (await call(`/peer/i/${c.id}`)).text(),
		};
		const stored = await storageOf(c.id);
		expect(Object.keys(stored)).toEqual(expect.arrayContaining(["table envelopes (3 rows)", "table blob_chunks (1 rows)", "table prekeys (1 rows)", "table tokens (3 rows)"]));

		const secrets = { body: BODY_MARKER, petname: PETNAME_MARKER, hostToken: c.hostToken, inviteToken: c.inviteToken, guestToken };
		const found = Object.entries({ ...stored, ...served }).flatMap(([surface, text]) =>
			Object.entries(secrets)
				.filter(([, s]) => holds(text, s))
				.map(([what]) => `${what} in ${surface}`),
		);
		expect(found, "the relay holds or serves readable plaintext or a bearer token").toEqual([]);

		// The scan is not vacuous: the client's own key opens what the relay
		// serves, and the relay served the sealed bytes exactly as put.
		const open_ = async (b64text: string) => {
			const bytes = fromB64(b64text)!;
			return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12)));
		};
		const toGuest = JSON.parse(served["GET envelopes as the guest"]!) as Envelope[];
		expect(toGuest.map((e) => [e.type, e.body])).toEqual([["card", card], ["msg", msg]]);
		expect(pushed.map((e) => e.body)).toEqual([msg]);
		expect(await open_(msg)).toBe(`${PETNAME_MARKER} says: ${BODY_MARKER}`);
		expect(await open_(card)).toContain(PETNAME_MARKER);
		expect((JSON.parse(served["GET envelopes as the host"]!) as Envelope[]).map((e) => e.body)).toEqual([prekeyEnv]);
		expect(served["GET blob as the guest"]).toBe(asText(file));
		expect(JSON.parse(served["POST prekeys/take as the host"]!)).toEqual({ id: 7, pub: prekeyPub });
	});
});
