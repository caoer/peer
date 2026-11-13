// PeerRoom — /peer/rooms, /peer/r, /peer/f: the `peer` v2 room relay.
//
// An owner login opens a room; its creator holds an admin token at idx 0 and
// mints members, each reading the log from the head it was minted at. Every
// test opens its own room (its own object) and speaks from its own client
// address, as channel.spec.ts does, because PEER_HITS counts every /peer request
// per address.
//
// The Worker under test is src/index.ts, its owner login RELAY_LOGIN bound to
// USER:TOKEN below by vitest.config.mts.

import { env, SELF, runInDurableObject, runDurableObjectAlarm, evictDurableObject } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { sleep } from "./helpers/sleep";
import { FRAME_WAIT_MS } from "./helpers/ws";
import { BODY_MAX, CLOSE_BAD_TOKEN, CLOSE_SILENT, PING, PONG, PULL_MAX, RETENTION_MS, SILENT_MS, TOKEN_RE, RELEASE_TAG } from "../src/relay/channel";
import { IDX_MAX, SOCKETS_PER_IDX, roomName } from "../src/relay/room";

const USER = "peerowner";
const TOKEN = "tok_" + "8".repeat(16);
const BEARER = `Bearer ${USER}:${TOKEN}`;
const ORIGIN = "https://peer.0xtau.com";


let n = 0;
let ip = "";
beforeEach(() => {
	n++;
	ip = `192.0.2.${n}`;
});

const call = (path: string, init: RequestInit & { token?: string } = {}) => {
	const headers = new Headers(init.headers);
	headers.set("CF-Connecting-IP", ip);
	if (init.token !== undefined) headers.set("authorization", `Bearer ${init.token}`);
	return SELF.fetch(`${ORIGIN}${path}`, { ...init, headers });
};
const send = (method: string, path: string, body: unknown, token?: string) =>
	call(path, { method, token, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

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

type Room = { id: string; adminToken: string; membership: number };
type Minted = { idx: number; token: string; from: number; membership: number };
type Rec = { seq: number; idx: number; type: string; body: string; at: number };
type Pulled = { membership: number; records: Rec[] };
type Listed = { membership: number; members: { idx: number; role: string; from: number; admin: boolean; revoked: boolean }[] };
type State = {
	room: { created: number; add: string; membership: number; next: number; retention: number; alarm: number | null };
	you: { idx: number; role: string; from: number; admin: boolean; sockets: number };
	log: { count: number; first: number | null; oldest: number | null };
	records: Rec[];
};

const createRoom = (body?: unknown) =>
	call("/peer/rooms", {
		method: "POST",
		headers: { authorization: BEARER, "content-type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
const open = async (body?: unknown) => ok<Room>(await createRoom(body));
const mint = (id: string, token: string, role: unknown) => send("POST", `/peer/r/${id}/members`, { role }, token);
const minted = async (id: string, token: string, role: "write" | "read" = "write") => ok<Minted>(await mint(id, token, role));
const put = (id: string, token: string, membership: unknown, body: unknown = b64("sealed"), extra: Record<string, unknown> = {}) =>
	send("POST", `/peer/r/${id}/records`, { type: "sealed", body, membership, ...extra }, token);
const pull = async (id: string, token: string, after?: number) =>
	ok<Pulled>(await call(`/peer/r/${id}/records${after === undefined ? "" : `?after=${after}`}`, { token }));
const members = (id: string, token: string) => call(`/peer/r/${id}/members`, { token });
const stateOf = (id: string, token?: string, after?: number) => call(`/peer/r/${id}/state${after === undefined ? "" : `?after=${after}`}`, { token });
const state = async (id: string, token: string, after?: number) => ok<State>(await stateOf(id, token, after));
const revoke = (id: string, token: string, idx: number | string) => call(`/peer/r/${id}/members/${idx}`, { method: "DELETE", token });
const grant = (id: string, token: string, idx: unknown) => send("POST", `/peer/r/${id}/admin`, { idx }, token);

const roomOf = (id: string) => env.PEER_ROOM.getByName(roomName(id));
const sqlOf = <T>(id: string, query: string, ...binds: unknown[]) =>
	runInDurableObject(roomOf(id), (_i, state) => state.storage.sql.exec(query, ...binds).toArray() as T[]);

describe("peer rooms", () => {
	it("opens a room with the creator's admin token at idx 0, and mints members that read from the log head", async () => {
		const r = await open();
		expect(r.id).toMatch(/^[0-9a-f]{32}$/);
		expect(r.adminToken).toMatch(TOKEN_RE);
		expect(r.membership).toBe(0);

		expect(await ok(await put(r.id, r.adminToken, 0, b64("a0")))).toEqual({ seq: 0, membership: 0 });
		expect(await ok(await put(r.id, r.adminToken, 0, b64("a1")))).toEqual({ seq: 1, membership: 0 });
		const w = await minted(r.id, r.adminToken, "write");
		expect(w).toEqual({ idx: 1, token: expect.stringMatching(TOKEN_RE), from: 2, membership: 1 });
		const rd = await minted(r.id, r.adminToken, "read");
		expect(rd).toEqual({ idx: 2, token: expect.stringMatching(TOKEN_RE), from: 2, membership: 2 });
		expect(await ok(await put(r.id, r.adminToken, 2, b64("a2")))).toEqual({ seq: 2, membership: 2 });
		expect(await ok(await put(r.id, w.token, 2, b64("w3")))).toEqual({ seq: 3, membership: 2 });

		// The from floor: a member minted at head 2 reads nothing below it, and
		// no member reads its own records.
		const forW = await pull(r.id, w.token);
		expect(forW.membership).toBe(2);
		expect(forW.records.map((x) => [x.seq, x.idx, x.type, atob(x.body)])).toEqual([[2, 0, "sealed", "a2"]]);
		expect(Math.abs(forW.records[0]!.at - Date.now())).toBeLessThan(60_000);
		expect((await pull(r.id, rd.token)).records.map((x) => [x.seq, x.idx])).toEqual([[2, 0], [3, 1]]);
		expect((await pull(r.id, r.adminToken)).records.map((x) => [x.seq, x.idx])).toEqual([[3, 1]]);
		// `after` is seq > n under the floor; omitted, it is -1.
		expect((await pull(r.id, rd.token, 2)).records.map((x) => x.seq)).toEqual([3]);
		expect((await pull(r.id, rd.token, 3)).records).toEqual([]);
		expect(await pull(r.id, rd.token, -1)).toEqual(await pull(r.id, rd.token));
		// A read deletes nothing.
		expect((await pull(r.id, rd.token, 0)).records.length).toBe(2);

		expect(await ok(await members(r.id, r.adminToken))).toEqual({
			membership: 2,
			members: [
				{ idx: 0, role: "write", from: 0, admin: true, revoked: false },
				{ idx: 1, role: "write", from: 2, admin: false, revoked: false },
				{ idx: 2, role: "read", from: 2, admin: false, revoked: false },
			],
		});
	});

	it("answers any member's token with the room as the relay holds it and its whole view of the log, its own records in it", async () => {
		const r = await open();
		const empty = await state(r.id, r.adminToken);
		expect(empty).toEqual({
			room: { created: expect.any(Number), add: "admins", membership: 0, next: 0, retention: RETENTION_MS, alarm: null },
			you: { idx: 0, role: "write", from: 0, admin: true, sockets: 0 },
			log: { count: 0, first: null, oldest: null },
			records: [],
		});
		expect(Math.abs(empty.room.created - Date.now())).toBeLessThan(60_000);

		await ok(await put(r.id, r.adminToken, 0, b64("a0")));
		await ok(await put(r.id, r.adminToken, 0, b64("a1")));
		const w = await minted(r.id, r.adminToken);
		const rd = await minted(r.id, r.adminToken, "read");
		await ok(await put(r.id, r.adminToken, 2, b64("a2")));
		await ok(await put(r.id, w.token, 2, b64("w3")));
		const at = Object.fromEntries((await sqlOf<{ seq: number; at: number }>(r.id, "SELECT seq, at FROM records")).map((x) => [x.seq, x.at]));
		const room = { created: empty.room.created, add: "admins", membership: 2, next: 4, retention: RETENTION_MS };
		const rows = (s: State) => s.records.map((x) => [x.seq, x.idx, x.type, atob(x.body), x.at]);
		// The alarm is armed for #0; a seat from #2 reads it as the expiry of
		// its own oldest record, so no time below its from reaches it.
		expect(await runInDurableObject(roomOf(r.id), (_i, s) => s.storage.getAlarm())).toBe(at[0]! + RETENTION_MS + 1);

		// The writer's own record #3 is in its view; #0 and #1, below its from, are not.
		const forW = await state(r.id, w.token);
		expect({ ...forW, records: rows(forW) }).toEqual({
			room: { ...room, alarm: at[2]! + RETENTION_MS + 1 },
			you: { idx: 1, role: "write", from: 2, admin: false, sockets: 0 },
			log: { count: 2, first: 2, oldest: at[2] },
			records: [
				[2, 0, "sealed", "a2", at[2]],
				[3, 1, "sealed", "w3", at[3]],
			],
		});
		const forRd = await state(r.id, rd.token);
		expect([forRd.you, forRd.log, rows(forRd).map((x) => x[0])]).toEqual([{ idx: 2, role: "read", from: 2, admin: false, sockets: 0 }, { count: 2, first: 2, oldest: at[2] }, [2, 3]]);
		const forAdmin = await state(r.id, r.adminToken);
		expect([forAdmin.room, forAdmin.log, rows(forAdmin).map((x) => x[0])]).toEqual([
			{ ...room, alarm: at[0]! + RETENTION_MS + 1 },
			{ count: 4, first: 0, oldest: at[0] },
			[0, 1, 2, 3],
		]);
		// `after` pages as a pull's does; the log counts stay the whole view's.
		expect((await state(r.id, w.token, 2)).records.map((x) => x.seq)).toEqual([3]);
		expect(await state(r.id, w.token, 3)).toEqual({ ...forW, records: [] });
		// A read changes nothing: the pull still never serves the writer its own.
		expect((await pull(r.id, w.token)).records.map((x) => x.seq)).toEqual([2]);
		// A seat whose view holds nothing is told of no alarm.
		const late = await minted(r.id, r.adminToken, "read");
		expect((await state(r.id, late.token)).room.alarm).toBeNull();
		expect(await ok(await revoke(r.id, r.adminToken, late.idx))).toEqual({ membership: 4 });

		// sockets: the caller's own idx's open push sockets.
		const sock = await connect(r.id, w.token);
		expect((await state(r.id, w.token)).you.sockets).toBe(1);
		expect((await state(r.id, rd.token)).you.sockets).toBe(0);
		sock.ws.close();

		// Refused as the pull refuses.
		expect(await ok(await revoke(r.id, rd.token, "self"))).toEqual({ membership: 5 });
		await refused(await stateOf(r.id, rd.token), 401, "revoked");
		await refused(await stateOf(r.id, "A".repeat(43)), 401, "bad_token");
		await refused(await stateOf(r.id, (await open()).adminToken), 401, "bad_token", "another room's token");
		await refused(await stateOf(r.id), 401, "bad_token", "no token");
		await refused(await stateOf("0".repeat(32), r.adminToken), 404, "no_such_room");
		for (const after of ["x", "-2", "1.5"]) await refused(await call(`/peer/r/${r.id}/state?after=${after}`, { token: w.token }), 400, "bad_request", after);
		await refused(await call(`/peer/r/${r.id}/state`, { method: "POST", token: w.token }), 405, "method_not_allowed");
	});

	it("keeps add from creation: under admins only an admin mints, under members any write member does", async () => {
		const a = await open();
		expect(await sqlOf(a.id, "SELECT add_by FROM room")).toEqual([{ add_by: "admins" }]);
		const aw = await minted(a.id, a.adminToken);
		const ar = await minted(a.id, a.adminToken, "read");
		await refused(await mint(a.id, aw.token, "write"), 403, "not_admin", "a write member under admins");
		await refused(await mint(a.id, ar.token, "read"), 403, "not_admin", "a read member under admins");

		const m = await open({ add: "members" });
		expect(await sqlOf(m.id, "SELECT add_by FROM room")).toEqual([{ add_by: "members" }]);
		const mw = await minted(m.id, m.adminToken);
		const mr = await minted(m.id, m.adminToken, "read");
		expect(await minted(m.id, mw.token, "read")).toMatchObject({ idx: 3, membership: 3 });
		await refused(await mint(m.id, mr.token, "write"), 403, "not_admin", "a read member under members");

		expect((await open({})).membership).toBe(0);
		expect(await sqlOf((await open({ add: "admins" })).id, "SELECT add_by FROM room")).toEqual([{ add_by: "admins" }]);
		for (const body of [{ add: "everyone" }, { add: 1 }, [], "admins"]) await refused(await createRoom(body), 400, "bad_request", JSON.stringify(body));
		await refused(await call("/peer/rooms", { method: "POST", headers: { authorization: BEARER }, body: "{not json" }), 400, "bad_request");
		await refused(await call("/peer/rooms", { method: "POST" }), 401, "bad_token");
		await refused(await call("/peer/rooms", { method: "POST", headers: { authorization: `Bearer ${USER}:tok_wrong` } }), 401, "bad_token");
		for (const role of ["admin", "", 1, undefined]) await refused(await mint(a.id, a.adminToken, role), 400, "bad_request", String(role));
	});

	it("linearizes puts on the membership version: one below it is 409 stale_membership and stores nothing", async () => {
		const r = await open();
		const w = await minted(r.id, r.adminToken);
		await refused(await put(r.id, w.token, 0), 409, "stale_membership");
		await refused(await put(r.id, w.token, 2), 400, "bad_request", "a version the room has not reached");
		expect(await ok(await put(r.id, w.token, 1))).toEqual({ seq: 0, membership: 1 });
		// A mint, an admin grant and a revoke each move the version.
		await minted(r.id, r.adminToken, "read");
		await refused(await put(r.id, w.token, 1), 409, "stale_membership", "after a mint");
		expect((await ok<{ membership: number }>(await grant(r.id, r.adminToken, 1))).membership).toBe(3);
		await refused(await put(r.id, w.token, 2), 409, "stale_membership", "after an admin grant");
		expect(await ok(await revoke(r.id, r.adminToken, 2))).toEqual({ membership: 4 });
		await refused(await put(r.id, w.token, 3), 409, "stale_membership", "after a revoke");
		// Nothing refused was stored or took a number; a pull answers the version to seal for.
		expect(await pull(r.id, r.adminToken)).toEqual({ membership: 4, records: [expect.objectContaining({ seq: 0, idx: 1 })] });
		expect(await ok(await put(r.id, w.token, 4))).toEqual({ seq: 1, membership: 4 });
	});

	it("lands a bump record and its version in one transaction, so no stale put lands after a removal record", async () => {
		const r = await open();
		const w = await minted(r.id, r.adminToken);
		await minted(r.id, r.adminToken);
		// The removal record travels with bump: its seq and the new version land together.
		expect(await ok(await put(r.id, r.adminToken, 2, b64("roster removed [2]"), { bump: true }))).toEqual({ seq: 0, membership: 3 });
		// A put sealed for the old set, the leaver among its recipients, is refused and never stored.
		await refused(await put(r.id, w.token, 2, b64("sealed to the leaver")), 409, "stale_membership");
		expect(await pull(r.id, w.token)).toEqual({ membership: 3, records: [expect.objectContaining({ seq: 0, idx: 0, body: b64("roster removed [2]") })] });
		// bump takes an admin token: a write member's is refused, and a read member puts nothing at all.
		await refused(await put(r.id, w.token, 3, b64("x"), { bump: true }), 403, "read_only", "a write member's bump");
		const rd = await minted(r.id, r.adminToken, "read");
		await refused(await put(r.id, rd.token, 4), 403, "read_only", "a read member's put");
		await refused(await put(r.id, rd.token, 4, b64("x"), { bump: true }), 403, "read_only", "a read member's bump");
		expect(await ok(await put(r.id, r.adminToken, 4, b64("plain"), { bump: false }))).toEqual({ seq: 1, membership: 4 });

		// A bump whose record cannot land moves nothing: the row its seq would
		// take is occupied, the put fails inside its transaction, and the
		// version and the counter stay where they were.
		await sqlOf(r.id, "INSERT INTO records (seq, idx, type, body, at) VALUES (2, 0, 'sealed', 'AA==', ?)", Date.now());
		const failed = await put(r.id, r.adminToken, 4, b64("removal"), { bump: true });
		expect(failed.status).toBe(500);
		expect(await failed.json()).toMatchObject({ code: "internal_error" });
		expect(await sqlOf(r.id, "SELECT membership, next_seq FROM room")).toEqual([{ membership: 4, next_seq: 2 }]);
		await sqlOf(r.id, "DELETE FROM records WHERE seq = 2");
		expect(await ok(await put(r.id, r.adminToken, 4, b64("removal"), { bump: true }))).toEqual({ seq: 2, membership: 5 });
	});

	it("revokes every token on an idx: each answers 401 revoked on every route, and the version rises once", async () => {
		const r = await open();
		const k = await minted(r.id, r.adminToken);
		const kAdmin = await ok<{ token: string; membership: number }>(await grant(r.id, r.adminToken, k.idx));
		const other = await minted(r.id, r.adminToken);
		await refused(await revoke(r.id, other.token, k.idx), 403, "not_admin", "a member's token");
		expect(await ok(await revoke(r.id, r.adminToken, k.idx))).toEqual({ membership: 4 });
		for (const [what, token] of [
			["the member token", k.token],
			["the admin token on the same idx", kAdmin.token],
		] as const) {
			await refused(await put(r.id, token, 4), 401, "revoked", `${what}: put`);
			await refused(await call(`/peer/r/${r.id}/records`, { token }), 401, "revoked", `${what}: pull`);
			await refused(await stateOf(r.id, token), 401, "revoked", `${what}: state`);
			await refused(await mint(r.id, token, "write"), 401, "revoked", `${what}: mint`);
			await refused(await members(r.id, token), 401, "revoked", `${what}: members`);
			await refused(await grant(r.id, token, other.idx), 401, "revoked", `${what}: admin`);
			await refused(await revoke(r.id, token, other.idx), 401, "revoked", `${what}: revoke`);
			await refused(await revoke(r.id, token, "self"), 401, "revoked", `${what}: leave`);
		}
		// Revoking it again changes nothing, so a retried removal is safe.
		expect(await ok(await revoke(r.id, r.adminToken, k.idx))).toEqual({ membership: 4 });
		for (const idx of [9, "x1", 65535]) await refused(await revoke(r.id, r.adminToken, idx), 404, "no_such_member", String(idx));
		expect((await ok<Listed>(await members(r.id, r.adminToken))).members[k.idx]).toEqual({ idx: 1, role: "write", from: 0, admin: true, revoked: true });
		// Every other member is untouched.
		expect(await ok(await put(r.id, other.token, 4))).toEqual({ seq: 0, membership: 4 });
	});

	it("lets any member leave with DELETE members/self, a read member included", async () => {
		const r = await open();
		const rd = await minted(r.id, r.adminToken, "read");
		expect(await ok(await revoke(r.id, rd.token, "self"))).toEqual({ membership: 2 });
		await refused(await call(`/peer/r/${r.id}/records`, { token: rd.token }), 401, "revoked");
		// An admin's host sees the reader gone.
		expect((await ok<Listed>(await members(r.id, r.adminToken))).members.map((m) => [m.idx, m.revoked])).toEqual([
			[0, false],
			[1, true],
		]);
	});

	it("holds admin as a per-token flag: the creator hands over and leaves, and the new admin still mints and revokes", async () => {
		const r = await open();
		const k = await minted(r.id, r.adminToken);
		await refused(await members(r.id, k.token), 403, "not_admin");
		const kAdmin = await ok<{ token: string; membership: number }>(await grant(r.id, r.adminToken, k.idx));
		expect(kAdmin).toEqual({ token: expect.stringMatching(TOKEN_RE), membership: 2 });
		// The flag is on the new token, not on idx 1: k's member token is no admin.
		await refused(await members(r.id, k.token), 403, "not_admin", "k's member token");
		await refused(await put(r.id, k.token, 2, b64("x"), { bump: true }), 403, "read_only", "k's member token");
		// The creator leaves: idx 0's token stops, k's admin token does not.
		expect(await ok(await revoke(r.id, r.adminToken, "self"))).toEqual({ membership: 3 });
		await refused(await members(r.id, r.adminToken), 401, "revoked");
		const later = await minted(r.id, kAdmin.token);
		expect(later).toMatchObject({ idx: 2, from: 0, membership: 4 });
		expect(await ok(await revoke(r.id, kAdmin.token, later.idx))).toEqual({ membership: 5 });
		expect(await ok(await put(r.id, kAdmin.token, 5, b64("roster removed [2]"), { bump: true }))).toEqual({ seq: 0, membership: 6 });
		// A record put with either of idx 1's tokens is idx 1's.
		expect(await ok(await put(r.id, k.token, 6))).toEqual({ seq: 1, membership: 6 });
		expect(await sqlOf(r.id, "SELECT seq, idx FROM records ORDER BY seq")).toEqual([
			{ seq: 0, idx: 1 },
			{ seq: 1, idx: 1 },
		]);
		expect((await ok<Listed>(await members(r.id, kAdmin.token))).members).toEqual([
			{ idx: 0, role: "write", from: 0, admin: true, revoked: true },
			{ idx: 1, role: "write", from: 0, admin: true, revoked: false },
			{ idx: 2, role: "write", from: 0, admin: false, revoked: true },
		]);
		// Admin goes to a live write idx only.
		const rd = await minted(r.id, kAdmin.token, "read");
		await refused(await grant(r.id, kAdmin.token, rd.idx), 403, "read_only", "a read idx");
		await refused(await grant(r.id, kAdmin.token, later.idx), 404, "no_such_member", "a revoked idx");
		await refused(await grant(r.id, kAdmin.token, 99), 404, "no_such_member", "an idx never minted");
		await refused(await grant(r.id, k.token, k.idx), 403, "not_admin");
		for (const idx of [-1, 1.5, "1", null, IDX_MAX + 1]) await refused(await grant(r.id, kAdmin.token, idx), 400, "bad_request", String(idx));
	});

	it("refuses a wrong, missing or other room's token, and an unknown room", async () => {
		const r = await open();
		const other = await open();
		const w = await minted(r.id, r.adminToken);
		for (const [what, token] of [
			["another room's admin token", other.adminToken],
			["a random token", "A".repeat(43)],
			["a malformed token", "not-a-token"],
		] as const) {
			await refused(await put(r.id, token, 1), 401, "bad_token", what);
			await refused(await call(`/peer/r/${r.id}/records`, { token }), 401, "bad_token", what);
			await refused(await stateOf(r.id, token), 401, "bad_token", what);
			await refused(await mint(r.id, token, "write"), 401, "bad_token", what);
			await refused(await members(r.id, token), 401, "bad_token", what);
			await refused(await revoke(r.id, token, "self"), 401, "bad_token", what);
			await refused(await grant(r.id, token, 0), 401, "bad_token", what);
		}
		await refused(await call(`/peer/r/${r.id}/records`), 401, "bad_token", "no token");
		// A member token opens its own room and no other.
		await refused(await put(other.id, w.token, 0), 401, "bad_token");
		const unknown = "0".repeat(32);
		await refused(await put(unknown, r.adminToken, 0), 404, "no_such_room", "put");
		await refused(await call(`/peer/r/${unknown}/records`, { token: r.adminToken }), 404, "no_such_room", "pull");
		await refused(await mint(unknown, r.adminToken, "write"), 404, "no_such_room", "mint");
		await refused(await members(unknown, r.adminToken), 404, "no_such_room", "members");
		await refused(await revoke(unknown, r.adminToken, 1), 404, "no_such_room", "revoke");
		await refused(await grant(unknown, r.adminToken, 0), 404, "no_such_room", "admin");
		await refused(await call("/peer/r/NOT-AN-ID/records", { token: r.adminToken }), 404, "no_such_room", "a malformed id");
		// Nothing was written for the id nobody created.
		expect(await sqlOf(unknown, "SELECT name FROM sqlite_master WHERE name = 'room'")).toEqual([]);
	});

	it("caps a record at 1 MiB decoded and refuses what is not a sealed record", async () => {
		const r = await open();
		expect(await ok(await put(r.id, r.adminToken, 0, b64Of(BODY_MAX)))).toEqual({ seq: 0, membership: 0 });
		await refused(await put(r.id, r.adminToken, 0, b64Of(BODY_MAX + 1)), 413, "too_large");
		for (const body of ["", "abc", "ab=c", "YQ", 42]) await refused(await put(r.id, r.adminToken, 0, body), 400, "bad_request", `body ${body}`);
		for (const membership of [undefined, -1, 0.5, "0", null]) await refused(await put(r.id, r.adminToken, membership), 400, "bad_request", `membership ${membership}`);
		await refused(await put(r.id, r.adminToken, 0, b64("x"), { bump: "yes" }), 400, "bad_request", "bump");
		await refused(await put(r.id, r.adminToken, 0, b64("x"), { type: "msg" }), 400, "bad_request", "type");
		await refused(await call(`/peer/r/${r.id}/records`, { method: "POST", token: r.adminToken, body: "{not json" }), 400, "bad_request");
		// Nothing refused took a number.
		expect(await ok(await put(r.id, r.adminToken, 0, b64("next")))).toEqual({ seq: 1, membership: 0 });
	});

	it("pages a pull by count and by body size, skipping the caller's own, and the client re-pulls until none", async () => {
		const r = await open();
		const w = await minted(r.id, r.adminToken);
		// Three bodies near the cap: two fit the byte budget, the third is the next page.
		for (let i = 0; i < 3; i++) await ok(await put(r.id, r.adminToken, 1, b64Of(BODY_MAX)));
		expect((await pull(r.id, w.token, -1)).records.map((x) => x.seq)).toEqual([0, 1]);
		expect((await pull(r.id, w.token, 1)).records.map((x) => x.seq)).toEqual([2]);
		expect((await pull(r.id, w.token, 2)).records).toEqual([]);

		// More small rows than one page holds, every fourth the caller's own,
		// written straight into the table.
		const seqs = Array.from({ length: PULL_MAX + 40 }, (_, i) => i + 3);
		await runInDurableObject(roomOf(r.id), (_i, state) => {
			for (const seq of seqs)
				state.storage.sql.exec("INSERT INTO records (seq, idx, type, body, at) VALUES (?, ?, 'sealed', 'AA==', ?)", seq, seq % 4 === 0 ? w.idx : 0, Date.now());
		});
		const theirs = seqs.filter((s) => s % 4 !== 0);
		const page = (await pull(r.id, w.token, 2)).records;
		expect(page.map((x) => x.seq)).toEqual(theirs.slice(0, PULL_MAX));
		expect((await pull(r.id, w.token, page.at(-1)!.seq)).records.map((x) => x.seq)).toEqual(theirs.slice(PULL_MAX));
		// The state route pages the same way, the caller's own rows in its pages.
		const all = (await state(r.id, w.token, 2)).records.map((x) => x.seq);
		expect(all).toEqual(seqs.slice(0, PULL_MAX));
		expect((await state(r.id, w.token, all.at(-1)!)).records.map((x) => x.seq)).toEqual(seqs.slice(PULL_MAX));
		expect((await state(r.id, w.token, -1)).records.map((x) => x.seq)).toEqual([0, 1]);
		for (const after of ["x", "-2", "1.5"]) await refused(await call(`/peer/r/${r.id}/records?after=${after}`, { token: w.token }), 400, "bad_request", after);
	});

	it("drops records older than 30 days on the alarm, keeps the members, and never reuses a seq", async () => {
		const r = await open();
		const w = await minted(r.id, r.adminToken);
		await ok(await put(r.id, r.adminToken, 1, b64("old")));
		await ok(await put(r.id, r.adminToken, 1, b64("kept")));
		const old = Date.now() - RETENTION_MS - 60_000;
		await sqlOf(r.id, "UPDATE records SET at = ? WHERE seq = 0", old);

		expect(await runDurableObjectAlarm(roomOf(r.id))).toBe(true);
		expect(await sqlOf(r.id, "SELECT seq FROM records")).toEqual([{ seq: 1 }]);
		const kept = (await sqlOf<{ at: number }>(r.id, "SELECT at FROM records"))[0]!.at;
		expect(await runInDurableObject(roomOf(r.id), (_i, state) => state.storage.getAlarm())).toBe(kept + RETENTION_MS + 1);
		expect((await pull(r.id, w.token)).records.map((x) => atob(x.body))).toEqual(["kept"]);
		// The state route shows the alarm armed for the oldest record left.
		const after = await state(r.id, w.token);
		expect([after.room.alarm, after.room.next, after.log]).toEqual([kept + RETENTION_MS + 1, 2, { count: 1, first: 1, oldest: kept }]);

		// The log emptied: the next record is #2, not #0 again, and every member still opens the room.
		await sqlOf(r.id, "UPDATE records SET at = ?", old);
		expect(await runDurableObjectAlarm(roomOf(r.id))).toBe(true);
		expect(await sqlOf(r.id, "SELECT seq FROM records")).toEqual([]);
		expect(await ok(await put(r.id, w.token, 1, b64("new")))).toEqual({ seq: 2, membership: 1 });
		expect((await pull(r.id, r.adminToken, 1)).records.map((x) => atob(x.body))).toEqual(["new"]);
	});

	it(`mints no idx past ${IDX_MAX}: a stanza names its recipient in a uint16 and 65535 is the feed link's`, async () => {
		const r = await open();
		await sqlOf(r.id, "INSERT INTO members (idx, role, from_seq, created) VALUES (?, 'write', 0, ?)", IDX_MAX, Date.now());
		await refused(await mint(r.id, r.adminToken, "write"), 413, "too_large");
		expect(await sqlOf(r.id, "SELECT membership FROM room")).toEqual([{ membership: 0 }]);
	});

	it("answers the feed landing text and refuses what is not a room route", async () => {
		const id = "a".repeat(32);
		const res = await call(`/peer/f/${id}`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toMatch(/^text\/plain/);
		const text = await res.text();
		expect(text).toContain(`go install github.com/caoer/peer/cmd/peer@${RELEASE_TAG}`);
		expect(text.indexOf("go install")).toBeLessThan(text.indexOf("peer room follow '<the link>'"));
		const head = await call(`/peer/f/${id}`, { method: "HEAD" });
		expect(head.status).toBe(200);
		expect(await head.text()).toBe("");
		await refused(await call("/peer/f/nope"), 404, "no_such_room");
		await refused(await call(`/peer/f/${id}`, { method: "POST" }), 405, "method_not_allowed");
		await refused(await call("/peer/rooms"), 405, "method_not_allowed");
		await refused(await call(`/peer/r/${id}/records`, { method: "DELETE" }), 405, "method_not_allowed");
		await refused(await call(`/peer/r/${id}/members`, { method: "PUT" }), 405, "method_not_allowed");
		await refused(await call(`/peer/r/${id}/members/1`), 405, "method_not_allowed");
		await refused(await call(`/peer/r/${id}/admin`), 405, "method_not_allowed");
		await refused(await call(`/peer/r/${id}/state`, { method: "DELETE" }), 405, "method_not_allowed");
		await refused(await call(`/peer/r/${id}`), 404, "no_such_route");
		await refused(await call(`/peer/r/${id}/elsewhere`), 404, "no_such_route");
		await refused(await call(`/peer/r/${id}/members/1/more`, { method: "DELETE" }), 404, "no_such_route");
		expect(await (await SELF.fetch(`${ORIGIN}/peer/`)).text()).toContain("POST /peer/rooms");
	});
});

// A push socket on the records route: every text frame kept as it arrives.
const upgrade = (id: string, token?: string) => call(`/peer/r/${id}/records`, { token, headers: { upgrade: "websocket" } });
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
	const rows = () => raw.filter((f) => f !== PONG).map((f) => JSON.parse(f) as Rec);
	// The first `count` rows, waiting for them.
	const take = async (count: number) => {
		const until = Date.now() + FRAME_WAIT_MS;
		while (rows().length < count && Date.now() < until) await sleep(10);
		expect(rows().length, JSON.stringify(raw).slice(0, 500)).toBeGreaterThanOrEqual(count);
		return rows().slice(0, count);
	};
	return { ws, raw, rows, take, closed };
};

describe("peer room push", () => {
	it("pushes each record to every other member's sockets as the row a pull answers, never to the writer's own", async () => {
		const r = await open();
		const b = await minted(r.id, r.adminToken);
		const c = await minted(r.id, r.adminToken, "read");
		const sa = await connect(r.id, r.adminToken);
		const sb = await connect(r.id, b.token);
		const sc = await connect(r.id, c.token);

		const landed = await ok<{ seq: number }>(await put(r.id, r.adminToken, c.membership, b64("a0")));
		const [frame] = await sb.take(1);
		// The row is in the table by the time its frame arrives.
		expect((await pull(r.id, b.token)).records).toEqual([frame]);
		expect(frame).toEqual({ seq: landed.seq, idx: 0, type: "sealed", body: b64("a0"), at: expect.any(Number) });
		expect(await sc.take(1)).toEqual([frame]);

		await ok(await put(r.id, b.token, c.membership, b64("b0")));
		const [fromB] = await sa.take(1);
		expect(fromB).toMatchObject({ idx: b.idx, body: b64("b0") });
		expect((await sc.take(2))[1]).toEqual(fromB);

		// A member never hears its own puts.
		await sleep(200);
		expect(sa.rows()).toEqual([fromB]);
		expect(sb.rows()).toEqual([frame]);
	});

	it("refuses an upgrade as the pull refuses: a revoked token 401 revoked, a bad or missing one bad_token, an unknown room", async () => {
		const r = await open();
		const other = await open();
		const b = await minted(r.id, r.adminToken);
		await ok(await revoke(r.id, r.adminToken, b.idx));
		const res = await upgrade(r.id, b.token);
		expect(res.webSocket).toBeNull();
		await refused(res, 401, "revoked");
		for (const [what, token] of [
			["no token", undefined],
			["another room's admin token", other.adminToken],
			["a malformed token", "not-a-token"],
		] as const) {
			const res = await upgrade(r.id, token);
			expect(res.webSocket, what).toBeNull();
			await refused(res, 401, "bad_token", what);
		}
		await refused(await upgrade("0".repeat(32), r.adminToken), 404, "no_such_room");
	});

	it("closes every socket of a revoked idx with 4401 and leaves the others open and receiving", async () => {
		const r = await open();
		const b = await minted(r.id, r.adminToken);
		const d = await minted(r.id, r.adminToken);
		const sa = await connect(r.id, r.adminToken);
		const sb1 = await connect(r.id, b.token);
		const sb2 = await connect(r.id, b.token);
		const sd = await connect(r.id, d.token);

		const gone = await ok<{ membership: number }>(await revoke(r.id, r.adminToken, b.idx));
		expect(await sb1.closed).toMatchObject({ code: CLOSE_BAD_TOKEN, reason: "revoked" });
		expect(await sb2.closed).toMatchObject({ code: CLOSE_BAD_TOKEN, reason: "revoked" });
		await ok(await put(r.id, d.token, gone.membership, b64("after")));
		expect((await sa.take(1))[0]!.body).toBe(b64("after"));
		expect(sa.ws.readyState).toBe(WebSocket.OPEN);

		// A leave closes the leaver's own sockets the same way.
		const left = await ok<{ membership: number }>(await revoke(r.id, d.token, "self"));
		expect(await sd.closed).toMatchObject({ code: CLOSE_BAD_TOKEN, reason: "revoked" });
		await ok(await put(r.id, r.adminToken, left.membership, b64("still")));
		await sleep(200);
		expect(sa.ws.readyState).toBe(WebSocket.OPEN);
	});

	it("answers ping with pong, and closes a socket whose token stopped opening the room", async () => {
		const r = await open();
		const b = await minted(r.id, r.adminToken);
		const sa = await connect(r.id, r.adminToken);
		sa.ws.send(PING);
		const until = Date.now() + FRAME_WAIT_MS;
		while (!sa.raw.includes(PONG) && Date.now() < until) await sleep(10);
		expect(sa.raw).toEqual([PONG]);
		// Any other client frame is read as nothing while the token still opens the room.
		sa.ws.send("hello");
		await sleep(200);
		expect(sa.ws.readyState).toBe(WebSocket.OPEN);

		const sb = await connect(r.id, b.token);
		await sqlOf(r.id, "UPDATE tokens SET hash = ? WHERE idx = ?", "0".repeat(64), b.idx);
		sb.ws.send("hello");
		expect(await sb.closed).toMatchObject({ code: CLOSE_BAD_TOKEN, reason: "bad_token" });
	});

	it(`holds at most ${SOCKETS_PER_IDX} sockets per idx and refuses the next with too_many_sockets`, async () => {
		const r = await open();
		const b = await minted(r.id, r.adminToken);
		const held = [];
		for (let i = 0; i < SOCKETS_PER_IDX; i++) held.push(await connect(r.id, b.token));
		const over = await upgrade(r.id, b.token);
		expect(over.webSocket).toBeNull();
		await refused(over, 429, "too_many_sockets");
		// Another idx's places are its own.
		await connect(r.id, r.adminToken);
		// A closed socket gives its place back.
		held[0]!.ws.close(1000, "bye");
		await held[0]!.closed;
		await connect(r.id, b.token);
		// Every held socket still receives.
		await ok(await put(r.id, r.adminToken, b.membership, b64("all")));
		for (const s of held.slice(1)) expect((await s.take(1))[0]!.body).toBe(b64("all"));
	});

	it(`gives a socket silent past ${SILENT_MS / 1000} s its place back, and keeps one that pinged`, async () => {
		const r = await open();
		const b = await minted(r.id, r.adminToken);
		const held = [];
		for (let i = 0; i < SOCKETS_PER_IDX; i++) held.push(await connect(r.id, b.token));
		// Connections lost without a close stay OPEN on the relay and fall silent.
		await runInDurableObject(roomOf(r.id), (_i, state) => {
			for (const ws of state.getWebSockets(`idx:${b.idx}`))
				ws.serializeAttachment({ ...(ws.deserializeAttachment() as object), at: Date.now() - SILENT_MS - 1 });
		});
		const live = held[0]!;
		live.ws.send(PING);
		const until = Date.now() + FRAME_WAIT_MS;
		while (!live.raw.includes(PONG) && Date.now() < until) await sleep(10);
		expect(live.raw).toEqual([PONG]);

		// The reconnect gets a socket, not too_many_sockets.
		const again = await connect(r.id, b.token);
		for (const s of held.slice(1)) expect(await s.closed).toMatchObject({ code: CLOSE_SILENT, reason: "silent" });
		await ok(await put(r.id, r.adminToken, b.membership, b64("after")));
		for (const s of [live, again]) expect((await s.take(1))[0]!.body).toBe(b64("after"));
	});

	it("keeps its sockets, their idx and their token through the object's hibernation", async () => {
		const r = await open();
		const b = await minted(r.id, r.adminToken);
		const d = await minted(r.id, r.adminToken);
		const sa = await connect(r.id, r.adminToken);
		const sb = await connect(r.id, b.token);
		await evictDurableObject(roomOf(r.id));

		// A put after the wake reaches the other idx and not the writer.
		await ok(await put(r.id, r.adminToken, d.membership, b64("woke")));
		expect((await sb.take(1))[0]).toMatchObject({ idx: 0, body: b64("woke") });
		await sleep(200);
		expect(sa.rows()).toEqual([]);

		// The tag survives too: a revoke after the wake closes the idx's socket.
		await evictDurableObject(roomOf(r.id));
		await ok(await revoke(r.id, r.adminToken, b.idx));
		expect(await sb.closed).toMatchObject({ code: CLOSE_BAD_TOKEN, reason: "revoked" });
		expect(sa.ws.readyState).toBe(WebSocket.OPEN);
	});
});
