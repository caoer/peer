// src/sign.ts — the feed config's signature. The fixture
// test/fixtures/config-signed.json is written by cmd/peer/feed_test.go
// (-update): the Go side's bytes, verified here, are the cross-implementation
// check; every other case signs with a party born in the test.

import { describe, it, expect } from "vitest";
import { MAX_SKEW_MS, b64urlDecode, signedConfig, signedRead, verifiedBy } from "../src/sign";
import { newParty } from "./helpers/party";
import fixture from "./fixtures/config-signed.json";

const enc = new TextEncoder();
const HASH = "sha256:" + "a".repeat(64);
const configBody = (party: string, at: string, readers = [HASH]) => JSON.stringify({ v: 1, party, at, source: HASH, readers });

describe("the fixture cmd/peer wrote", () => {
	const at = (JSON.parse(fixture.put.body) as { at: string }).at;

	it("is this party's signature of the PUT body", async () => {
		const c = await signedConfig(fixture.party, enc.encode(fixture.put.body), fixture.put.signature, Date.parse(at));
		expect(c).toMatchObject({ v: 1, party: fixture.party, at });
	});

	it("is this party's signature of the X-Peer-At value for the GET", async () => {
		expect(await signedRead(fixture.party, fixture.get.at, fixture.get.signature, Date.parse(fixture.get.at))).toBeNull();
	});
});

describe("PUT config", () => {
	it("accepts the party's signature over the exact body within the skew, de-duplicating readers", async () => {
		const p = await newParty();
		const at = new Date().toISOString();
		const body = configBody(p.id, at, [HASH, HASH]);
		const c = await signedConfig(p.id, enc.encode(body), await p.sign(body));
		expect(c).toEqual({ v: 1, party: p.id, at, source: HASH, readers: [HASH] });
	});

	it("refuses another party's signature, a changed byte, and a body for another party", async () => {
		const p = await newParty();
		const other = await newParty();
		const at = new Date().toISOString();
		const body = configBody(p.id, at);
		expect(await signedConfig(p.id, enc.encode(body), await other.sign(body))).toMatchObject({ status: 401, code: "bad_signature" });
		expect(await signedConfig(p.id, enc.encode(body + " "), await p.sign(body))).toMatchObject({ status: 401, code: "bad_signature" });
		expect(await signedConfig(p.id, enc.encode(body), null)).toMatchObject({ status: 401, code: "bad_signature" });
		const forOther = configBody(other.id, at);
		expect(await signedConfig(p.id, enc.encode(forOther), await p.sign(forOther))).toMatchObject({ status: 400, code: "bad_request" });
	});

	it("refuses an at outside five minutes and a body that is not a config", async () => {
		const p = await newParty();
		const now = Date.now();
		for (const skew of [MAX_SKEW_MS + 1000, -(MAX_SKEW_MS + 1000)]) {
			const body = configBody(p.id, new Date(now + skew).toISOString());
			expect(await signedConfig(p.id, enc.encode(body), await p.sign(body), now)).toMatchObject({ status: 401, code: "stale" });
		}
		const local = configBody(p.id, "2026-11-08T10:00:00+08:00");
		expect(await signedConfig(p.id, enc.encode(local), await p.sign(local))).toMatchObject({ status: 401, code: "stale" });
		for (const body of ["not json", "{}", JSON.stringify({ v: 2, party: p.id, at: new Date().toISOString(), source: HASH, readers: [] }), JSON.stringify({ v: 1, party: p.id, at: new Date().toISOString(), source: "md5:x", readers: [] })])
			expect(await signedConfig(p.id, enc.encode(body), await p.sign(body))).toMatchObject({ status: 400, code: "bad_request" });
	});
});

describe("GET config", () => {
	it("takes the signature over the X-Peer-At bytes, not over the empty body", async () => {
		const p = await newParty();
		const at = new Date().toISOString();
		expect(await signedRead(p.id, at, await p.sign(at))).toBeNull();
		expect(await signedRead(p.id, at, await p.sign(new Uint8Array(0)))).toMatchObject({ status: 401, code: "bad_signature" });
		expect(await signedRead(p.id, at, null)).toMatchObject({ status: 401, code: "bad_signature" });
		expect(await signedRead(p.id, null, await p.sign(at))).toMatchObject({ status: 401, code: "bad_signature" });
	});

	it("refuses a stale X-Peer-At even when signed", async () => {
		const p = await newParty();
		const at = new Date(Date.now() - MAX_SKEW_MS - 1000).toISOString();
		expect(await signedRead(p.id, at, await p.sign(at))).toMatchObject({ status: 401, code: "stale" });
	});
});

describe("verifiedBy and base64url", () => {
	it("refuses a malformed party id or signature without throwing", async () => {
		const p = await newParty();
		const sig = await p.sign("x");
		expect(await verifiedBy("ed25519:short", enc.encode("x"), sig)).toBe(false);
		expect(await verifiedBy(p.id, enc.encode("x"), "not*base64url")).toBe(false);
		expect(await verifiedBy(p.id, enc.encode("x"), sig.slice(0, 40))).toBe(false);
		expect(await verifiedBy(p.id, enc.encode("x"), sig)).toBe(true);
	});

	it("decodes unpadded base64url and refuses a length no encoding produces", () => {
		expect([...b64urlDecode("_-8")!]).toEqual([0xff, 0xef]);
		expect(b64urlDecode("A")).toBeNull();
		expect(b64urlDecode("AB=")).toBeNull();
	});
});
