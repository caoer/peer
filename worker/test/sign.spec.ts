// src/sign.ts — the feed config's signature under the card's delegation.
// test/fixtures/config-signed.json is the fixture cmd/peer/feed_test.go
// writes (-update): the Go side's bytes verified here are the
// cross-implementation check. test/fixtures/card-cases.json is written by
// test/fixtures/gen (go run ./worker/test/fixtures/gen) for the refusal cases.

import { describe, it, expect } from "vitest";
import { MAX_SKEW_MS, b64urlDecode, cardOf, edwardsOf, identityVerifies, signedConfig, signedRead, verifiedBy } from "../src/sign";
import fixture from "./fixtures/config-signed.json";
import cases from "./fixtures/card-cases.json";

const enc = new TextEncoder();
const hex = (s: string) => Uint8Array.from(s.match(/../g)!, (b) => parseInt(b, 16));
const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const atOf = (body: string) => Date.parse((JSON.parse(body) as { at: string }).at);
const p1 = cases.p1;
const p2 = cases.p2;

describe("the fixture cmd/peer wrote", () => {
	it("is the identity key's signature of the PUT body under the root-signed card", async () => {
		const c = await signedConfig(fixture.party, enc.encode(fixture.body), fixture.card, fixture.signature, atOf(fixture.body));
		expect(c).toMatchObject({ v: 1, party: fixture.party });
	});

	it("is the identity key's signature of the X-Peer-At value for the GET", async () => {
		expect(await signedRead(fixture.party, fixture.at, fixture.card, fixture.atSignature, Date.parse(fixture.at))).toBeNull();
	});
});

describe("the card", () => {
	it("yields the current identity key when the root signature verifies", async () => {
		const d = await cardOf(p1.party, p1.card);
		expect("identity" in d && d.identity.length).toBe(32);
	});

	it("refuses a card of another party, and never parses one whose signature fails", async () => {
		expect(await cardOf(p1.party, p2.card)).toMatchObject({ status: 401, code: "bad_card", error: expect.stringContaining("not signed by this party's root key") });
		const packed = b64urlDecode(p1.card)!;
		const broken = packed.slice();
		broken[64 + 1] = 0x7b; // the card's JSON no longer parses — and is never reached
		expect(await cardOf(p1.party, b64url(broken))).toMatchObject({ code: "bad_card", error: expect.stringContaining("not signed by this party's root key") });
		expect(await cardOf(p1.party, null)).toMatchObject({ status: 401, code: "bad_card" });
		expect(await cardOf(p1.party, "not*base64url")).toMatchObject({ code: "bad_card" });
		expect(await cardOf(p1.party, b64url(packed.subarray(0, 64)))).toMatchObject({ code: "bad_card" });
	});
});

describe("PUT config", () => {
	const initial = p1.configs.initial;

	it("accepts the identity key's signature over the exact body within the skew", async () => {
		const c = await signedConfig(p1.party, enc.encode(initial.body), p1.card, initial.signature, atOf(initial.body));
		expect(c).toMatchObject({ v: 1, party: p1.party, readers: JSON.parse(initial.body).readers });
	});

	it("refuses the same body signed by the root key, naming it", async () => {
		expect(await signedConfig(p1.party, enc.encode(p1.rootSigned.body), p1.card, p1.rootSigned.signature, atOf(p1.rootSigned.body))).toMatchObject({ status: 401, code: "root_signed" });
	});

	it("refuses a tampered body, another party's card, and a missing signature", async () => {
		const now = atOf(initial.body);
		expect(await signedConfig(p1.party, enc.encode(initial.body + " "), p1.card, initial.signature, now)).toMatchObject({ status: 401, code: "bad_signature" });
		expect(await signedConfig(p1.party, enc.encode(initial.body), p2.card, initial.signature, now)).toMatchObject({ status: 401, code: "bad_card" });
		expect(await signedConfig(p1.party, enc.encode(initial.body), p1.card, null, now)).toMatchObject({ status: 401, code: "bad_signature" });
		expect(await signedConfig(p1.party, enc.encode(initial.body), p1.card, p2.configs.initial.signature, now)).toMatchObject({ status: 401, code: "bad_signature" });
	});

	it("refuses an at outside five minutes and a body that is not a config", async () => {
		const at = atOf(initial.body);
		for (const now of [at + MAX_SKEW_MS + 1000, at - MAX_SKEW_MS - 1000])
			expect(await signedConfig(p1.party, enc.encode(initial.body), p1.card, initial.signature, now)).toMatchObject({ status: 401, code: "stale" });
		for (const body of ["not json", "{}", JSON.stringify({ v: 2, party: p1.party, at: "2026-11-08T16:00:00Z", source: "sha256:" + "a".repeat(64), readers: [] })])
			expect(await signedConfig(p1.party, enc.encode(body), p1.card, initial.signature, at)).toMatchObject({ status: 400, code: "bad_request" });
	});
});

describe("GET config", () => {
	it("takes the identity key's signature over the X-Peer-At bytes, not over the empty body", async () => {
		const now = Date.parse(p1.read.at);
		expect(await signedRead(p1.party, p1.read.at, p1.card, p1.read.signature, now)).toBeNull();
		expect(await signedRead(p1.party, p1.read.at, p1.card, p1.read.emptySignature, now)).toMatchObject({ status: 401, code: "bad_signature" });
		expect(await signedRead(p1.party, p1.read.at, p2.card, p1.read.signature, now)).toMatchObject({ status: 401, code: "bad_card" });
		expect(await signedRead(p1.party, p1.read.at, p1.card, null, now)).toMatchObject({ status: 401, code: "bad_signature" });
		expect(await signedRead(p1.party, null, p1.card, p1.read.signature, now)).toMatchObject({ status: 401, code: "bad_signature" });
	});

	it("refuses a stale X-Peer-At even when signed", async () => {
		expect(await signedRead(p1.party, p1.read.at, p1.card, p1.read.signature, Date.parse(p1.read.at) + MAX_SKEW_MS + 1000)).toMatchObject({ status: 401, code: "stale" });
	});
});

describe("XEdDSA as libsignal spells it", () => {
	// libsignal-protocol-java Curve25519Test.testSignature: Alice's identity
	// key signs her serialized ephemeral public key (0x05 ‖ 32 bytes).
	const identity = hex("ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64");
	const message = hex("05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a");
	const signature = hex("5de88ca9a89b4a115da79109c67c9c7464a3e4180274f1cb8c63c2984e286dfbede82deb9dcd9fae0bfbb821569b3d9001bd8130cd11d486cef047bd60b86e88");

	it("verifies the known vector through edwardsOf and refuses it altered", async () => {
		expect(await identityVerifies(identity, message, signature)).toBe(true);
		const flipped = signature.slice();
		flipped[0]! ^= 1;
		expect(await identityVerifies(identity, message, flipped)).toBe(false);
		const other = message.slice();
		other[5]! ^= 1;
		expect(await identityVerifies(identity, other, signature)).toBe(false);
		expect(await identityVerifies(identity, message, signature.subarray(0, 63))).toBe(false);
	});

	it("maps u to y = (u − 1)/(u + 1) with the sign bit the signature carries, and refuses u ≡ −1", () => {
		const y0 = edwardsOf(identity, 0)!;
		const y1 = edwardsOf(identity, 1)!;
		expect(y0.length).toBe(32);
		expect(y0[31]! & 0x80).toBe(0);
		expect(y1[31]! & 0x80).toBe(0x80);
		expect(y1.subarray(0, 31)).toEqual(y0.subarray(0, 31));
		// u = 9, the base point: y = 8/10 = 4/5 — Ed25519's base point y.
		const nine = new Uint8Array(32);
		nine[0] = 9;
		expect(b64url(edwardsOf(nine, 0)!)).toBe(b64url(hex("5866666666666666666666666666666666666666666666666666666666666666")));
		const minusOne = hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		expect(edwardsOf(minusOne, 0)).toBeNull();
		expect(edwardsOf(new Uint8Array(31), 0)).toBeNull();
	});
});

describe("verifiedBy and base64url", () => {
	it("verifies the root's own signature and refuses a malformed party id or signature without throwing", async () => {
		expect(await verifiedBy(p1.party, enc.encode(p1.rootSigned.body), p1.rootSigned.signature)).toBe(true);
		expect(await verifiedBy("ed25519:short", enc.encode("x"), p1.rootSigned.signature)).toBe(false);
		expect(await verifiedBy(p1.party, enc.encode("x"), "not*base64url")).toBe(false);
		expect(await verifiedBy(p1.party, enc.encode("x"), p1.rootSigned.signature.slice(0, 40))).toBe(false);
	});

	it("decodes unpadded base64url and refuses a length no encoding produces", () => {
		expect([...b64urlDecode("_-8")!]).toEqual([0xff, 0xef]);
		expect(b64urlDecode("A")).toBeNull();
		expect(b64urlDecode("AB=")).toBeNull();
	});
});
