// GET /: the reader page, byte for byte the file in worker/reader, with the
// file's own CSP repeated as a header.

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { READER_CACHE } from "../src/reader";
import file from "../reader/index.html?raw";

const ORIGIN = "https://peer.0xtau.com";
const sha256 = async (text: string) =>
	[...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("GET /", () => {
	it("serves worker/reader/index.html as the repo holds it, with its CSP as a header", async () => {
		const res = await SELF.fetch(`${ORIGIN}/`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
		expect(res.headers.get("cache-control")).toBe(READER_CACHE);
		const body = await res.text();
		expect(await sha256(body)).toBe(await sha256(file));
		const meta = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i.exec(file)![1];
		expect(res.headers.get("content-security-policy")).toBe(meta);
		expect(meta).toContain("default-src 'none'");
	});

	it("answers HEAD without a body and refuses other methods", async () => {
		const head = await SELF.fetch(`${ORIGIN}/`, { method: "HEAD" });
		expect(head.status).toBe(200);
		expect(await head.text()).toBe("");
		expect((await SELF.fetch(`${ORIGIN}/`, { method: "POST" })).status).toBe(405);
	});
});
