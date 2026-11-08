// What src/index.ts adds around the relay routes, which channel.spec.ts and
// room.spec.ts cannot see: every non-socket answer is private, the route list
// is at /peer/, the routes still to come answer not_yet, and nothing else is
// served.

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

const ORIGIN = "https://peer.0xtau.com";

describe("the peer worker", () => {
	it("answers privately and serves nothing but /peer", async () => {
		const landing = await SELF.fetch(`${ORIGIN}/peer/i/${"a".repeat(32)}`, { headers: { "CF-Connecting-IP": "203.0.113.250" } });
		expect(landing.status).toBe(200);
		expect(landing.headers.get("cache-control")).toBe("private, no-store");
		expect(landing.headers.get("x-robots-tag")).toBe("noindex");
		const off = await SELF.fetch(`${ORIGIN}/elsewhere`);
		expect(off.status).toBe(404);
		expect(await off.json()).toMatchObject({ code: "no_such_route" });
	});

	it("prints the route list at /peer and /peer/", async () => {
		for (const path of ["/peer", "/peer/"]) {
			const res = await SELF.fetch(`${ORIGIN}${path}`);
			expect(res.status).toBe(200);
			expect(res.headers.get("content-type")).toMatch(/^text\/plain/);
			expect(await res.text()).toContain("POST /peer/channels");
		}
	});

	it("answers 404 not_yet on the reader and the feed", async () => {
		for (const [method, path] of [["GET", "/"], ["GET", "/feed/x"], ["PUT", "/feed/x/config"]] as const) {
			const res = await SELF.fetch(`${ORIGIN}${path}`, { method });
			expect(res.status, `${method} ${path}`).toBe(404);
			expect(await res.json()).toMatchObject({ code: "not_yet" });
		}
	});
});
