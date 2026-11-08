// What src/index.ts adds around the relay routes, which channel.spec.ts and
// room.spec.ts cannot see: every non-socket answer is private, the route list
// is at /peer/, and nothing else is served (the reader, feed and forward
// routes have their own specs).

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { RELEASE_TAG } from "../src/relay/channel";
import readme from "../../README.md?raw";

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

	it("points an agent at the release README installs", () => {
		const tags = [...readme.matchAll(/github\.com\/caoer\/peer(?:\/cmd\/peer@|\/releases\/tag\/)(v\d+\.\d+\.\d+)/g)].map((m) => m[1]);
		expect(tags.length).toBeGreaterThan(0);
		expect(new Set(tags)).toEqual(new Set([RELEASE_TAG]));
	});
});
