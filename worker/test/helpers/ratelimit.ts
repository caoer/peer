// ratelimit.ts — a rate limiter's configured limit and period, read from
// wrangler.jsonc, so a test derives its burst from the config and a change to
// the config cannot silently desync the two.
//
// Under the suite every ratelimit binding is the limiter double
// (test/helpers/limiter-double.mjs): it refuses past the configured limit per
// key, its counts empty before each test and never roll on the clock, so a
// burst needs no timing to be counted in one window.

import wranglerConfig from "../../wrangler.jsonc?raw";

export type LimiterName = "PEER_HITS";

export const limiter = (name: LimiterName): { limit: number; period: number } => {
	const raw = wranglerConfig.replace(/^\s*\/\/.*$/gm, "");
	const simple = JSON.parse(raw).ratelimits?.find((r: { name: string }) => r.name === name)?.simple;
	if (typeof simple?.limit !== "number" || typeof simple?.period !== "number")
		throw new Error(`${name} limit or period not found in wrangler.jsonc`);
	return { limit: simple.limit, period: simple.period };
};
