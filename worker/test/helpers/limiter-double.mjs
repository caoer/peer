// limiter-double.mjs — the suite's rate limiter: an auxiliary Worker both
// vitest configs bind under every ratelimit name in place of miniflare's
// (test/helpers/limiter-double-options.mjs).
//
// It answers `limit({ key })` as the Workers binding does — `{ success }`, the
// first `limit` calls per key admitted, every later one refused — with the
// limit wrangler.jsonc configures for that binding. Its window never rolls on
// the clock: counts start empty before each test (test/helpers/limiter-reset.ts)
// and hold until the next. miniflare counts in fixed 10 s windows of the real
// clock, and a loaded CI runner stretches a limit+5 burst past 10 s (pipeline
// 1127: 105 requests to a route that does nothing after the limiter took
// 15.7 s), so a test against it measured the runner, not the Worker.

import { WorkerEntrypoint } from "cloudflare:workers";

const counts = new Map();

export class Limiter extends WorkerEntrypoint {
	async limit(options) {
		const { name, limit } = this.ctx.props;
		const id = `${name}\u0000${options?.key ?? ""}`;
		const n = counts.get(id) ?? 0;
		if (n >= limit) return { success: false };
		counts.set(id, n + 1);
		return { success: true };
	}

	async reset() {
		counts.clear();
	}
}

export default {
	fetch() {
		return new Response("the limiter double answers RPC only", { status: 404 });
	},
};
