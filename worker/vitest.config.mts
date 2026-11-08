import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import {
	assertRuntimeHonoursDate,
	readRequestedDate,
	readSupportedDate,
	resolveWorkerdPkg,
} from './runtime-gate.mjs';
import { limiterDouble } from './test/helpers/limiter-double-options.mjs';

// The suite must run on the workerd the Worker deploys on: the gate refuses a
// pool whose workerd cannot honour wrangler.jsonc's compatibility_date.
const workerdPkg = resolveWorkerdPkg();
assertRuntimeHonoursDate({
	workerdPkg,
	requested: readRequestedDate(new URL('./wrangler.jsonc', import.meta.url)),
	supported: readSupportedDate(workerdPkg),
	wranglerPath: 'wrangler.jsonc',
});

const double = limiterDouble(new URL('./wrangler.jsonc', import.meta.url));

export default defineConfig({
	plugins: [
		cloudflareTest({
			// PEER_HITS is the limiter double, at the limit wrangler.jsonc gives
			// it (test/helpers/limiter-double.mjs).
			wrangler: { configPath: double.configPath },
			miniflare: {
				...double.miniflare,
				// The owner login channel.spec.ts and room.spec.ts open with.
				bindings: { RELAY_LOGIN: 'peerowner:tok_' + '8'.repeat(16) },
				outboundService: () => new Response('the suite reaches no network', { status: 502 }),
			},
		}),
	],
	test: {
		include: ['test/**/*.spec.ts'],
		setupFiles: ['test/helpers/limiter-reset.ts'],
		// A timeout only a hang reaches, on a loaded CI agent.
		testTimeout: 120_000,
		hookTimeout: 120_000,
	},
});
