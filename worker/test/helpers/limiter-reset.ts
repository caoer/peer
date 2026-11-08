// Every test starts with the limiter double's counts empty
// (test/helpers/limiter-double.mjs). reset() clears every binding's counts.
import { env } from "cloudflare:test";
import { beforeEach } from "vitest";

beforeEach(async () => {
	await (env as unknown as { PEER_HITS: { reset(): Promise<void> } }).PEER_HITS.reset();
});
