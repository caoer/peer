// limiter-double-options.mjs — what a vitest config needs to bind
// test/helpers/limiter-double.mjs under each ratelimit its wrangler config
// declares, at that binding's configured limit.
//
// A miniflare option cannot remove a binding the wrangler config declares (the
// plugin merges overrides into it), and the double's service binding takes the
// same names. So the suite runs on a copy of the wrangler config without its
// `ratelimits`: `<name>.vitest.gen.json`, written beside the original so
// every relative path in it resolves the same (.gitignore: wrangler.*.gen.json).

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function limiterDouble(wranglerConfig) {
	const path = fileURLToPath(wranglerConfig);
	const { ratelimits = [], ...rest } = JSON.parse(readFileSync(path, "utf8").replace(/^\s*\/\/.*$/gm, ""));
	const configPath = path.replace(/\.jsonc$/, ".vitest.gen.json");
	writeFileSync(configPath, JSON.stringify(rest, null, "\t") + "\n");
	const serviceBindings = {};
	for (const r of ratelimits) {
		if (typeof r?.simple?.limit !== "number") throw new Error(`${r?.name}: no simple.limit in ${path}`);
		serviceBindings[r.name] = { name: "limiter-double", entrypoint: "Limiter", props: { name: r.name, limit: r.simple.limit } };
	}
	return {
		configPath,
		miniflare: {
			serviceBindings,
			workers: [
				{
					name: "limiter-double",
					modules: true,
					scriptPath: fileURLToPath(new URL("./limiter-double.mjs", import.meta.url)),
					compatibilityDate: rest.compatibility_date,
				},
			],
		},
	};
}
