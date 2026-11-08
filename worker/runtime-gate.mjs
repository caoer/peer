// Suite must run on the workerd the service deploys.
// Resolves pool → miniflare → workerd; fails if compatibility date unsupported.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const DATE = /^\d{4}-\d{2}-\d{2}$/;
export function resolveWorkerdPkg() {
  const poolEntry = fileURLToPath(import.meta.resolve("@cloudflare/vitest-plugin"));
  const miniflarePkg = createRequire(poolEntry).resolve("miniflare/package.json");
  return createRequire(miniflarePkg).resolve("workerd/package.json");
}
export function readRequestedDate(wranglerUrl) {
  const raw = readFileSync(wranglerUrl, "utf8").replace(/^\s*\/\/.*$/gm, "");
  return JSON.parse(raw).compatibility_date;
}
export function readSupportedDate(workerdPkg) {
  return createRequire(workerdPkg)("workerd").compatibilityDate;
}
export function assertRuntimeHonoursDate({ requested, supported, workerdPkg, wranglerPath = "wrangler.jsonc" }) {
  for (const [side, value, where] of [
    ["wrangler.jsonc compatibility_date", requested, wranglerPath],
    ["workerd compatibilityDate", supported, workerdPkg],
  ]) {
    if (typeof value !== "string" || !DATE.test(value)) {
      throw new Error(`runtime gate: ${side} is not a YYYY-MM-DD date (got ${JSON.stringify(value)}) — read from ` +
        `${where}. Refusing to compare, because an unparseable operand compares false against ` +
        `everything and would let this gate pass on nothing.`);
    }
  }
  if (supported < requested) {
    throw new Error(`runtime gate: wrangler.jsonc asks for compatibility_date ${requested}, but the workerd the ` +
      `pool will load only supports ${supported} (${workerdPkg}). miniflare would silently fall ` +
      `back and the suite would test a runtime the service does not run on. Bump the dependency ` +
      `that pins that workerd — miniflare, via @cloudflare/vitest-plugin — or lower the date.`);
  }
}
