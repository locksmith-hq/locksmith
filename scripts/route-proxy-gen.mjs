#!/usr/bin/env node
// B5: compile apps/api/route-table.json into a Caddy JSON config for the local api-proxy.
// Usage: node scripts/route-proxy-gen.mjs <route-table.json> <out.json>
// Only `nest` routes get a matcher; everything else (unknown path, unknown method) goes to Rust.
// Upstreams: LOCKSMITH_RUST_UPSTREAM (default host.docker.internal:8080), LOCKSMITH_NEST_UPSTREAM
// (default host.docker.internal:8081). The output is sorted and byte-stable.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const OWNERS = new Set(["rust", "nest"]);

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
}

/** `/v1/orgs/{org_id}/x` -> anchored regex string; `{name}` matches one segment. */
export function pathToRegex(path) {
  const parts = path.split(/(\{[^}/]+\})/).map((p) => (/^\{[^}/]+\}$/.test(p) ? "[^/]+" : escapeRegex(p)));
  return `^${parts.join("")}$`;
}

function literalSegments(path) {
  return path.split("/").filter((s) => s && !/^\{.*\}$/.test(s)).length;
}

export function generate(table, env = process.env) {
  const rust = env.LOCKSMITH_RUST_UPSTREAM || "host.docker.internal:8080";
  const nest = env.LOCKSMITH_NEST_UPSTREAM || "host.docker.internal:8081";
  const routes = table?.routes;
  if (!Array.isArray(routes)) throw new Error("route table has no routes array");
  for (const r of routes) {
    if (!OWNERS.has(r.owner)) {
      throw new Error(`route ${r.method} ${r.path}: owner must be "rust" or "nest", got ${JSON.stringify(r.owner)}`);
    }
  }
  const upstream = (name, dial) => ({
    handler: "reverse_proxy",
    upstreams: [{ dial }],
    flush_interval: -1,
    headers: { response: { set: { "X-Locksmith-Upstream": [name] } } },
  });
  const nestRoutes = routes
    .filter((r) => r.owner === "nest")
    .map((r) => ({ method: r.method.toUpperCase(), path: r.path }))
    .sort(
      (a, b) =>
        literalSegments(b.path) - literalSegments(a.path) ||
        a.path.localeCompare(b.path) ||
        a.method.localeCompare(b.method),
    )
    .map((r) => ({
      match: [{ method: [r.method], path_regexp: { pattern: pathToRegex(r.path) } }],
      handle: [upstream("nest", nest)],
    }));
  const defaultRoute = { handle: [upstream("rust", rust)] };
  return {
    admin: { disabled: true },
    apps: {
      http: {
        servers: {
          api: { listen: [":8088"], routes: [...nestRoutes, defaultRoute] },
        },
      },
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [tablePath, outPath] = process.argv.slice(2);
  if (!tablePath || !outPath) {
    console.error("usage: route-proxy-gen.mjs <route-table.json> <out.json>");
    process.exit(2);
  }
  try {
    const cfg = generate(JSON.parse(readFileSync(tablePath, "utf8")));
    writeFileSync(outPath, JSON.stringify(cfg, null, 2) + "\n");
  } catch (e) {
    console.error(`route-proxy-gen: ${e.message}`);
    process.exit(1);
  }
}
