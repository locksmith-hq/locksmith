import { test } from "node:test";
import assert from "node:assert/strict";
import { generate, pathToRegex } from "./route-proxy-gen.mjs";

const env = { LOCKSMITH_RUST_UPSTREAM: "r:1", LOCKSMITH_NEST_UPSTREAM: "n:2" };
const table = (...routes) => ({ routes: routes.map(([method, path, owner]) => ({ method, path, owner })) });
const routesOf = (cfg) => cfg.apps.http.servers.api.routes;
const dial = (r) => r.handle[0].upstreams[0].dial;
// Mimic Caddy: first route whose method and path_regexp match wins, else the matcher-less default.
function pick(cfg, method, path) {
  for (const r of routesOf(cfg)) {
    if (!r.match) return dial(r);
    const m = r.match[0];
    if (m.method.includes(method) && new RegExp(m.path_regexp.pattern).test(path)) return dial(r);
  }
}

test("all rust: only the default route", () => {
  const cfg = generate(table(["GET", "/healthz", "rust"], ["GET", "/v1/orgs/{org_id}", "rust"]), env);
  assert.equal(routesOf(cfg).length, 1);
  assert.equal(pick(cfg, "GET", "/healthz"), "r:1");
});

test("one nest route goes to nest, the rest to rust", () => {
  const cfg = generate(table(["GET", "/healthz", "nest"], ["GET", "/readyz", "rust"]), env);
  assert.equal(pick(cfg, "GET", "/healthz"), "n:2");
  assert.equal(pick(cfg, "GET", "/readyz"), "r:1");
  assert.equal(routesOf(cfg)[0].handle[0].headers.response.set["X-Locksmith-Upstream"][0], "nest");
});

test("templated nest route beside a longer rust route under the same prefix", () => {
  const cfg = generate(table(["GET", "/v1/orgs/{org_id}", "nest"], ["GET", "/v1/orgs/{org_id}/members", "rust"]), env);
  assert.equal(pick(cfg, "GET", "/v1/orgs/abc"), "n:2");
  assert.equal(pick(cfg, "GET", "/v1/orgs/abc/members"), "r:1");
  assert.equal(pick(cfg, "GET", "/v1/orgs/abc/"), "r:1");
});

test("more literal segments are emitted first", () => {
  const cfg = generate(table(["GET", "/v1/{a}/x", "nest"], ["GET", "/v1/orgs/x", "nest"]), env);
  assert.equal(routesOf(cfg)[0].match[0].path_regexp.pattern, pathToRegex("/v1/orgs/x"));
});

test("method mismatch and unknown path go to rust", () => {
  const cfg = generate(table(["GET", "/healthz", "nest"]), env);
  assert.equal(pick(cfg, "POST", "/healthz"), "r:1");
  assert.equal(pick(cfg, "GET", "/nope"), "r:1");
});

test("regex escapes literals", () => {
  const cfg = generate(table(["GET", "/.well-known/jwks.json", "nest"]), env);
  assert.equal(pick(cfg, "GET", "/.well-known/jwks.json"), "n:2");
  assert.equal(pick(cfg, "GET", "/xwell-known/jwksxjson"), "r:1");
});

test("unknown owner fails naming the route", () => {
  assert.throws(() => generate(table(["GET", "/v1/foo", "go"]), env), /GET \/v1\/foo.*"go"/);
});

test("two runs give identical bytes", () => {
  const t = table(["GET", "/b", "nest"], ["POST", "/a/{id}", "nest"], ["GET", "/a/{id}", "nest"]);
  assert.equal(JSON.stringify(generate(t, env)), JSON.stringify(generate(t, env)));
  const reversed = { routes: [...t.routes].reverse() };
  assert.equal(JSON.stringify(generate(t, env)), JSON.stringify(generate(reversed, env)));
});
