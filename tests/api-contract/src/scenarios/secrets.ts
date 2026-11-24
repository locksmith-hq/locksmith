import type { Ctx, Scenario } from "../scenario.ts";

const missing = "00000000-0000-4000-8000-000000000000";

function idOf(body: unknown): string {
  return (body as { id: string }).id;
}

/** A canary from `just canary new` (the runner script exports it); it is sent, never recorded. */
function canary(): string {
  const v = process.env.API_CONTRACT_CANARY;
  if (!v) throw new Error("API_CONTRACT_CANARY is not set; run through scripts/api-contract.sh");
  return v;
}

async function tree(ctx: Ctx, label: string) {
  const { a } = ctx.seed;
  const p = await ctx.expect(`${label}: project`, 201, {
    method: "POST",
    path: "/v1/projects",
    headers: a.auth,
    body: { name: `sec-${label}-${ctx.seed.run}` },
  });
  const pid = idOf(p.body);
  const e = await ctx.expect(`${label}: environment`, 201, {
    method: "POST",
    path: `/v1/projects/${pid}/environments`,
    headers: a.auth,
    body: { name: "dev" },
  });
  return `/v1/projects/${pid}/environments/${idOf(e.body)}/secrets`;
}

export const scenarios: Scenario[] = [
  {
    id: "secrets",
    covers: [
      "GET /v1/projects/{project_id}/environments/{environment_id}/secrets",
      "POST /v1/projects/{project_id}/environments/{environment_id}/secrets",
      "GET /v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}",
      "PATCH /v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}",
      "DELETE /v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}",
    ],
    async run(ctx) {
      const { a, b } = ctx.seed;
      const base = await tree(ctx, "meta");
      const created = await ctx.expect("create", 201, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { name: "API_KEY", description: "d" },
      });
      const s = idOf(created.body);
      await ctx.expect("create no token", 401, { method: "POST", path: base, body: { name: "x" } });
      await ctx.expect("create missing name", 400, { method: "POST", path: base, headers: a.auth, body: {} });
      await ctx.expect("create duplicate", 409, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { name: "API_KEY" },
      });
      await ctx.expect("create cross-tenant", 404, {
        method: "POST",
        path: base,
        headers: b.auth,
        body: { name: "x" },
      });
      await ctx.expect("list", 200, { method: "GET", path: base, headers: a.auth });
      await ctx.expect("list bad limit", 400, { method: "GET", path: `${base}?limit=0`, headers: a.auth });
      await ctx.expect("list no token", 401, { method: "GET", path: base });
      await ctx.expect("list cross-tenant", 404, { method: "GET", path: base, headers: b.auth });
      await ctx.expect("get", 200, { method: "GET", path: `${base}/${s}`, headers: a.auth });
      await ctx.expect("get no token", 401, { method: "GET", path: `${base}/${s}` });
      await ctx.expect("get cross-tenant", 404, { method: "GET", path: `${base}/${s}`, headers: b.auth });
      await ctx.expect("get missing", 404, { method: "GET", path: `${base}/${missing}`, headers: a.auth });
      await ctx.expect("patch", 200, {
        method: "PATCH",
        path: `${base}/${s}`,
        headers: a.auth,
        body: { description: "changed" },
      });
      await ctx.expect("patch empty name", 400, {
        method: "PATCH",
        path: `${base}/${s}`,
        headers: a.auth,
        body: { name: "" },
      });
      await ctx.expect("patch no token", 401, { method: "PATCH", path: `${base}/${s}`, body: { description: "x" } });
      await ctx.expect("patch cross-tenant", 404, {
        method: "PATCH",
        path: `${base}/${s}`,
        headers: b.auth,
        body: { description: "x" },
      });
      await ctx.expect("delete no token", 401, { method: "DELETE", path: `${base}/${s}` });
      await ctx.expect("delete cross-tenant", 404, { method: "DELETE", path: `${base}/${s}`, headers: b.auth });
      await ctx.expect("delete", 204, { method: "DELETE", path: `${base}/${s}`, headers: a.auth });
      await ctx.expect("get deleted", 404, { method: "GET", path: `${base}/${s}`, headers: a.auth });
    },
  },
  {
    id: "secret-versions",
    covers: [
      "GET /v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}/versions",
      "POST /v1/projects/{project_id}/environments/{environment_id}/secrets/{secret_id}/versions",
    ],
    async run(ctx) {
      const { a, b } = ctx.seed;
      const base = await tree(ctx, "ver");
      const created = await ctx.expect("create secret", 201, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { name: "TOKEN" },
      });
      const v = `${base}/${idOf(created.body)}/versions`;
      await ctx.expect("write version", 201, { method: "POST", path: v, headers: a.auth, body: { value: canary() } });
      await ctx.expect("write second version", 201, {
        method: "POST",
        path: v,
        headers: a.auth,
        body: { value: canary() },
      });
      await ctx.expect("write missing value", 400, { method: "POST", path: v, headers: a.auth, body: {} });
      await ctx.expect("write no token", 401, { method: "POST", path: v, body: { value: canary() } });
      await ctx.expect("write cross-tenant", 404, {
        method: "POST",
        path: v,
        headers: b.auth,
        body: { value: canary() },
      });
      await ctx.expect("write missing secret", 404, {
        method: "POST",
        path: `${base}/${missing}/versions`,
        headers: a.auth,
        body: { value: canary() },
      });
      await ctx.expect("list", 200, { method: "GET", path: v, headers: a.auth });
      await ctx.expect("list no token", 401, { method: "GET", path: v });
      await ctx.expect("list cross-tenant", 404, { method: "GET", path: v, headers: b.auth });
      await ctx.expect("list missing secret", 404, {
        method: "GET",
        path: `${base}/${missing}/versions`,
        headers: a.auth,
      });
    },
  },
];
