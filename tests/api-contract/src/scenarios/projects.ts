import type { Ctx, Scenario } from "../scenario.ts";

const missing = "00000000-0000-4000-8000-000000000000";

function idOf(body: unknown): string {
  return (body as { id: string }).id;
}

async function project(ctx: Ctx, label: string) {
  const res = await ctx.expect(`${label}: create project`, 201, {
    method: "POST",
    path: "/v1/projects",
    headers: ctx.seed.a.auth,
    body: { name: `proj-${label}-${ctx.seed.run}`, description: "contract" },
  });
  return idOf(res.body);
}

export const scenarios: Scenario[] = [
  {
    id: "projects",
    covers: [
      "GET /v1/projects",
      "POST /v1/projects",
      "GET /v1/projects/{project_id}",
      "PATCH /v1/projects/{project_id}",
      "DELETE /v1/projects/{project_id}",
    ],
    async run(ctx) {
      const { a, b } = ctx.seed;
      const p = await project(ctx, "main");
      await ctx.expect("create no token", 401, { method: "POST", path: "/v1/projects", body: { name: "x" } });
      await ctx.expect("create missing name", 400, { method: "POST", path: "/v1/projects", headers: a.auth, body: {} });
      await ctx.expect("create empty name", 400, {
        method: "POST",
        path: "/v1/projects",
        headers: a.auth,
        body: { name: "" },
      });
      await ctx.expect("create duplicate", 409, {
        method: "POST",
        path: "/v1/projects",
        headers: a.auth,
        body: { name: `proj-main-${ctx.seed.run}` },
      });
      await ctx.expect("list", 200, { method: "GET", path: "/v1/projects", headers: a.auth });
      await ctx.expect("list limit", 200, { method: "GET", path: "/v1/projects?limit=1", headers: a.auth });
      await ctx.expect("list bad limit", 400, { method: "GET", path: "/v1/projects?limit=0", headers: a.auth });
      await ctx.expect("list bad cursor", 400, { method: "GET", path: "/v1/projects?cursor=zzz", headers: a.auth });
      await ctx.expect("list no token", 401, { method: "GET", path: "/v1/projects" });
      await ctx.expect("list other tenant", 200, { method: "GET", path: "/v1/projects", headers: b.auth });
      await ctx.expect("get", 200, { method: "GET", path: `/v1/projects/${p}`, headers: a.auth });
      await ctx.expect("get no token", 401, { method: "GET", path: `/v1/projects/${p}` });
      await ctx.expect("get cross-tenant", 404, { method: "GET", path: `/v1/projects/${p}`, headers: b.auth });
      await ctx.expect("get missing", 404, { method: "GET", path: `/v1/projects/${missing}`, headers: a.auth });
      await ctx.expect("patch", 200, {
        method: "PATCH",
        path: `/v1/projects/${p}`,
        headers: a.auth,
        body: { description: "changed" },
      });
      await ctx.expect("patch empty name", 400, {
        method: "PATCH",
        path: `/v1/projects/${p}`,
        headers: a.auth,
        body: { name: "" },
      });
      await ctx.expect("patch no token", 401, {
        method: "PATCH",
        path: `/v1/projects/${p}`,
        body: { description: "x" },
      });
      await ctx.expect("patch cross-tenant", 404, {
        method: "PATCH",
        path: `/v1/projects/${p}`,
        headers: b.auth,
        body: { description: "x" },
      });
      await ctx.expect("delete no token", 401, { method: "DELETE", path: `/v1/projects/${p}` });
      await ctx.expect("delete cross-tenant", 404, { method: "DELETE", path: `/v1/projects/${p}`, headers: b.auth });
      await ctx.expect("delete", 204, { method: "DELETE", path: `/v1/projects/${p}`, headers: a.auth });
      await ctx.expect("get deleted", 404, { method: "GET", path: `/v1/projects/${p}`, headers: a.auth });
    },
  },
  {
    id: "environments",
    covers: [
      "GET /v1/projects/{project_id}/environments",
      "POST /v1/projects/{project_id}/environments",
      "GET /v1/projects/{project_id}/environments/{environment_id}",
      "PATCH /v1/projects/{project_id}/environments/{environment_id}",
      "DELETE /v1/projects/{project_id}/environments/{environment_id}",
    ],
    async run(ctx) {
      const { a, b } = ctx.seed;
      const p = await project(ctx, "env");
      const base = `/v1/projects/${p}/environments`;
      const created = await ctx.expect("create", 201, {
        method: "POST",
        path: base,
        headers: a.auth,
        body: { name: "dev", description: "d" },
      });
      const e = idOf(created.body);
      await ctx.expect("create no token", 401, { method: "POST", path: base, body: { name: "x" } });
      await ctx.expect("create missing name", 400, { method: "POST", path: base, headers: a.auth, body: {} });
      await ctx.expect("create duplicate", 409, { method: "POST", path: base, headers: a.auth, body: { name: "dev" } });
      await ctx.expect("create cross-tenant", 404, {
        method: "POST",
        path: base,
        headers: b.auth,
        body: { name: "x" },
      });
      await ctx.expect("list", 200, { method: "GET", path: base, headers: a.auth });
      await ctx.expect("list no token", 401, { method: "GET", path: base });
      await ctx.expect("list cross-tenant", 404, { method: "GET", path: base, headers: b.auth });
      await ctx.expect("get", 200, { method: "GET", path: `${base}/${e}`, headers: a.auth });
      await ctx.expect("get no token", 401, { method: "GET", path: `${base}/${e}` });
      await ctx.expect("get cross-tenant", 404, { method: "GET", path: `${base}/${e}`, headers: b.auth });
      await ctx.expect("get missing", 404, { method: "GET", path: `${base}/${missing}`, headers: a.auth });
      await ctx.expect("patch", 200, {
        method: "PATCH",
        path: `${base}/${e}`,
        headers: a.auth,
        body: { description: "changed" },
      });
      await ctx.expect("patch empty name", 400, {
        method: "PATCH",
        path: `${base}/${e}`,
        headers: a.auth,
        body: { name: "" },
      });
      await ctx.expect("patch no token", 401, { method: "PATCH", path: `${base}/${e}`, body: { description: "x" } });
      await ctx.expect("patch cross-tenant", 404, {
        method: "PATCH",
        path: `${base}/${e}`,
        headers: b.auth,
        body: { description: "x" },
      });
      await ctx.expect("delete no token", 401, { method: "DELETE", path: `${base}/${e}` });
      await ctx.expect("delete cross-tenant", 404, { method: "DELETE", path: `${base}/${e}`, headers: b.auth });
      await ctx.expect("delete", 204, { method: "DELETE", path: `${base}/${e}`, headers: a.auth });
      await ctx.expect("get deleted", 404, { method: "GET", path: `${base}/${e}`, headers: a.auth });
    },
  },
];
