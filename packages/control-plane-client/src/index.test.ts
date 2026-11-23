import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, bindingDetails, createClient } from "./index";
import { bindingSummaries } from "./fixtures";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

afterEach(() => vi.unstubAllGlobals());

function stub(...responses: Response[]) {
  const f = vi.fn();
  for (const r of responses) f.mockResolvedValueOnce(r);
  vi.stubGlobal("fetch", f);
  return f;
}

describe("console client", () => {
  it("lists projects across pages with the bearer token", async () => {
    const f = stub(json({ items: [{ id: "p1" }], next: "c2" }), json({ items: [{ id: "p2" }], next: null }));
    const c = createClient("org", "http://x", () => "tok");
    expect((await c.listProjects()).map((p) => p.id)).toEqual(["p1", "p2"]);
    expect(f.mock.calls[1]![0]).toBe("http://x/v1/projects?cursor=c2");
    expect((f.mock.calls[0]![1] as RequestInit).headers).toMatchObject({ authorization: "Bearer tok" });
  });

  it("uses the right method and path for project and environment writes", async () => {
    const f = stub(json({}), json({}), new Response(null, { status: 204 }), json({}), json({}), new Response(null, { status: 204 }));
    const c = createClient("org");
    await c.createProject({ name: "a" });
    await c.updateProject("p/1", { name: "b" });
    await c.deleteProject("p1");
    await c.createEnvironment("p1", { name: "dev" });
    await c.updateEnvironment("p1", "e1", { name: "x" });
    await c.deleteEnvironment("p1", "e1");
    expect(f.mock.calls.map((a) => `${(a[1] as RequestInit).method} ${a[0]}`)).toEqual([
      "POST /v1/projects",
      "PATCH /v1/projects/p%2F1",
      "DELETE /v1/projects/p1",
      "POST /v1/projects/p1/environments",
      "PATCH /v1/projects/p1/environments/e1",
      "DELETE /v1/projects/p1/environments/e1",
    ]);
  });

  it("reads secret metadata and versions only", async () => {
    const f = stub(json({ items: [{ id: "s1" }] }), json({ id: "s1" }), json({ items: [{ version: 1 }] }));
    const c = createClient("org");
    await c.listSecrets("p", "e");
    await c.getSecret("p", "e", "s1");
    expect(await c.listSecretVersions("p", "e", "s1")).toEqual([{ version: 1 }]);
    for (const a of f.mock.calls) expect(String(a[0])).not.toMatch(/material|value/);
    expect(f.mock.calls.every((a) => (a[1] as RequestInit).method === "GET")).toBe(true);
  });

  it("surfaces the problem detail and status", async () => {
    stub(json({ title: "Conflict", detail: "name taken", status: 409 }, 409));
    const err = await createClient("o").createProject({ name: "a" }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 409, message: "name taken" });
  });

  it("lists bindings with a GET and the fixtures carry no secret fields", async () => {
    const f = stub(json({ items: bindingSummaries }));
    const got = await createClient("org").listBindings();
    expect(got.map((b) => b.kind)).toEqual(["http", "git", "pg", "aws"]);
    expect(`${(f.mock.calls[0]![1] as RequestInit).method} ${f.mock.calls[0]![0]}`).toBe("GET /v1/bindings");
    expect(JSON.stringify(bindingSummaries)).not.toMatch(/password|template|secret|token|key/i);
  });

  it("bindingDetails shows the non-secret fields per kind", () => {
    const by = Object.fromEntries(bindingSummaries.map((b) => [b.kind, bindingDetails(b)]));
    expect(by.pg).toEqual([["Host", "db.internal.example.com"], ["Port", "5432"], ["User", "app"], ["Database", "appdb"], ["TLS", "verify-full"]]);
    expect(by.http).toEqual([["Origin", "https://api.example.com"], ["Header", "Authorization"]]);
    expect(by.git).toEqual([["Host", "github.com"], ["Repo", "acme"]]);
    expect(by.aws).toContainEqual(["Max duration", "900s"]);
  });
});
