/// <reference types="node" />
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { createGatewayClient, OAUTH_ERROR_SLUGS, OAuthError, parseCallback, type ConnectionSummary } from "./oauth";
import {
  oauthConnectRequest,
  oauthConnectResponse,
  oauthConnection,
  oauthConnectionGrant,
  oauthConnectionRefreshFailed,
  oauthConnections,
  oauthGrantListing,
  oauthHostNotAllowed,
  oauthProviders,
  oauthWrongPerson,
} from "./oauth-fixtures";

const dir = join(dirname(fileURLToPath(import.meta.url)), "../../../crates/ls-oauth/fixtures");
const rust = (name: string): unknown => JSON.parse(readFileSync(join(dir, `${name}.json`), "utf8"));

describe("fixtures match the Rust ones", () => {
  it.each([
    ["connection_summary", oauthConnection],
    ["connection_refresh_failed", oauthConnectionRefreshFailed],
    ["connection_grant", oauthConnectionGrant],
    ["grant_listing", oauthGrantListing],
    ["connect_request", oauthConnectRequest],
    ["connect_response", oauthConnectResponse],
    ["error_wrong_person", oauthWrongPerson],
    ["error_forbidden_host", oauthHostNotAllowed],
    ["provider_summary", oauthProviders[0]],
  ])("%s", (name, ts) => {
    expect(ts).toEqual(rust(name));
  });

  it("has five providers, two connections and one refresh_failed", () => {
    expect(oauthProviders.map((p) => p.provider)).toEqual(["github", "google", "slack", "linear", "atlassian"]);
    expect(oauthConnections.map((c) => c.status)).toEqual(["connected", "refresh_failed"]);
  });

  it("no fixture field names a token", () => {
    const all = JSON.stringify([oauthProviders, oauthConnections, oauthConnectionGrant, oauthGrantListing]);
    expect(all).not.toMatch(/token|secret|password/i);
  });
});

describe("gateway client", () => {
  const reply = (status: number, body: unknown) =>
    vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));

  it("connect posts the request with the bearer", async () => {
    const f = reply(200, oauthConnectResponse);
    const c = createGatewayClient("http://gw/", () => "tok", f as unknown as typeof fetch);
    expect(await c.connect(oauthConnectRequest)).toEqual(oauthConnectResponse);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://gw/v1/oauth/connect");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer tok");
    expect(JSON.parse(init.body as string)).toEqual(oauthConnectRequest);
  });

  it("confirm and disconnect hit their paths", async () => {
    const f = reply(200, oauthConnection satisfies ConnectionSummary);
    const c = createGatewayClient("http://gw", undefined, f as unknown as typeof fetch);
    await c.confirm("f 1");
    await c.disconnect("c1");
    const urls = f.mock.calls.map((x) => (x as unknown as [string])[0]);
    expect(urls).toEqual(["http://gw/v1/oauth/flows/f%201/confirm", "http://gw/v1/oauth/connections/c1/disconnect"]);
    expect((f.mock.calls[0] as unknown as [string, RequestInit])[1].headers).not.toHaveProperty("authorization");
  });

  it("surfaces wrong_person as a slug and nothing else", async () => {
    const c = createGatewayClient("http://gw", () => "t", reply(403, oauthWrongPerson) as unknown as typeof fetch);
    const e = await c.confirm("f").catch((x: unknown) => x);
    expect(e).toBeInstanceOf(OAuthError);
    expect((e as OAuthError).status).toBe(403);
    expect((e as OAuthError).slug).toBe("wrong_person");
  });

  it("a non-slug error body gives a null slug", async () => {
    const c = createGatewayClient(
      "http://gw",
      undefined,
      reply(500, { error: "boom: secret" }) as unknown as typeof fetch,
    );
    const e = (await c.connect(oauthConnectRequest).catch((x: unknown) => x)) as OAuthError;
    expect(e.slug).toBeNull();
    expect(e.message).not.toContain("secret");
  });
});

describe("parseCallback", () => {
  it("accepts pending_confirm and every slug, rejects the rest", () => {
    expect(parseCallback("?flow=f&result=pending_confirm")).toEqual({ flow: "f", result: "pending_confirm" });
    for (const s of OAUTH_ERROR_SLUGS) expect(parseCallback(`?flow=f&result=${s}`)?.result).toBe(s);
    expect(parseCallback("?flow=f&result=<script>")).toBeNull();
    expect(parseCallback("?result=pending_confirm")).toBeNull();
  });
});
