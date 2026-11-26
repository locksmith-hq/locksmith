import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ProblemException } from "../../platform/problem/problem.js";
import { CoreHoneyMinter } from "./honey-minter.js";

const ORG = "0192f3a0-0000-7000-8000-0000000000a1";
const SECRET = "0192f3a0-0000-7000-8000-0000000000a5";
const TOKEN = "svc-token-test-only";

describe("CoreHoneyMinter", () => {
  let status = 201;
  const seen: { url: string | undefined; method: string | undefined; auth: string | undefined; org: string | undefined; ctype: string | undefined; body: string }[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({
        url: req.url,
        method: req.method,
        auth: req.headers.authorization,
        org: req.headers["x-locksmith-org"] as string | undefined,
        ctype: req.headers["content-type"],
        body,
      });
      res.writeHead(status).end("{}");
    });
  });
  let base: string;
  beforeAll(async () => {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  });
  afterAll(() => new Promise((r) => server.close(r)));

  const kind = async (p: Promise<unknown>) => {
    try {
      await p;
    } catch (e) {
      expect(e).toBeInstanceOf(ProblemException);
      return (e as ProblemException).kind;
    }
    return "ok";
  };

  it("POSTs the contract body with the service token and org header", async () => {
    const m = new CoreHoneyMinter(base, TOKEN);
    status = 201;
    expect(await kind(m.mint(ORG, SECRET, "github_pat"))).toBe("ok");
    expect(seen.at(-1)).toEqual({
      url: "/internal/v1/honey/mint",
      method: "POST",
      auth: `Bearer ${TOKEN}`,
      org: ORG,
      ctype: "application/json",
      body: JSON.stringify({ template: "github_pat", secret_id: SECRET }),
    });
  });

  it("maps 404 and 409, and every other failure to unavailable,", async () => {
    const m = new CoreHoneyMinter(base, TOKEN);
    for (const [s, k] of [[404, "not-found"], [409, "conflict"], [401, "unavailable"], [500, "unavailable"], [503, "unavailable"]] as const) {
      status = s;
      expect(await kind(m.mint(ORG, SECRET, "slack_token"))).toBe(k);
    }
  });

  it("an unreachable core is unavailable", async () => {
    const m = new CoreHoneyMinter("http://127.0.0.1:1/", TOKEN);
    expect(await kind(m.mint(ORG, SECRET, "slack_token"))).toBe("unavailable");
  });
});
