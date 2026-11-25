import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentError, createAgentClient } from "./index";

const KIT = new URL("../../../tests/kit/", import.meta.url).pathname;
const errors: { slug: string; status: number }[] = JSON.parse(
  (await import("node:fs")).readFileSync(`${KIT}agent-contract/errors.json`, "utf8"),
);
const ENROLL = "canary-enroll-secret";
const procs: ChildProcess[] = [];
afterEach(() => {
  for (const p of procs.splice(0)) p.kill();
  vi.restoreAllMocks();
});

async function start(...args: string[]): Promise<string> {
  const p = spawn("python3", ["-I", `${KIT}mock_gateway.py`, ...args], { stdio: ["ignore", "pipe", "ignore"] });
  procs.push(p);
  const line: string = await new Promise((res) => p.stdout!.once("data", (d) => res(String(d))));
  return `http://127.0.0.1:${/port=(\d+)/.exec(line)![1]}`;
}

describe("agent client errors", () => {
  it("maps every gateway slug to its slug and status without leaking", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    for (const e of errors) {
      const url = await start("--fail", e.slug);
      const c = createAgentClient({ gatewayUrl: url, token: "canary-agent-token" });
      const got = await c.listGrants().catch((x) => x);
      expect(got).toBeInstanceOf(AgentError);
      expect(got).toMatchObject({ slug: e.slug, status: e.status, message: e.slug });
      expect(String(got.stack)).not.toContain("canary-");
    }
    expect(log).not.toHaveBeenCalled();
    expect(err).not.toHaveBeenCalled();
  }, 60_000);

  it("renews once after a 401 and retries the request", async () => {
    const url = await start();
    const seen: string[] = [];
    let first = true;
    const f: typeof fetch = async (input, init) => {
      const u = String(input);
      if (u.endsWith("/v1/grants")) {
        seen.push("grants");
        if (first) {
          first = false;
          return new Response(JSON.stringify({ error: "unauthenticated" }), { status: 401 });
        }
      } else if (u.endsWith("/v1/agent-tokens")) seen.push("token");
      return fetch(input, init);
    };
    const c = createAgentClient({ gatewayUrl: url, enrollmentSecret: ENROLL, fetch: f });
    expect((await c.listGrants()).length).toBe(1);
    expect(seen).toEqual(["token", "grants", "token", "grants"]);
  });

  it("gives up after a second 401", async () => {
    const url = await start("--fail", "unauthenticated");
    const c = createAgentClient({ gatewayUrl: url, enrollmentSecret: ENROLL });
    await expect(c.listGrants()).rejects.toMatchObject({ slug: "unauthenticated", status: 401 });
  });

  it("rejects a bad configuration and a transport failure with fixed slugs", async () => {
    expect(() => createAgentClient({ gatewayUrl: "not a url", token: "x" })).toThrow(AgentError);
    expect(() => createAgentClient({ gatewayUrl: "http://127.0.0.1:1" })).toThrow(AgentError);
    const c = createAgentClient({ gatewayUrl: "http://127.0.0.1:1", token: "x" });
    await expect(c.listGrants()).rejects.toMatchObject({ slug: "transport", status: 0 });
  });

  it("leaves no canary in a transcript scan", async () => {
    const url = await start();
    const enroll = randomBytes(32).toString("base64url");
    const c = createAgentClient({ gatewayUrl: url, enrollmentSecret: enroll });
    const dir = mkdtempSync(join(tmpdir(), "agent-"));
    const lines: string[] = [];
    const grants = await c.listGrants();
    lines.push(JSON.stringify({ tool: "list_my_keys", result: grants }));
    const r = await c.relay({ secretId: grants[0]!.secret_id, version: 1, method: "GET", url: "http://127.0.0.1:9/x" });
    lines.push(JSON.stringify({ tool: "relay_http_request", result: r }));
    const transcript = join(dir, "transcript.jsonl");
    writeFileSync(transcript, lines.join("\n") + "\n");
    const canaries = join(dir, "canaries");
    writeFileSync(canaries, `${enroll}\n`);
    const scan = spawnSync("python3", [
      "-I",
      `${KIT}oracle.py`,
      "scan",
      "--canary-file",
      canaries,
      "--transcript",
      transcript,
    ]);
    expect(scan.status, String(scan.stdout)).toBe(0);
  });
});
