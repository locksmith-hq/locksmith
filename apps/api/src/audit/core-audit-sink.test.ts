import { describe, expect, it } from "vitest";
import { createCoreClient } from "@locksmith/core-client";
import { appendAuditEvent } from "@locksmith/core-client/fixtures";
import { CoreAuditSink } from "./core-audit-sink.js";

const ORG = "0192f0a0-0000-7000-8000-000000000001";
const USER = "0192f0a0-0000-7000-8000-0000000000a1";
const event = { kind: "auth.sign_in", userId: USER, orgId: ORG, issuerHost: "idp.example.com", outcome: "ok" } as const;

function sink(handler: (req: Request) => Response | Promise<Response>) {
  const calls: Request[] = [];
  const fetchFn = (async (input: Request) => {
    calls.push(input.clone());
    return handler(input);
  }) as unknown as typeof fetch;
  return {
    sink: new CoreAuditSink(createCoreClient({ baseUrl: "http://core.test", token: "svc", fetch: fetchFn })),
    calls,
  };
}

describe("CoreAuditSink", () => {
  it("appends one event through the core with ids and the issuer host only", async () => {
    const { sink: s, calls } = sink(() => Response.json(appendAuditEvent));
    await s.append(event);
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0]!.url).pathname).toBe("/v1/audit/events");
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer svc");
    expect(await calls[0]!.json()).toEqual({
      org_id: ORG,
      kind: "auth.sign_in",
      outcome: "ok",
      actor: { type: "user", id: USER },
      target: { type: "org", id: ORG },
      attrs: { issuer: "idp.example.com" },
    });
  });

  it("omits the issuer attribute when there is no host", async () => {
    const { sink: s, calls } = sink(() => Response.json(appendAuditEvent));
    await s.append({ ...event, issuerHost: undefined });
    expect(((await calls[0]!.json()) as { attrs: unknown }).attrs).toEqual({});
  });

  it.each([400, 401, 500])("fails closed with 503 when the core answers %i", async (status) => {
    const { sink: s } = sink(() => Response.json({ title: "x", status, detail: "core says LEAK-CANARY" }, { status }));
    const err = await s.append(event).catch((e: unknown) => e);
    expect((err as { getStatus(): number }).getStatus()).toBe(503);
    expect(JSON.stringify(err)).not.toContain("LEAK-CANARY");
    expect(String((err as Error).message)).not.toContain("LEAK-CANARY");
  });

  it("fails closed when the core is unreachable", async () => {
    const { sink: s } = sink(() => {
      throw new TypeError("fetch failed");
    });
    const err = await s.append(event).catch((e: unknown) => e);
    expect((err as { getStatus(): number }).getStatus()).toBe(503);
  });
});
