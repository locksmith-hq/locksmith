import { describe, expect, it } from "vitest";
import type { Exchange } from "./client.ts";
import { diffTranscripts } from "./diff.ts";

const ex = (over: Partial<Exchange> = {}): Exchange => ({
  name: "orgs: create",
  method: "POST",
  path: "/v1/orgs",
  status: 201,
  headers: { "content-type": "application/json" },
  body: { id: "<id-1>", name: "x" },
  ...over,
});

describe("diffTranscripts", () => {
  it("is empty for equal transcripts", () => {
    expect(diffTranscripts([ex()], [ex()])).toEqual([]);
  });
  it("reports the status first", () => {
    const d = diffTranscripts([ex()], [ex({ status: 200, body: null })]);
    expect(d).toEqual([{ where: "POST /v1/orgs (orgs: create)", field: "status", a: 201, b: 200 }]);
  });
  it("reports a header before the body", () => {
    const d = diffTranscripts([ex()], [ex({ headers: {}, body: { id: "<id-1>", name: "y" } })]);
    expect(d[0]?.field).toBe("headers.content-type");
  });
  it("names the first differing body field", () => {
    const d = diffTranscripts([ex()], [ex({ body: { id: "<id-1>", name: "y" } })]);
    expect(d[0]).toMatchObject({ field: "body.name", a: "x", b: "y" });
  });
  it("reports exchanges present on one side only", () => {
    const d = diffTranscripts([ex()], [ex({ name: "orgs: other" })]);
    expect(d.map((x) => x.field)).toEqual(["exchange", "exchange"]);
  });
});
