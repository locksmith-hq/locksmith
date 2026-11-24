import { describe, expect, it } from "vitest";
import { Normaliser } from "./normalise.ts";

const ID1 = "0f8fad5b-d9cb-469f-a165-70867728950e";
const ID2 = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";

describe("normalise", () => {
  it("numbers ids in order of first appearance and keeps references", () => {
    const n = new Normaliser();
    const out = n.json({ id: ID1, parent: ID2, again: ID1 });
    expect(out).toEqual({ again: "<id-1>", id: "<id-1>", parent: "<id-2>" });
  });

  it("replaces ids inside paths and headers", () => {
    const n = new Normaliser();
    expect(n.text(`/v1/projects/${ID1}/environments/${ID2}`)).toBe("/v1/projects/<id-1>/environments/<id-2>");
    const h = new Headers({ Location: `/v1/orgs/${ID1}`, date: "x", "content-type": "application/json" });
    expect(n.headers(h)).toEqual({ "content-type": "application/json", location: "/v1/orgs/<id-1>" });
  });

  it("replaces timestamps with and without fractions or offsets", () => {
    const n = new Normaliser();
    const out = n.json({ a: "2026-11-24T10:00:00Z", b: "2026-11-24T10:00:00.123456+02:00", c: "2026-11-24T10:00:00Z" });
    expect(out).toEqual({ a: "<ts-1>", b: "<ts-2>", c: "<ts-1>" });
  });

  it("redacts tokens, JWTs and secret-keyed values", () => {
    const n = new Normaliser();
    const out = n.json({ access_token: "abc", enrollment_secret: "s3", note: `bearer ${JWT}`, secret_id: ID1 });
    expect(out).toEqual({
      access_token: "<token-1>",
      enrollment_secret: "<token-2>",
      note: "bearer <token-3>",
      secret_id: "<id-1>",
    });
  });

  it("replaces JWKS key material", () => {
    const n = new Normaliser();
    expect(n.json({ kid: "abc", x: "def", kty: "OKP" })).toEqual({ kid: "<key-1>", x: "<key-2>", kty: "OKP" });
  });

  it("replaces a registered per-run literal", () => {
    const n = new Normaliser();
    n.literal("x1y2", "<run>");
    expect(n.json({ name: "contract-a-x1y2" })).toEqual({ name: "contract-a-<run>" });
  });

  it("replaces digests, cursors and ciphertext blobs", () => {
    const n = new Normaliser();
    expect(n.json({ digest: "ab", prev_digest: "cd", next: "n1", ciphertext: "Y2k=", wrapped_dek: "ZA==" })).toEqual({
      ciphertext: "<key-1>",
      digest: "<key-2>",
      next: "<key-3>",
      prev_digest: "<key-4>",
      wrapped_dek: "<key-5>",
    });
  });

  it("sorts object keys and leaves other values alone", () => {
    const n = new Normaliser();
    expect(JSON.stringify(n.json({ z: 1, a: [true, null, "x"] }))).toBe('{"a":[true,null,"x"],"z":1}');
  });

  it("gives the same output for two runs with different ids", () => {
    const run = (x: string, y: string) => new Normaliser().json({ id: x, children: [{ id: y, parent: x }] });
    expect(run(ID1, ID2)).toEqual(run(ID2, ID1));
  });
});
