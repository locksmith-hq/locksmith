import { describe, expect, it } from "vitest";
import {
  encodeHandle,
  GITHUB_ISSUER,
  type IssuerKind,
  issuerHostAllowed,
  PolicyError,
  type PolicyErrorCode,
  validate,
} from "./validate.js";

// Port of the unit tests in Rust `crates/ls-oidc-verify/src/workload.rs` (fixtures use `acme`).
const ci = (claim: string, value: string) => ({ claim, value });
const gh = (inputs: { claim: string; value: string }[]) =>
  validate("ci", "github", null, "https://locksmith.example", inputs);
const oidc = (issuer: string | null, inputs: { claim: string; value: string }[], kind: IssuerKind = "oidc") =>
  validate("k", kind, issuer, "a", inputs);
const code = (f: () => unknown): PolicyErrorCode | undefined => {
  try {
    f();
  } catch (e) {
    if (e instanceof PolicyError) return e.code;
    throw e;
  }
  return undefined;
};

describe("validate", () => {
  it("pins the repository and fixes the github issuer", () => {
    const p = gh([ci("repository", "acme/app"), ci("ref", "refs/heads/main")]);
    expect(p.issuer).toBe(GITHUB_ISSUER);
    expect(p.conditions[0]!.op).toBe("eq");
    expect(gh([ci("repository", "a/b")]).audience).toBe("https://locksmith.example");
  });

  it("does not let a github policy override the issuer, but accepts it with a trailing slash", () => {
    expect(code(() => oidc("https://evil.example", [ci("repository", "a/b")], "github"))).toBe("IssuerNotAllowed");
    expect(oidc(`${GITHUB_ISSUER}/`, [ci("repository", "a/b")], "github").issuer).toBe(GITHUB_ISSUER);
  });

  it("requires a subject pin and at least one condition", () => {
    expect(code(() => gh([ci("ref", "refs/heads/main")]))).toBe("NoSubjectPin");
    expect(code(() => gh([]))).toBe("NoConditions");
    expect(code(() => gh(Array.from({ length: 17 }, () => ci("repository", "a/b"))))).toBe("TooManyConditions");
  });

  it("makes github prefix pins fix the owner", () => {
    for (const [claim, value] of [
      ["sub", "repo:*"],
      ["sub", "repo:acme*"],
      ["sub", "repo:/*"],
      ["sub", "*"],
      ["repository", "a*"],
      ["repository", "acme*"],
      ["repository", "/x*"],
    ] as const)
      expect(
        code(() => gh([ci(claim, value)])),
        `${claim}=${value}`,
      ).toBe(value === "*" ? "BareWildcard" : "NoSubjectPin");
    expect(() => gh([ci("repository", "acme/*")])).not.toThrow();
    expect(() => gh([ci("sub", "repo:acme/app:*")])).not.toThrow();
    expect(() => gh([ci("sub", "repo:acme/*")])).not.toThrow();
  });

  it("refuses a bare and an inner wildcard, and an empty value", () => {
    expect(code(() => gh([ci("repository", "*")]))).toBe("BareWildcard");
    expect(code(() => gh([ci("repository", "ac*me/app")]))).toBe("BadCondition");
    expect(code(() => gh([ci("repository", "a**")]))).toBe("BadCondition");
    expect(code(() => gh([ci("repository", "")]))).toBe("BadCondition");
    expect(code(() => gh([ci(" ", "a/b")]))).toBe("BadCondition");
    expect(code(() => gh([ci("x".repeat(65), "a/b")]))).toBe("BadCondition");
    expect(code(() => gh([ci("repository", "a".repeat(513))]))).toBe("BadCondition");
  });

  it("turns a trailing star into a prefix condition", () => {
    expect(gh([ci("repository", "acme/*")]).conditions[0]).toEqual({
      claim: "repository",
      op: "prefix",
      value: "acme/",
    });
  });

  it("gives an oidc policy on the github issuer the owner pin rule", () => {
    const v = (val: string) => () => oidc(GITHUB_ISSUER, [ci("sub", val)]);
    expect(code(v("repo:acme*"))).toBe("NoSubjectPin");
    expect(code(v("repo:*"))).toBe("NoSubjectPin");
    expect(code(v("repo:acme/api:*"))).toBeUndefined();
  });

  it("needs a plain https oidc issuer", () => {
    const ok = (i: string | null) => oidc(i, [ci("sub", "system:serviceaccount:ns:sa")]);
    expect(ok("https://k8s.example/").issuer).toBe("https://k8s.example");
    for (const bad of [
      "http://k8s.example",
      "k8s.example",
      "https://",
      "https://u:p@k8s.example",
      "https://k8s.example?x=1",
      "https://k8s.example#f",
      "https://a b",
    ])
      expect(
        code(() => ok(bad)),
        bad,
      ).toBe("IssuerNotHttps");
    expect(code(() => ok(null))).toBe("IssuerNotHttps");
  });

  it("needs a sub pin, not repository, for oidc", () => {
    expect(code(() => oidc("https://k8s.example", [ci("repository", "a/b")]))).toBe("NoSubjectPin");
    expect(() => oidc("https://k8s.example", [ci("sub", "system:serviceaccount:prod:*")])).not.toThrow();
  });

  it("requires the audience and the name", () => {
    expect(code(() => validate("ci", "github", null, " ", [ci("repository", "a/b")]))).toBe("Audience");
    expect(code(() => validate(" ", "github", null, "a", [ci("repository", "a/b")]))).toBe("Name");
    expect(validate("ci", "github", null, "  aud  ", [ci("repository", "a/b")]).audience).toBe("aud");
  });

  it("carries a static detail", () => {
    expect(new PolicyError("NoSubjectPin").detail).toBe("a condition must pin the subject (repository or sub)");
  });
});

describe("encodeHandle", () => {
  it("is lsw_ plus base64url of org id then policy id", () => {
    const org = "01234567-89ab-7cde-8f01-23456789abcd";
    const pol = "fedcba98-7654-7321-8fed-cba987654321";
    const h = encodeHandle(org, pol);
    expect(h.startsWith("lsw_")).toBe(true);
    const raw = Buffer.from(h.slice(4), "base64url");
    expect(raw.length).toBe(32);
    expect(raw.subarray(0, 16).toString("hex")).toBe(org.replaceAll("-", ""));
    expect(raw.subarray(16).toString("hex")).toBe(pol.replaceAll("-", ""));
    expect(h).not.toMatch(/[=+/]/);
  });
});

describe("issuerHostAllowed", () => {
  it("refuses literal private, loopback, link-local, metadata and unspecified addresses", () => {
    for (const u of [
      "https://127.0.0.1",
      "https://10.1.2.3",
      "https://172.16.0.1/x",
      "https://172.31.255.255",
      "https://192.168.1.1",
      "https://169.254.169.254",
      "https://169.254.1.1",
      "https://100.64.0.1",
      "https://0.0.0.0",
      "https://224.0.0.1",
      "https://[::1]",
      "https://[::]",
      "https://[fd00:ec2::254]",
      "https://[fc00::1]",
      "https://[fe80::1]",
      "https://[::ffff:10.0.0.1]",
      "https://[::ffff:169.254.169.254]",
      "https://localhost",
      "https://app.localhost:8443",
      "https://metadata.google.internal",
    ])
      expect(issuerHostAllowed(u), u).toBe(false);
  });

  it("accepts public addresses and names", () => {
    for (const u of [
      "https://token.actions.githubusercontent.com",
      "https://8.8.8.8",
      "https://172.32.0.1",
      "https://100.128.0.1",
      "https://[2606:4700::1]",
      "https://k8s.example",
    ])
      expect(issuerHostAllowed(u), u).toBe(true);
  });

  it("allows private hosts in dev mode but never metadata", () => {
    expect(issuerHostAllowed("https://127.0.0.1", true)).toBe(true);
    expect(issuerHostAllowed("https://localhost", true)).toBe(true);
    expect(issuerHostAllowed("https://169.254.169.254", true)).toBe(false);
    expect(issuerHostAllowed("https://[fd00:ec2::254]", true)).toBe(false);
    expect(issuerHostAllowed("https://0.0.0.0", true)).toBe(false);
  });
});
