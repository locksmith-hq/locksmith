import "reflect-metadata";
import { Controller, Get, type ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { describe, expect, it } from "vitest";
import { ProblemException } from "../problem/problem.js";
import { OrgBoundGuard } from "./org-bound.guard.js";
import type { Principal } from "./principal.js";
import { RequireOrg } from "./require-org.decorator.js";

@Controller("t")
class T {
  @Get("open") open() {}
  @Get("org") @RequireOrg() org() {}
}

const ORG = "00000000-0000-0000-0000-0000000000a1";
const ctx = (handler: () => void, principal?: Principal) =>
  ({
    getHandler: () => handler,
    getClass: () => T,
    switchToHttp: () => ({ getRequest: () => ({ principal }) }),
  }) as unknown as ExecutionContext;
const guard = new OrgBoundGuard(new Reflector());
const t = new T();

describe("org-bound guard", () => {
  const cases: [string, Principal | undefined, boolean][] = [
    ["human, bound", { kind: "human", orgId: ORG }, true],
    ["agent, bound", { kind: "agent", orgId: ORG }, true],
    ["service, bound", { kind: "service", orgId: ORG }, true],
    ["human, unbound", { kind: "human", orgId: null }, false],
    ["agent, unbound", { kind: "agent", orgId: null }, false],
    ["service, unbound", { kind: "service", orgId: null }, false],
    ["no principal", undefined, false],
  ];
  it.each(cases)("@RequireOrg route: %s", (_n, principal, allowed) => {
    if (allowed) return expect(guard.canActivate(ctx(t.org, principal))).toBe(true);
    try {
      guard.canActivate(ctx(t.org, principal));
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ProblemException);
      expect((e as ProblemException).kind).toBe("forbidden");
      expect((e as ProblemException).getStatus()).toBe(403);
    }
  });
  it("leaves routes without @RequireOrg alone", () => {
    expect(guard.canActivate(ctx(t.open, { kind: "human", orgId: null }))).toBe(true);
  });
});
