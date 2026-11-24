import "reflect-metadata";
import { readFileSync } from "node:fs";
import { PATH_METADATA, METHOD_METADATA } from "@nestjs/common/constants.js";
import { describe, expect, it } from "vitest";
import { HealthController } from "../../health.controller.js";
import { APP_GUARD } from "@nestjs/core";
import { AuthGuard } from "./auth.guard.js";
import { AuthModule } from "./auth.module.js";
import { IS_PUBLIC } from "./public.decorator.js";

// Every controller registered in AppModule. Add new controllers here and to the module.
const CONTROLLERS: { prototype: object }[] = [HealthController];
// The list above must match AppModule: the first test fails if a controller is added there and not here.
// Routes allowed to be open. Anything else must sit behind the global AuthGuard.
const PUBLIC_ALLOWLIST = new Set(["GET /healthz", "GET /readyz"]);
const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "ALL", "OPTIONS", "HEAD"];

const join = (...p: string[]) => "/" + p.map((s) => s.replace(/^\/+|\/+$/g, "")).filter(Boolean).join("/");

describe("route guard coverage", () => {
  const routes = CONTROLLERS.flatMap((c) => {
    const proto = c.prototype as Record<string, object>;
    const base = Reflect.getMetadata(PATH_METADATA, c) as string;
    return Object.getOwnPropertyNames(c.prototype)
      .filter((n) => n !== "constructor" && Reflect.hasMetadata(METHOD_METADATA, proto[n]!))
      .map((n) => {
        const h = proto[n]!;
        return {
          key: `${METHODS[Reflect.getMetadata(METHOD_METADATA, h) as number]} ${join(base, Reflect.getMetadata(PATH_METADATA, h) as string)}`,
          public: Reflect.getMetadata(IS_PUBLIC, h) === true || Reflect.getMetadata(IS_PUBLIC, c) === true,
        };
      });
  });

  it("registers the AuthGuard globally and imports it in AppModule", async () => {
    process.env["DATABASE_URL"] ??= "postgres://unused"; // app.module reads env at import
    process.env["LOG_LEVEL"] = "silent";
    const { AppModule } = await import("../../app.module.js");
    const providers = Reflect.getMetadata("providers", AuthModule) as { provide?: unknown; useClass?: unknown }[];
    expect(providers.some((p) => p.provide === APP_GUARD && p.useClass === AuthGuard)).toBe(true);
    expect(Reflect.getMetadata("imports", AppModule)).toContain(AuthModule);
    expect(Reflect.getMetadata("controllers", AppModule)).toEqual(CONTROLLERS);
  });

  it("finds the registered routes", () => {
    expect(routes.length).toBeGreaterThan(0);
  });

  it("leaves open only the allowlisted routes", () => {
    for (const r of routes) expect(r.public, r.key).toBe(PUBLIC_ALLOWLIST.has(r.key));
  });

  it("marks no route public that route-table.json hands to nest and is not allowlisted", () => {
    const table = JSON.parse(readFileSync(new URL("../../../route-table.json", import.meta.url), "utf8")) as {
      routes: { method: string; path: string; owner: string }[];
    };
    const nest = table.routes.filter((r) => r.owner === "nest").map((r) => `${r.method} ${r.path.replace(/\{(\w+)\}/g, ":$1")}`);
    for (const key of nest) {
      const hit = routes.find((r) => r.key === key);
      if (hit) expect(hit.public, key).toBe(PUBLIC_ALLOWLIST.has(key));
    }
  });
});
