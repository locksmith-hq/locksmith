import "reflect-metadata";
import { Writable } from "node:stream";
import { Test } from "@nestjs/testing";
import pino from "pino";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { validateEnv } from "./env.js";
import { REDACT_PATHS, loggerFormatters } from "./logging.js";

describe("env", () => {
  it("fails fast without DATABASE_URL and does not echo values", () => {
    expect(() => validateEnv({ PORT: "abc-not-a-port" })).toThrow(/DATABASE_URL/);
    try {
      validateEnv({ PORT: "abc-not-a-port" });
    } catch (e) {
      expect(String(e)).not.toContain("abc-not-a-port");
    }
  });
  it("accepts a valid env", () => {
    expect(validateEnv({ DATABASE_URL: "postgres://x" }).PORT).toBe(3000);
  });
});

describe("logging redaction", () => {
  it("redacts authorization and secret/token fields", () => {
    const lines: string[] = [];
    const sink = new Writable({
      write(chunk, _e, cb) {
        lines.push(String(chunk));
        cb();
      },
    });
    const log = pino({ formatters: loggerFormatters, redact: { paths: REDACT_PATHS, censor: "[redacted]" } }, sink);
    log.info({
      req: { headers: { authorization: "Bearer FAKE-AUTH-123" } },
      body: { client_secret: "FAKE-SECRET-456", refresh_token: "FAKE-TOKEN-789" },
    });
    const out = lines.join("");
    expect(out).not.toContain("FAKE-AUTH-123");
    expect(out).not.toContain("FAKE-SECRET-456");
    expect(out).not.toContain("FAKE-TOKEN-789");
  });
});

describe("health", () => {
  it("serves /healthz and /readyz", async () => {
    process.env["DATABASE_URL"] = "postgres://unused";
    process.env["LOG_LEVEL"] = "silent";
    const { AppModule } = await import("./app.module.js"); // reads env at import
    const { PG_BOSS } = await import("./jobs/jobs.service.js");
    // Jobs need a real database (see jobs.test.ts); the health test stubs pg-boss.
    const boss = {
      on() {},
      start: async () => {},
      createQueue: async () => {},
      work: async () => "",
      schedule: async () => {},
      stop: async () => {},
    };
    const mod = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(PG_BOSS)
      .useValue(boss)
      .compile();
    const app = mod.createNestApplication();
    await app.init();
    await request(app.getHttpServer()).get("/healthz").expect(200, { status: "ok" });
    const r = await request(app.getHttpServer()).get("/readyz").expect(200);
    expect(r.body.status).toBe("ok");
    await app.close();
  });
});
