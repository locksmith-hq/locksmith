import "reflect-metadata";
import { Writable } from "node:stream";
import { Test } from "@nestjs/testing";
import { Controller, Get, Module } from "@nestjs/common";
import { LoggerModule } from "nestjs-pino";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { REDACT_PATHS, loggerFormatters, loggerSerializers } from "./logging.js";

// Own file: nestjs-pino keeps one module-level logger, so this must not share a module graph with app.test.ts.

describe("request logging end to end", () => {
  it("redacts token-like headers and keeps the status code", async () => {
    const lines: string[] = [];
    const stream = new Writable({
      write(c, _e, cb) {
        lines.push(String(c));
        cb();
      },
    });
    @Controller()
    class C {
      @Get("ping")
      ping() {
        return { ok: true };
      }
    }
    @Module({
      imports: [
        LoggerModule.forRoot({
          pinoHttp: [
            {
              formatters: loggerFormatters,
              serializers: loggerSerializers,
              redact: { paths: REDACT_PATHS, censor: "[redacted]" },
            },
            stream,
          ],
        }),
      ],
      controllers: [C],
    })
    class M {}
    const mod = await Test.createTestingModule({ imports: [M] }).compile();
    const app = mod.createNestApplication();
    await app.init();
    await request(app.getHttpServer())
      .get("/ping")
      .set("authorization", "Bearer FAKE-A")
      .set("x-api-token", "FAKE-TOK")
      .set("x-client-secret", "FAKE-SEC")
      .expect(200);
    await app.close();
    await new Promise((r) => setTimeout(r, 50));
    const out = lines.join("");
    expect(out).toContain('"statusCode":200');
    for (const leak of ["FAKE-A", "FAKE-TOK", "FAKE-SEC"]) expect(out).not.toContain(leak);
  });
});
