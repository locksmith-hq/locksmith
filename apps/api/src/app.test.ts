import "reflect-metadata";
import { Writable } from "node:stream";
import { Test } from "@nestjs/testing";
import type { INestApplication } from "@nestjs/common";
import { LoggerModule } from "nestjs-pino";
import pino from "pino";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HealthController } from "./health.controller.js";
import { pinoOptions } from "./logging.js";
import { TerminusModule } from "@nestjs/terminus";

describe("health and log redaction", () => {
  let app: INestApplication;
  const lines: string[] = [];

  beforeAll(async () => {
    const stream = new Writable({
      write(chunk, _enc, cb) {
        lines.push(chunk.toString());
        cb();
      },
    });
    const mod = await Test.createTestingModule({
      imports: [
        TerminusModule,
        LoggerModule.forRoot({
          pinoHttp: {
            logger: pino(pinoOptions, stream),
          },
        }),
      ],
      controllers: [HealthController],
    }).compile();
    app = mod.createNestApplication();
    await app.init();
  });
  afterAll(() => app.close());

  it("GET /healthz and /readyz answer ok", async () => {
    for (const path of ["/healthz", "/readyz"]) {
      const res = await request(app.getHttpServer()).get(path);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe("ok");
    }
  });

  it("redacts authorization and cookie headers in request logs", async () => {
    await request(app.getHttpServer())
      .get("/healthz")
      .set("Authorization", "Bearer PLANTED-CANARY-TOKEN")
      .set("Cookie", "sid=PLANTED-CANARY-COOKIE");
    await new Promise((r) => setTimeout(r, 50));
    const out = lines.join("");
    expect(out).toContain("req");
    expect(out).not.toContain("PLANTED-CANARY");
  });

  it("redacts fields named like secrets or tokens", () => {
    const sink: string[] = [];
    const log = pino(
      pinoOptions,
      new Writable({ write(c, _e, cb) { sink.push(c.toString()); cb(); } }),
    );
    log.info({ client_secret: "PLANTED-S", body: { access_token: "PLANTED-T", secret_value: "PLANTED-V" } }, "x");
    const out = sink.join("");
    expect(out).not.toContain("PLANTED");
  });
});
