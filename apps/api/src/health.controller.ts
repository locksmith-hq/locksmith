import { Controller, Get, Inject } from "@nestjs/common";
import { HealthCheck, HealthCheckService, HealthIndicatorService } from "@nestjs/terminus";
import { sql } from "kysely";
import type { Database } from "./db/db.js";
import { DATABASE } from "./db/db.module.js";

@Controller()
export class HealthController {
  // Explicit @Inject: vitest's transform does not emit design:paramtypes, so DI must not rely on it.
  constructor(
    @Inject(HealthCheckService) private readonly health: HealthCheckService,
    @Inject(HealthIndicatorService) private readonly indicator: HealthIndicatorService,
    @Inject(DATABASE) private readonly db: Database,
  ) {}

  // Liveness: the process answers. No dependency checks, so a database blip never restarts the pod.
  @Get("healthz")
  @HealthCheck()
  healthz() {
    return this.health.check([]);
  }

  // Readiness: the database answers a trivial query. The error is never echoed (it can carry the URL).
  @Get("readyz")
  @HealthCheck()
  readyz() {
    return this.health.check([
      async () => {
        const check = this.indicator.check("database");
        try {
          await sql`select 1`.execute(this.db);
          return check.up();
        } catch {
          return check.down("unreachable");
        }
      },
    ]);
  }
}
