import { Controller, Get, Inject } from "@nestjs/common";
import { HealthCheck, HealthCheckService } from "@nestjs/terminus";

@Controller()
export class HealthController {
  // Explicit @Inject: vitest (oxc) does not emit design:paramtypes metadata.
  constructor(@Inject(HealthCheckService) private readonly health: HealthCheckService) {}

  @Get("healthz")
  healthz() {
    return { status: "ok" };
  }

  @Get("readyz")
  @HealthCheck()
  readyz() {
    // Dependency indicators (database) join here with task 2.3.
    return this.health.check([async () => ({ process: { status: "up" as const } })]);
  }
}
