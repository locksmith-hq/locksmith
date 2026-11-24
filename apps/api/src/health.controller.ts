import { Controller, Get, Inject } from "@nestjs/common";
import { HealthCheck, HealthCheckService } from "@nestjs/terminus";

@Controller()
export class HealthController {
  // Explicit @Inject: vitest's transform does not emit design:paramtypes, so DI must not rely on it.
  constructor(@Inject(HealthCheckService) private readonly health: HealthCheckService) {}

  // Liveness: the process answers. No dependency checks, so a database blip never restarts the pod.
  @Get("healthz")
  @HealthCheck()
  healthz() {
    return this.health.check([]);
  }

  // Readiness: dependency indicators are added by the data layer (task 2.3).
  @Get("readyz")
  @HealthCheck()
  readyz() {
    return this.health.check([]);
  }
}
