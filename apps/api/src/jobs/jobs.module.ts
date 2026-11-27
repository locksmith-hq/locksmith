import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JobsService, PG_BOSS, createBoss } from "./jobs.service.js";

/**
 * pg-boss on the same Postgres as the data layer (no Redis). pg-boss owns its own `pgboss` schema
 * and creates it on start, so `JOBS_DATABASE_URL` may name a role allowed to do that; it falls back
 * to `DATABASE_URL`.
 */
@Module({
  providers: [
    {
      provide: PG_BOSS,
      inject: [ConfigService],
      useFactory: (config: ConfigService) =>
        createBoss(config.get<string>("JOBS_DATABASE_URL") ?? config.getOrThrow<string>("DATABASE_URL")),
    },
    JobsService,
  ],
  exports: [JobsService],
})
export class JobsModule {}
