import { Module } from "@nestjs/common";
import { APP_FILTER } from "@nestjs/core";
import { ConfigModule } from "@nestjs/config";
import { TerminusModule } from "@nestjs/terminus";
import { LoggerModule } from "nestjs-pino";
import { AuthModule } from "./auth/auth.module.js";
import { UsersModule } from "./users/users.module.js";
import { OrgsModule } from "./orgs/orgs.module.js";
import { AgentsModule } from "./agents/agents.module.js";
import { ProjectsModule } from "./projects/projects.module.js";
import { WorkloadIdentitiesModule } from "./workload-identities/workload-identities.module.js";
import { JobsModule } from "./jobs/jobs.module.js";
import { CoreModule } from "./core/core.module.js";
import { DbModule } from "./db/db.module.js";
import { TenantModule } from "./tenant/tenant.module.js";
import { ProblemFilter } from "./platform/problem.js";
import { validateEnv } from "./env.js";
import { HealthController } from "./health.controller.js";
import { REDACT_PATHS, loggerFormatters, loggerSerializers } from "./logging.js";

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validate: validateEnv }),
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env["LOG_LEVEL"] ?? "info",
        formatters: loggerFormatters,
        serializers: loggerSerializers,
        redact: { paths: REDACT_PATHS, censor: "[redacted]" },
      },
    }),
    TerminusModule,
    CoreModule,
    DbModule,
    TenantModule,
    AuthModule,
    UsersModule,
    OrgsModule,
    AgentsModule,
    ProjectsModule,
    WorkloadIdentitiesModule,
    JobsModule,
  ],
  controllers: [HealthController],
  providers: [{ provide: APP_FILTER, useClass: ProblemFilter }],
})
export class AppModule {}
