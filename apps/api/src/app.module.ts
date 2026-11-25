import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { TerminusModule } from "@nestjs/terminus";
import { LoggerModule } from "nestjs-pino";
import { JobsModule } from "./jobs/jobs.module.js";
import { NotificationsModule } from "./domains/notifications/notifications.module.js";
import { DbModule } from "./db/db.module.js";
import { TenantModule } from "./tenant/tenant.module.js";
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
    DbModule,
    TenantModule,
    JobsModule,
    NotificationsModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
