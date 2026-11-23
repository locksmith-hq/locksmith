import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { TerminusModule } from "@nestjs/terminus";
import { LoggerModule } from "nestjs-pino";
import { validateEnv } from "./env.js";
import { HealthController } from "./health.controller.js";
import { REDACT_PATHS, loggerFormatters } from "./logging.js";

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validate: validateEnv }),
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env["LOG_LEVEL"] ?? "info",
        formatters: loggerFormatters,
        redact: { paths: REDACT_PATHS, censor: "[redacted]" },
      },
    }),
    TerminusModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
