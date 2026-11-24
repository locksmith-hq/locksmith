import { Module } from "@nestjs/common";
import { TerminusModule } from "@nestjs/terminus";
import { LoggerModule } from "nestjs-pino";
import { loadEnv } from "./config.js";
import { HealthController } from "./health.controller.js";
import { loggerParams } from "./logging.js";

@Module({
  imports: [TerminusModule, LoggerModule.forRoot(loggerParams(loadEnv().LOG_LEVEL))],
  controllers: [HealthController],
})
export class AppModule {}
