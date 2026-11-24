import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { Logger } from "nestjs-pino";
import { AppModule } from "./app.module.js";
import { loadEnv } from "./config.js";

async function bootstrap() {
  const env = loadEnv();
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useLogger(app.get(Logger));
  await app.listen(env.PORT);
}

void bootstrap();
