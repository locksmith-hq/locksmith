import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { Logger } from "nestjs-pino";
import { AppModule } from "./app.module.js";
import { paidModules } from "./paid.js";

async function bootstrap() {
  const app = await NestFactory.create(AppModule.with(await paidModules()), { bufferLogs: true });
  app.useLogger(app.get(Logger));
  await app.listen(Number(process.env["PORT"] ?? 3000));
}

void bootstrap();
