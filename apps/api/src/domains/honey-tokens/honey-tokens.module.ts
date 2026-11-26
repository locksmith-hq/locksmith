import { Module } from "@nestjs/common";
import { HoneyTokensController } from "./honey-tokens.controller.js";

@Module({ controllers: [HoneyTokensController] })
export class HoneyTokensModule {}
