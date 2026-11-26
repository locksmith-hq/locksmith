import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import type { Env } from "../../env.js";
import { CoreHoneyMinter, HONEY_MINTER } from "./honey-minter.js";
import { HoneyTokensController } from "./honey-tokens.controller.js";
import { HoneyTokensService } from "./honey-tokens.service.js";

@Module({
  controllers: [HoneyTokensController],
  providers: [
    HoneyTokensService,
    {
      provide: HONEY_MINTER,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) => {
        const url = config.get("LOCKSMITH_CORE_URL", { infer: true });
        const token = config.get("LOCKSMITH_CORE_TOKEN", { infer: true });
        return url && token ? new CoreHoneyMinter(url, token) : null;
      },
    },
  ],
})
export class HoneyTokensModule {}
