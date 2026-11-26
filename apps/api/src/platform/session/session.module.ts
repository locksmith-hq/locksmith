import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import type { Env } from "../../env.js";
import { AUDIT_SINK } from "./audit-sink.js";
import { CoreAuditSink } from "./core-audit-sink.js";
import { SessionController } from "./session.controller.js";
import { SessionService } from "./session.service.js";
import { UsersService } from "./users.service.js";

@Module({
  controllers: [SessionController],
  providers: [
    UsersService,
    SessionService,
    {
      provide: AUDIT_SINK,
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) => {
        const url = config.get("LOCKSMITH_CORE_URL", { infer: true });
        const token = config.get("LOCKSMITH_CORE_TOKEN", { infer: true });
        return url && token ? new CoreAuditSink(url, token) : null;
      },
    },
  ],
})
export class SessionModule {}
