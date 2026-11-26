import { Global, Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createCoreClient } from "@locksmith/core-client";
import { CoreAuditSink } from "../audit/core-audit-sink.js";
import { AUDIT_SINK } from "../audit/audit-sink.js";
import { CORE_CLIENT } from "./core.tokens.js";

/**
 * The Rust core boundary (audit, token mint and verify, DEK wrap). The base URL and service
 * token come from the environment; a missing value fails startup (see `env.ts`), so the API
 * never runs with an audit sink it cannot reach.
 */
@Global()
@Module({
  providers: [
    {
      provide: CORE_CLIENT,
      inject: [ConfigService],
      useFactory: (config: ConfigService) =>
        createCoreClient({
          baseUrl: config.getOrThrow<string>("LOCKSMITH_CORE_URL"),
          token: () => config.get<string>("LOCKSMITH_CORE_SERVICE_TOKEN"),
        }),
    },
    { provide: AUDIT_SINK, useClass: CoreAuditSink },
  ],
  exports: [CORE_CLIENT, AUDIT_SINK],
})
export class CoreModule {}
