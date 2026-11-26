import { Module } from "@nestjs/common";
import { AuthGuard, HUMAN_AUTH } from "./auth.guard.js";
import { DEV_AUTH, devAuthEnabled } from "./dev-auth.js";
import { humanAuthConfig } from "./auth.config.js";
import { HumanAuth } from "./human-auth.js";

@Module({
  providers: [
    {
      provide: HUMAN_AUTH,
      useFactory: () => {
        const config = humanAuthConfig(process.env);
        return config ? new HumanAuth(config) : null;
      },
    },
    { provide: DEV_AUTH, useFactory: () => devAuthEnabled(process.env) },
    AuthGuard,
  ],
  exports: [AuthGuard, HUMAN_AUTH, DEV_AUTH],
})
export class AuthModule {}
