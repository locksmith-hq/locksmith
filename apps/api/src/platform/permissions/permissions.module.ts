import { Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { OrgBoundGuard } from "./org-bound.guard.js";

// Registered after AuthModule in AppModule so it runs after the AuthGuard.
@Module({ providers: [{ provide: APP_GUARD, useClass: OrgBoundGuard }] })
export class PermissionsModule {}
