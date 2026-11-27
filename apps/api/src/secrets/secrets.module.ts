import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { UsersModule } from "../users/users.module.js";
import { SecretsController } from "./secrets.controller.js";
import { SecretsService } from "./secrets.service.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [SecretsService, OrgBindingGuard],
  controllers: [SecretsController],
})
export class SecretsModule {}
