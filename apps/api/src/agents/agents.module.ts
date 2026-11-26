import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { UsersModule } from "../users/users.module.js";
import { AgentsController } from "./agents.controller.js";
import { AgentsService } from "./agents.service.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [AgentsService, OrgBindingGuard],
  controllers: [AgentsController],
})
export class AgentsModule {}
