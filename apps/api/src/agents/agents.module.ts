import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { UsersModule } from "../users/users.module.js";
import { AgentTokensController } from "./agent-tokens.controller.js";
import { AgentTokensService } from "./agent-tokens.service.js";
import { AgentsController } from "./agents.controller.js";
import { AgentsService } from "./agents.service.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [AgentsService, AgentTokensService, OrgBindingGuard],
  controllers: [AgentsController, AgentTokensController],
})
export class AgentsModule {}
