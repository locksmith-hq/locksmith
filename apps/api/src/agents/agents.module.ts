import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { ServiceOrgGuard } from "../auth/service-org.guard.js";
import { UsersModule } from "../users/users.module.js";
import { AgentTokensController } from "./agent-tokens.controller.js";
import { AgentTokensService } from "./agent-tokens.service.js";
import { AgentsController } from "./agents.controller.js";
import { AgentsService } from "./agents.service.js";
import { InternalAgentsController } from "./internal-agents.controller.js";
import { JwksController } from "./jwks.controller.js";

@Module({
  imports: [AuthModule, UsersModule],
  providers: [AgentsService, AgentTokensService, OrgBindingGuard, ServiceOrgGuard],
  controllers: [AgentsController, AgentTokensController, InternalAgentsController, JwksController],
})
export class AgentsModule {}
