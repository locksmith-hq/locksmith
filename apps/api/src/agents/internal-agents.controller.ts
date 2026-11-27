import { Controller, Get, Inject, Param, UseGuards } from "@nestjs/common";
import { ServiceOrgGuard } from "../auth/service-org.guard.js";
import { pathId } from "../platform/paging.js";
import { AgentsService } from "./agents.service.js";

/** Rust `api/internal.rs::agent_grants`: gateway-only (service token plus `X-Locksmith-Org`); ids, names and modes, never a value. */
@Controller("internal/v1/agents")
@UseGuards(ServiceOrgGuard)
export class InternalAgentsController {
  constructor(@Inject(AgentsService) private readonly svc: AgentsService) {}

  @Get(":agentId/grants")
  grants(@Param("agentId") agentId: string) {
    return this.svc.activeGrants(pathId(agentId));
  }
}
