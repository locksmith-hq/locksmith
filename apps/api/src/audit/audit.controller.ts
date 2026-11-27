import { Controller, Get, Inject, Query, UseGuards } from "@nestjs/common";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { AuditReadsService } from "./audit-reads.service.js";

/** Rust `api/audit.rs`: reads only. Org binding first, then the query, then the handler. */
@Controller("v1/audit")
@UseGuards(OrgBindingGuard)
export class AuditController {
  constructor(@Inject(AuditReadsService) private readonly svc: AuditReadsService) {}

  @Get("events")
  events(@Query() query: unknown) {
    return this.svc.events(query);
  }

  @Get("status")
  status() {
    return this.svc.status();
  }
}
