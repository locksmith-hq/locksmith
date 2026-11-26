import { Controller, Get, Inject, Query, UseGuards } from "@nestjs/common";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { resolvePage } from "../platform/paging.js";
import { AuditService, decodeSeqCursor } from "./audit.service.js";

/** Rust `api/audit.rs` read handlers: org binding (401), then query (400). */
@Controller("v1/audit")
@UseGuards(OrgBindingGuard)
export class AuditController {
  constructor(@Inject(AuditService) private readonly svc: AuditService) {}

  @Get("events")
  events(@Query() query: unknown) {
    return this.svc.listEvents(resolvePage(query, decodeSeqCursor));
  }

  @Get("status")
  status() {
    return this.svc.status();
  }
}
