import { Body, Controller, Delete, Get, HttpCode, Inject, Param, Post, Query, Res, UseGuards } from "@nestjs/common";
import type { Response } from "express";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { pathId, resolvePage } from "../platform/paging.js";
import { NewWorkloadIdentity, type WorkloadIdentity } from "./workload-identities.schemas.js";
import { WorkloadIdentitiesService } from "./workload-identities.service.js";

/** Rust `api/workload_identities.rs`. Check order as in axum's extractors: org binding, path id, query, body, handler. */
@Controller("v1/workload-identities")
@UseGuards(OrgBindingGuard)
export class WorkloadIdentitiesController {
  constructor(@Inject(WorkloadIdentitiesService) private readonly svc: WorkloadIdentitiesService) {}

  @Post()
  @HttpCode(201)
  async create(@Body() body: unknown, @Res({ passthrough: true }) res: Response): Promise<WorkloadIdentity> {
    const input = NewWorkloadIdentity.parse(body);
    const out = await this.svc.create(input);
    res.setHeader("Location", `/v1/workload-identities/${out.id}`);
    return out;
  }

  @Get()
  list(@Query() query: unknown) {
    return this.svc.list(resolvePage(query));
  }

  @Get(":id")
  one(@Param("id") id: string): Promise<WorkloadIdentity> {
    return this.svc.get(pathId(id));
  }

  @Delete(":id")
  @HttpCode(204)
  async remove(@Param("id") id: string): Promise<void> {
    await this.svc.remove(pathId(id));
  }
}
