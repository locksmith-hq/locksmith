import { Body, Controller, Get, HttpCode, Inject, Param, Post, Res, UseGuards } from "@nestjs/common";
import type { Response } from "express";
import { DEV_AUTH } from "../auth/dev-auth.js";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { ProblemException } from "../platform/problem.js";
import { TenantService } from "../tenant/tenant.service.js";
import { NewOrg, type Org } from "./orgs.schemas.js";
import { OrgsService } from "./orgs.service.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Rust `api/orgs.rs`: dev-only create, and get of the bound org (by id, or as `current`). */
@Controller("v1/orgs")
export class OrgsController {
  constructor(
    @Inject(OrgsService) private readonly orgs: OrgsService,
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(DEV_AUTH) private readonly devAuth: boolean,
  ) {}

  /** As in Rust, the body is parsed first (400), then without dev auth there is no way to name an org yet: 401 before any query. */
  @Post()
  @HttpCode(201)
  async create(@Body() body: unknown, @Res({ passthrough: true }) res: Response): Promise<Org> {
    const input = NewOrg.parse(body);
    if (!this.devAuth) throw new ProblemException("unauthenticated");
    const org = await this.orgs.create(input.name);
    res.setHeader("Location", `/v1/orgs/${org.id}`);
    return org;
  }

  @Get("current")
  @UseGuards(OrgBindingGuard)
  current(): Promise<Org> {
    return this.orgs.bound(this.tenant.orgId()!);
  }

  /** Only the bound org exists as far as a request can tell: another id, or a malformed one, is 404. */
  @Get(":orgId")
  @UseGuards(OrgBindingGuard)
  one(@Param("orgId") orgId: string): Promise<Org> {
    if (!UUID.test(orgId) || orgId.toLowerCase() !== this.tenant.orgId()) throw new ProblemException("not-found");
    return this.orgs.bound(this.tenant.orgId()!);
  }
}
