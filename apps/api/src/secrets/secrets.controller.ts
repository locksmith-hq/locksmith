import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Inject,
  Param,
  Patch,
  Post,
  Query,
  Res,
  UseGuards,
} from "@nestjs/common";
import type { Response } from "express";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { pathId, resolvePage } from "../platform/paging.js";
import { Patch as PatchBody } from "../projects/projects.schemas.js";
import { NewSecret, type Secret } from "./secrets.schemas.js";
import { SecretsService } from "./secrets.service.js";

/** Rust `api/secrets.rs`. Check order as axum: org binding, path ids, query, body, then the handler. */
@Controller("v1/projects/:projectId/environments/:environmentId/secrets")
@UseGuards(OrgBindingGuard)
export class SecretsController {
  constructor(@Inject(SecretsService) private readonly svc: SecretsService) {}

  @Post()
  @HttpCode(201)
  async create(
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Body() body: unknown,
    @Res({ passthrough: true }) res: Response,
  ): Promise<Secret> {
    const [pid, eid] = [pathId(projectId), pathId(environmentId)];
    const input = NewSecret.parse(body);
    const secret = await this.svc.create(pid, eid, input.name, input.description ?? "");
    res.setHeader("Location", `/v1/projects/${pid}/environments/${eid}/secrets/${secret.id}`);
    return secret;
  }

  @Get()
  list(@Param("projectId") projectId: string, @Param("environmentId") environmentId: string, @Query() query: unknown) {
    const [pid, eid] = [pathId(projectId), pathId(environmentId)];
    return this.svc.list(pid, eid, resolvePage(query));
  }

  @Get(":secretId")
  one(
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Param("secretId") secretId: string,
  ): Promise<Secret> {
    return this.svc.get(pathId(projectId), pathId(environmentId), pathId(secretId));
  }

  @Patch(":secretId")
  patch(
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Param("secretId") secretId: string,
    @Body() body: unknown,
  ): Promise<Secret> {
    const ids = [pathId(projectId), pathId(environmentId), pathId(secretId)] as const;
    return this.svc.patch(...ids, PatchBody.parse(body));
  }

  @Delete(":secretId")
  @HttpCode(204)
  async remove(
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Param("secretId") secretId: string,
  ): Promise<void> {
    await this.svc.remove(pathId(projectId), pathId(environmentId), pathId(secretId));
  }
}
