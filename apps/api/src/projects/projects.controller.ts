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
import { ProjectsService } from "./projects.service.js";
import { type Environment, NewEnvironment, NewProject, Patch as PatchBody, type Project } from "./projects.schemas.js";

/**
 * Rust `api/projects.rs` and `api/environments.rs`. Check order matches axum's extractors: org binding (401), path ids
 * (404), query (400), body (400), then the handler's own validation and queries.
 */
@Controller("v1/projects")
@UseGuards(OrgBindingGuard)
export class ProjectsController {
  constructor(@Inject(ProjectsService) private readonly svc: ProjectsService) {}

  @Post()
  @HttpCode(201)
  async create(@Body() body: unknown, @Res({ passthrough: true }) res: Response): Promise<Project> {
    const input = NewProject.parse(body);
    const project = await this.svc.createProject(input.name, input.description ?? "");
    res.setHeader("Location", `/v1/projects/${project.id}`);
    return project;
  }

  @Get()
  list(@Query() query: unknown) {
    return this.svc.listProjects(resolvePage(query));
  }

  @Get(":projectId")
  one(@Param("projectId") projectId: string): Promise<Project> {
    return this.svc.getProject(pathId(projectId));
  }

  @Patch(":projectId")
  async patch(@Param("projectId") projectId: string, @Body() body: unknown): Promise<Project> {
    const id = pathId(projectId);
    return this.svc.patchProject(id, PatchBody.parse(body));
  }

  @Delete(":projectId")
  @HttpCode(204)
  async remove(@Param("projectId") projectId: string): Promise<void> {
    await this.svc.deleteProject(pathId(projectId));
  }

  @Post(":projectId/environments")
  @HttpCode(201)
  async createEnvironment(
    @Param("projectId") projectId: string,
    @Body() body: unknown,
    @Res({ passthrough: true }) res: Response,
  ): Promise<Environment> {
    const pid = pathId(projectId);
    const input = NewEnvironment.parse(body);
    const env = await this.svc.createEnvironment(pid, input.name, input.description ?? "");
    res.setHeader("Location", `/v1/projects/${pid}/environments/${env.id}`);
    return env;
  }

  @Get(":projectId/environments")
  listEnvironments(@Param("projectId") projectId: string, @Query() query: unknown) {
    const pid = pathId(projectId);
    return this.svc.listEnvironments(pid, resolvePage(query));
  }

  @Get(":projectId/environments/:environmentId")
  oneEnvironment(@Param("projectId") projectId: string, @Param("environmentId") environmentId: string) {
    return this.svc.getEnvironment(pathId(projectId), pathId(environmentId));
  }

  @Patch(":projectId/environments/:environmentId")
  patchEnvironment(
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Body() body: unknown,
  ) {
    const [pid, eid] = [pathId(projectId), pathId(environmentId)];
    return this.svc.patchEnvironment(pid, eid, PatchBody.parse(body));
  }

  @Delete(":projectId/environments/:environmentId")
  @HttpCode(204)
  async removeEnvironment(@Param("projectId") projectId: string, @Param("environmentId") environmentId: string) {
    await this.svc.deleteEnvironment(pathId(projectId), pathId(environmentId));
  }
}
