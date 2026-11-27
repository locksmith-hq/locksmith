import { Inject, Injectable } from "@nestjs/common";
import { sql } from "kysely";
import { ProblemException } from "../platform/problem.js";
import { type Page, paged } from "../platform/paging.js";
import { validateName } from "../orgs/orgs.service.js";
import { TenantService, type Tx } from "../tenant/tenant.service.js";
import type { Environment, Patch, Project } from "./projects.schemas.js";
import { validateDescription, validatePatch } from "./validate.js";

type Row = { id: string; name: string; description: string; created_at: Date; updated_at: Date };
const iso = (d: Date) => new Date(d).toISOString();
const toProject = (r: Row): Project => ({
  id: r.id,
  name: r.name,
  description: r.description,
  created_at: iso(r.created_at),
  updated_at: iso(r.updated_at),
});
const toEnvironment = (r: Row & { project_id: string }): Environment => ({
  id: r.id,
  project_id: r.project_id,
  name: r.name,
  description: r.description,
  created_at: iso(r.created_at),
  updated_at: iso(r.updated_at),
});

const PROJECT_COLS = ["id", "name", "description", "created_at", "updated_at"] as const;
const ENV_COLS = ["id", "project_id", "name", "description", "created_at", "updated_at"] as const;

/** Projects and their environments, in the request's tenant transaction (row-level security scopes every query). */
@Injectable()
export class ProjectsService {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  private get tx(): Tx {
    return this.tenant.tx();
  }

  async createProject(name: string, description: string): Promise<Project> {
    validateName(name);
    validateDescription(description);
    const row = await this.tx
      .insertInto("projects")
      .values({ org_id: this.tenant.orgId()!, name, description })
      .returning(PROJECT_COLS)
      .executeTakeFirstOrThrow();
    return toProject(row);
  }

  async getProject(id: string): Promise<Project> {
    const row = await this.tx.selectFrom("projects").select(PROJECT_COLS).where("id", "=", id).executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toProject(row);
  }

  async listProjects(page: Page) {
    let q = this.tx.selectFrom("projects").select(PROJECT_COLS);
    if (page.after) q = q.where("id", ">", page.after);
    const rows = await q
      .orderBy("id")
      .limit(page.limit + 1)
      .execute();
    return paged(rows.map(toProject), page);
  }

  async patchProject(id: string, patch: Patch): Promise<Project> {
    validatePatch(patch);
    const row = await this.tx
      .updateTable("projects")
      .set({
        ...(patch.name != null ? { name: patch.name } : {}),
        ...(patch.description != null ? { description: patch.description } : {}),
        updated_at: sql<Date>`now()`,
      })
      .where("id", "=", id)
      .returning(PROJECT_COLS)
      .executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toProject(row);
  }

  /** A project with environments is a 409 (parents are RESTRICT-deleted): the filter maps the foreign-key error. */
  async deleteProject(id: string): Promise<void> {
    const res = await this.tx.deleteFrom("projects").where("id", "=", id).executeTakeFirst();
    if (res.numDeletedRows === 0n) throw new ProblemException("not-found");
  }

  private async requireProject(projectId: string): Promise<void> {
    const row = await this.tx.selectFrom("projects").select("id").where("id", "=", projectId).executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
  }

  async createEnvironment(projectId: string, name: string, description: string): Promise<Environment> {
    validateName(name);
    validateDescription(description);
    await this.requireProject(projectId);
    const row = await this.tx
      .insertInto("environments")
      .values({ org_id: this.tenant.orgId()!, project_id: projectId, name, description })
      .returning(ENV_COLS)
      .executeTakeFirstOrThrow();
    return toEnvironment(row);
  }

  async getEnvironment(projectId: string, id: string): Promise<Environment> {
    const row = await this.tx
      .selectFrom("environments")
      .select(ENV_COLS)
      .where("id", "=", id)
      .where("project_id", "=", projectId)
      .executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toEnvironment(row);
  }

  async listEnvironments(projectId: string, page: Page) {
    await this.requireProject(projectId);
    let q = this.tx.selectFrom("environments").select(ENV_COLS).where("project_id", "=", projectId);
    if (page.after) q = q.where("id", ">", page.after);
    const rows = await q
      .orderBy("id")
      .limit(page.limit + 1)
      .execute();
    return paged(rows.map(toEnvironment), page);
  }

  async patchEnvironment(projectId: string, id: string, patch: Patch): Promise<Environment> {
    validatePatch(patch);
    const row = await this.tx
      .updateTable("environments")
      .set({
        ...(patch.name != null ? { name: patch.name } : {}),
        ...(patch.description != null ? { description: patch.description } : {}),
        updated_at: sql<Date>`now()`,
      })
      .where("id", "=", id)
      .where("project_id", "=", projectId)
      .returning(ENV_COLS)
      .executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toEnvironment(row);
  }

  async deleteEnvironment(projectId: string, id: string): Promise<void> {
    const res = await this.tx
      .deleteFrom("environments")
      .where("id", "=", id)
      .where("project_id", "=", projectId)
      .executeTakeFirst();
    if (res.numDeletedRows === 0n) throw new ProblemException("not-found");
  }
}
