import { Inject, Injectable } from "@nestjs/common";
import { sql } from "kysely";
import { validateName } from "../orgs/orgs.service.js";
import { type Page, paged } from "../platform/paging.js";
import { ProblemException } from "../platform/problem.js";
import type { Patch } from "../projects/projects.schemas.js";
import { validateDescription, validatePatch } from "../projects/validate.js";
import { TenantService, type Tx } from "../tenant/tenant.service.js";
import type { Secret, SecretVersionList } from "./secrets.schemas.js";

const iso = (d: Date) => new Date(d).toISOString();
type Row = {
  id: string;
  project_id: string;
  environment_id: string;
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
  version_count: string | number | bigint;
};
const toSecret = (r: Row): Secret => ({
  id: r.id,
  project_id: r.project_id,
  environment_id: r.environment_id,
  name: r.name,
  description: r.description,
  version_count: Math.min(Number(r.version_count), 4294967295),
  created_at: iso(r.created_at),
  updated_at: iso(r.updated_at),
});

const COLS = ["id", "project_id", "environment_id", "name", "description", "created_at", "updated_at"] as const;
/** Versions of the row's secret; row-level security limits the count to the bound org. */
const versionCount =
  sql<string>`(SELECT count(*) FROM secret_versions v WHERE v.org_id = secrets.org_id AND v.secret_id = secrets.id)`.as(
    "version_count",
  );

/** Secret metadata under a project and environment (Rust `api/secrets.rs`). No value field exists here, ever. */
@Injectable()
export class SecretsService {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  private get tx(): Tx {
    return this.tenant.tx();
  }

  private async requireEnvironment(projectId: string, environmentId: string): Promise<void> {
    const row = await this.tx
      .selectFrom("environments")
      .select("id")
      .where("id", "=", environmentId)
      .where("project_id", "=", projectId)
      .executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
  }

  async create(projectId: string, environmentId: string, name: string, description: string): Promise<Secret> {
    validateName(name);
    validateDescription(description);
    await this.requireEnvironment(projectId, environmentId);
    const row = await this.tx
      .insertInto("secrets")
      .values({
        org_id: this.tenant.orgId()!,
        project_id: projectId,
        environment_id: environmentId,
        name,
        description,
      })
      .returning([...COLS, versionCount])
      .executeTakeFirstOrThrow();
    return toSecret(row);
  }

  async get(projectId: string, environmentId: string, id: string): Promise<Secret> {
    const row = await this.tx
      .selectFrom("secrets")
      .select([...COLS, versionCount])
      .where("id", "=", id)
      .where("project_id", "=", projectId)
      .where("environment_id", "=", environmentId)
      .executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toSecret(row);
  }

  async list(projectId: string, environmentId: string, page: Page) {
    await this.requireEnvironment(projectId, environmentId);
    let q = this.tx
      .selectFrom("secrets")
      .select([...COLS, versionCount])
      .where("project_id", "=", projectId)
      .where("environment_id", "=", environmentId);
    if (page.after) q = q.where("id", ">", page.after);
    const rows = await q
      .orderBy("id")
      .limit(page.limit + 1)
      .execute();
    return paged(rows.map(toSecret), page);
  }

  async patch(projectId: string, environmentId: string, id: string, patch: Patch): Promise<Secret> {
    validatePatch(patch);
    const updated = await this.tx
      .updateTable("secrets")
      .set({
        ...(patch.name != null ? { name: patch.name } : {}),
        ...(patch.description != null ? { description: patch.description } : {}),
        updated_at: sql<Date>`now()`,
      })
      .where("id", "=", id)
      .where("project_id", "=", projectId)
      .where("environment_id", "=", environmentId)
      .returning("id")
      .executeTakeFirst();
    if (!updated) throw new ProblemException("not-found");
    return this.get(projectId, environmentId, id);
  }

  async remove(projectId: string, environmentId: string, id: string): Promise<void> {
    const res = await this.tx
      .deleteFrom("secrets")
      .where("id", "=", id)
      .where("project_id", "=", projectId)
      .where("environment_id", "=", environmentId)
      .executeTakeFirst();
    if (res.numDeletedRows === 0n) throw new ProblemException("not-found");
  }

  /** Version metadata, oldest first. Selects only `version`, `key_id` and `created_at`: ciphertext and wrapped keys are never read. */
  async listVersions(projectId: string, environmentId: string, secretId: string): Promise<SecretVersionList> {
    await this.get(projectId, environmentId, secretId);
    const rows = await this.tx
      .selectFrom("secret_versions")
      .select(["version", "key_id", "created_at"])
      .where("secret_id", "=", secretId)
      .orderBy("version")
      .execute();
    return {
      items: rows.map((r) => ({
        secret_id: secretId,
        version: r.version,
        key_id: r.key_id,
        created_at: iso(r.created_at),
      })),
    };
  }
}
