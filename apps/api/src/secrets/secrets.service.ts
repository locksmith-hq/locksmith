import { Inject, Injectable } from "@nestjs/common";
import { sql } from "kysely";
import { type Page, paged } from "../platform/paging.js";
import { ProblemException } from "../platform/problem.js";
import { TenantService, type Tx } from "../tenant/tenant.service.js";
import type { Secret, SecretVersion } from "./secrets.schemas.js";

const iso = (d: Date) => new Date(d).toISOString();

/** Explicit column lists: `secret_versions.ciphertext` and `wrapped_dek` are never selected. */
const SECRET_COLS = ["id", "project_id", "environment_id", "name", "description", "created_at", "updated_at"] as const;

type SecretRow = {
  id: string;
  project_id: string;
  environment_id: string;
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
  version_count: string | number;
};

const toSecret = (r: SecretRow): Secret => ({
  id: r.id,
  project_id: r.project_id,
  environment_id: r.environment_id,
  name: r.name,
  description: r.description,
  version_count: Math.min(Number(r.version_count), 4294967295),
  created_at: iso(r.created_at),
  updated_at: iso(r.updated_at),
});

/** Secret metadata and version metadata, read-only, in the request's tenant transaction (row-level security). */
@Injectable()
export class SecretsService {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  private get tx(): Tx {
    return this.tenant.tx();
  }

  private secrets() {
    return this.tx
      .selectFrom("secrets")
      .select(SECRET_COLS)
      .select(
        sql<string>`(SELECT count(*) FROM secret_versions v WHERE v.org_id = secrets.org_id AND v.secret_id = secrets.id)`.as(
          "version_count",
        ),
      );
  }

  async listSecrets(projectId: string, environmentId: string, page: Page) {
    const env = await this.tx
      .selectFrom("environments")
      .select("id")
      .where("id", "=", environmentId)
      .where("project_id", "=", projectId)
      .executeTakeFirst();
    if (!env) throw new ProblemException("not-found");
    let q = this.secrets().where("project_id", "=", projectId).where("environment_id", "=", environmentId);
    if (page.after) q = q.where("id", ">", page.after);
    const rows = await q
      .orderBy("id")
      .limit(page.limit + 1)
      .execute();
    return paged(rows.map(toSecret), page);
  }

  async getSecret(projectId: string, environmentId: string, secretId: string): Promise<Secret> {
    const row = await this.secrets()
      .where("id", "=", secretId)
      .where("project_id", "=", projectId)
      .where("environment_id", "=", environmentId)
      .executeTakeFirst();
    if (!row) throw new ProblemException("not-found");
    return toSecret(row);
  }

  async listVersions(projectId: string, environmentId: string, secretId: string): Promise<{ items: SecretVersion[] }> {
    const secret = await this.tx
      .selectFrom("secrets")
      .select("id")
      .where("id", "=", secretId)
      .where("project_id", "=", projectId)
      .where("environment_id", "=", environmentId)
      .executeTakeFirst();
    if (!secret) throw new ProblemException("not-found");
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
