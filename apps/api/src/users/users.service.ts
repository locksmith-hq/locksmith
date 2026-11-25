import { ForbiddenException, Inject, Injectable } from "@nestjs/common";
import { sql, type Transaction } from "kysely";
import { AUDIT_SINK, issuerHost, type AuditSink } from "../audit/audit-sink.js";
import type { HumanIdentity } from "../auth/human-auth.js";
import { KYSELY, type Database } from "../db/db.module.js";
import type { DB } from "../db/types.js";

/** Name of an auto-created personal org (Rust `users::PERSONAL_ORG_NAME`). */
const PERSONAL_ORG_NAME = "Personal";

export interface ResolvedUser {
  userId: string;
  orgId: string;
  /** The identity was seen for the first time by this call. */
  created: boolean;
  /** A new personal org was created (false when the identity joined one by verified email). */
  orgCreated: boolean;
}

type Tx = Transaction<DB>;

/**
 * Users and personal orgs (Rust `users::resolve`). A first sign-in creates the org and the
 * `users` row in one transaction under a per-identity advisory lock; a repeat sign-in only reads.
 * A new identity whose email is verified joins the personal org of an existing user with the
 * same verified email. An unverified identity is refused (403) before any row is touched.
 */
@Injectable()
export class UsersService {
  constructor(
    @Inject(KYSELY) private readonly db: Database,
    @Inject(AUDIT_SINK) private readonly audit: AuditSink,
  ) {}

  async resolve(identity: HumanIdentity): Promise<ResolvedUser> {
    if (!identity.emailVerified) throw new ForbiddenException("email verification required");
    const email = identity.email?.trim() || undefined;
    const { issuer, subject } = identity;
    return this.db.transaction().execute(async (tx) => {
      // Login settings let row-level security show this identity's own row and verified-email
      // twins before any org is known; all transaction-local.
      await sql`select set_config('app.login_issuer', ${issuer}, true),
                       set_config('app.login_subject', ${subject}, true),
                       set_config('app.login_email', ${email?.toLowerCase() ?? ""}, true)`.execute(tx);
      const known = await this.find(tx, issuer, subject);
      if (known) return this.known(tx, known, email);

      // Serialise first sign-ins of one identity; the loser finds the winner's committed row.
      await sql`select pg_advisory_xact_lock(hashtextextended(${`user:${issuer.length}:${issuer}${subject}`}, 0))`.execute(
        tx,
      );
      const again = await this.find(tx, issuer, subject);
      if (again) return this.known(tx, again, email);

      const linked = email
        ? (
            await tx
              .selectFrom("users")
              .select("personal_org_id")
              .where("email_verified", "=", true)
              .where(sql<boolean>`lower(email) = lower(${email})`)
              .orderBy("created_at")
              .orderBy("id")
              .limit(1)
              .executeTakeFirst()
          )?.personal_org_id
        : undefined;
      const orgId = linked ?? (await this.newOrgId(tx));
      await this.bindOrg(tx, orgId);
      if (!linked) {
        await tx.insertInto("orgs").values({ id: orgId, name: PERSONAL_ORG_NAME }).execute();
      }
      const user = await tx
        .insertInto("users")
        .values({ issuer, subject, email: email ?? null, email_verified: true, personal_org_id: orgId })
        .returning("id")
        .executeTakeFirstOrThrow();
      if (!linked) {
        await this.audit.append({
          kind: "org.personal_created",
          userId: user.id,
          orgId,
          issuerHost: issuerHost(issuer),
          outcome: "ok",
        });
      }
      return { userId: user.id, orgId, created: true, orgCreated: !linked };
    });
  }

  private async find(tx: Tx, issuer: string, subject: string) {
    return tx
      .selectFrom("users")
      .select(["id", "personal_org_id", "email"])
      .where("issuer", "=", issuer)
      .where("subject", "=", subject)
      .executeTakeFirst();
  }

  private async known(
    tx: Tx,
    row: { id: string; personal_org_id: string; email: string | null },
    email: string | undefined,
  ): Promise<ResolvedUser> {
    if ((row.email ?? undefined) !== email) {
      await this.bindOrg(tx, row.personal_org_id);
      await tx
        .updateTable("users")
        .set({ email: email ?? null, email_verified: true })
        .where("id", "=", row.id)
        .execute();
    }
    return { userId: row.id, orgId: row.personal_org_id, created: false, orgCreated: false };
  }

  private async bindOrg(tx: Tx, orgId: string): Promise<void> {
    await sql`select set_config('app.org_id', ${orgId}, true)`.execute(tx);
  }

  private async newOrgId(tx: Tx): Promise<string> {
    const { rows } = await sql<{ id: string }>`select uuidv7()::text as id`.execute(tx);
    return rows[0]!.id;
  }
}
