import { Inject, Injectable } from "@nestjs/common";
import { sql, type Transaction } from "kysely";
import { KYSELY, type Database } from "../../db/db.module.js";
import type { DB } from "../../db/types.js";
import { ProblemException } from "../problem/problem.js";
import type { HumanIdentity } from "../auth/token-verifier.js";

/** Name of an auto-created personal org (same as the Rust control plane). */
const PERSONAL_ORG_NAME = "Personal";

export type ResolvedUser = {
  userId: string;
  orgId: string;
  /** This call saw the identity for the first time. */
  created: boolean;
  /** This call created a new personal org (false when the identity joined an existing one by verified email). */
  orgCreated: boolean;
};

type Tx = Transaction<DB>;
type Found = { id: string; personal_org_id: string; email: string | null };

/**
 * Users and personal orgs; port of services/control-plane/src/users.rs `resolve`. Only public
 * identity claims reach this class: a token never does.
 */
@Injectable()
export class UsersService {
  constructor(@Inject(KYSELY) private readonly db: Database) {}

  /** 403 before any database access when the email is unverified: it may be someone else's. */
  async resolve(identity: HumanIdentity): Promise<ResolvedUser> {
    if (!identity.emailVerified) throw new ProblemException("email-verification-required");
    const email = identity.email?.trim() || null;
    const { issuer, subject } = identity;
    return this.db.transaction().execute(async (tx) => {
      // Transaction-local login settings (RLS, migration 0011), as `with_login` in Rust.
      await sql`select set_config('app.login_issuer', ${issuer}, true),
                       set_config('app.login_subject', ${subject}, true),
                       set_config('app.login_email', ${email?.toLowerCase() ?? ""}, true)`.execute(tx);
      return this.resolveInTx(tx, issuer, subject, email);
    });
  }

  private async find(tx: Tx, issuer: string, subject: string): Promise<Found | undefined> {
    return tx
      .selectFrom("users")
      .select(["id", "personal_org_id", "email"])
      .where("issuer", "=", issuer)
      .where("subject", "=", subject)
      .executeTakeFirst();
  }

  private async resolveInTx(tx: Tx, issuer: string, subject: string, email: string | null): Promise<ResolvedUser> {
    const existing = await this.find(tx, issuer, subject);
    if (existing) return this.known(tx, existing, email);

    // Serialise first sign-ins of one identity: the loser waits, then finds the winner's row.
    await sql`select pg_advisory_xact_lock(hashtextextended(${`user:${issuer.length}:${issuer}${subject}`}, 0))`.execute(tx);
    const again = await this.find(tx, issuer, subject);
    if (again) return this.known(tx, again, email);

    // Link by verified email: join the personal org of an existing user with the same address.
    const linked = email
      ? await tx
          .selectFrom("users")
          .select("personal_org_id")
          .where("email_verified", "=", true)
          .where(sql<boolean>`lower(email) = lower(${email})`)
          .orderBy("created_at")
          .orderBy("id")
          .limit(1)
          .executeTakeFirst()
      : undefined;
    const orgId = linked?.personal_org_id ?? (await sql<{ id: string }>`select uuidv7() as id`.execute(tx)).rows[0]!.id;
    await bindOrg(tx, orgId);
    if (!linked) await tx.insertInto("orgs").values({ id: orgId, name: PERSONAL_ORG_NAME }).execute();
    const user = await tx
      .insertInto("users")
      .values({ issuer, subject, email, email_verified: true, personal_org_id: orgId })
      .returning("id")
      .executeTakeFirstOrThrow();
    return { userId: user.id, orgId, created: true, orgCreated: !linked };
  }

  /** A known identity: bind its org and keep its email claim current. */
  private async known(tx: Tx, found: Found, email: string | null): Promise<ResolvedUser> {
    if (found.email !== email) {
      await bindOrg(tx, found.personal_org_id);
      await tx.updateTable("users").set({ email, email_verified: true }).where("id", "=", found.id).execute();
    }
    return { userId: found.id, orgId: found.personal_org_id, created: false, orgCreated: false };
  }
}

async function bindOrg(tx: Tx, orgId: string): Promise<void> {
  await sql`select set_config('app.org_id', ${orgId}, true)`.execute(tx);
}
