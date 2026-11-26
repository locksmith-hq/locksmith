import { Inject, Injectable } from "@nestjs/common";
import { sql, type Transaction } from "kysely";
import { ClsService } from "nestjs-cls";
import { KYSELY, type Database } from "../db/db.module.js";
import type { DB } from "../db/types.js";

export type Tx = Transaction<DB>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CLS_ORG = "tenant.orgId";
const CLS_TX = "tenant.tx";
const CLS_USER = "tenant.userId";

/**
 * Request-scoped tenant transactions (decision A0-5). Every query for an org runs inside a
 * transaction whose first statement is `set_config('app.org_id', $1, true)` (transaction-local),
 * so row-level security sees the org and a pooled connection never leaks it. Session-level `SET`
 * is banned (see `no-session-set.test.ts`).
 */
@Injectable()
export class TenantService {
  constructor(
    @Inject(KYSELY) private readonly db: Database,
    @Inject(ClsService) private readonly cls: ClsService,
  ) {}

  /** Called by the auth guard (task 4.1) once the principal's org is known. */
  setOrgId(orgId: string): void {
    this.cls.set(CLS_ORG, orgId);
  }

  /** Called by the auth guard (task 4.1) with the authenticated user's id. */
  setUserId(userId: string): void {
    this.cls.set(CLS_USER, userId);
  }

  userId(): string | undefined {
    return this.cls.get<string | undefined>(CLS_USER);
  }

  orgId(): string | undefined {
    return this.cls.get<string | undefined>(CLS_ORG);
  }

  /** The request's open transaction; throws outside a tenant-scoped request. */
  tx(): Tx {
    const tx = this.cls.get<Tx | undefined>(CLS_TX);
    if (!tx) throw new Error("no tenant transaction in this request");
    return tx;
  }

  /** Runs `fn` in a transaction scoped to `orgId`. */
  async run<T>(orgId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    if (!UUID.test(orgId)) throw new Error("invalid org id");
    return this.db.transaction().execute(async (tx) => {
      await sql`select set_config('app.org_id', ${orgId}, true)`.execute(tx);
      return fn(tx);
    });
  }

  /** Runs `fn` with the transaction exposed through `tx()` for the rest of the request. */
  async runInRequest<T>(orgId: string, fn: () => Promise<T>): Promise<T> {
    return this.run(orgId, async (tx) => {
      this.cls.set(CLS_TX, tx);
      try {
        return await fn();
      } finally {
        this.cls.set(CLS_TX, undefined);
      }
    });
  }
}
