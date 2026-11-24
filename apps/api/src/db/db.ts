import { Kysely, PostgresDialect } from "kysely";
import pg from "pg";
import type { DB } from "./types.js";

export type Database = Kysely<DB>;

// One pool per process. The app role (never the table owner) must be in the URL; tenant context
// is set per transaction by the tenant interceptor (task 2.4), never with a session-level SET.
export function createDb(databaseUrl: string): Database {
  return new Kysely<DB>({
    dialect: new PostgresDialect({ pool: new pg.Pool({ connectionString: databaseUrl, max: 10 }) }),
  });
}
