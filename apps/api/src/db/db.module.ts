import { Global, Inject, Injectable, Module, type OnApplicationShutdown } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Kysely, PostgresDialect } from "kysely";
import pg from "pg";
import type { DB } from "./types.js";

/** Injection token for the shared Kysely instance. */
export const KYSELY = Symbol("KYSELY");

export type Database = Kysely<DB>;

/**
 * Builds a Kysely instance over a `pg` pool. The pool connects lazily, so this opens no connection
 * (and needs no database) until the first query. `connectionString` is a secret: it is passed to
 * `pg` and never logged or put in an error message.
 */
export function createKysely(connectionString: string, max = 10): Database {
  if (!connectionString) throw new Error("DATABASE_URL is empty");
  return new Kysely<DB>({
    dialect: new PostgresDialect({ pool: new pg.Pool({ connectionString, max }) }),
  });
}

@Injectable()
class DbLifecycle implements OnApplicationShutdown {
  constructor(@Inject(KYSELY) private readonly db: Database) {}

  async onApplicationShutdown(): Promise<void> {
    await this.db.destroy();
  }
}

/**
 * Global module exporting `KYSELY`. The app role's URL comes from `DATABASE_URL` (validated by the
 * env schema, no default). Migrations are applied by the Rust `locksmith-migrate` binary, never here.
 */
@Global()
@Module({
  providers: [
    {
      provide: KYSELY,
      inject: [ConfigService],
      useFactory: (config: ConfigService): Database => createKysely(config.getOrThrow<string>("DATABASE_URL")),
    },
    DbLifecycle,
  ],
  exports: [KYSELY],
})
export class DbModule {}
