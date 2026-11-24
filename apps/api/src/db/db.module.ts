import { Global, Module, type OnApplicationShutdown, Inject } from "@nestjs/common";
import { loadEnv } from "../config.js";
import { createDb, type Database } from "./db.js";

export const DATABASE = Symbol("DATABASE");

@Global()
@Module({
  providers: [{ provide: DATABASE, useFactory: () => createDb(loadEnv().DATABASE_URL) }],
  exports: [DATABASE],
})
export class DbModule implements OnApplicationShutdown {
  constructor(@Inject(DATABASE) private readonly db: Database) {}
  async onApplicationShutdown(): Promise<void> {
    await this.db.destroy();
  }
}
