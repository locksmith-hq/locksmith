import { Test } from "@nestjs/testing";
import { ConfigModule } from "@nestjs/config";
import { describe, expect, it } from "vitest";
import { DbModule, KYSELY, createKysely, type Database } from "./db.module.js";

// An unroutable URL: a lazy pool must never try to connect during these tests.
const URL = "postgres://u:p@127.0.0.1:1/none";

describe("createKysely", () => {
  it("builds a query without a database and compiles typed SQL", async () => {
    const db = createKysely(URL);
    const compiled = db.selectFrom("orgs").select("id").compile();
    expect(compiled.sql).toBe('select "id" from "orgs"');
    await db.destroy();
  });

  it("rejects an empty URL without echoing it", () => {
    expect(() => createKysely("")).toThrow("DATABASE_URL is empty");
  });
});

describe("DbModule", () => {
  it("provides KYSELY from DATABASE_URL and closes it on shutdown", async () => {
    const mod = await Test.createTestingModule({
      imports: [ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true, load: [() => ({ DATABASE_URL: URL })] }), DbModule],
    }).compile();
    const app = mod.createNestApplication();
    await app.init();
    expect(app.get<Database>(KYSELY)).toBeDefined();
    await app.close();
  });

  it("fails fast when DATABASE_URL is missing", async () => {
    await expect(
      Test.createTestingModule({
        imports: [ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true, ignoreEnvVars: true }), DbModule],
      }).compile(),
    ).rejects.toThrow();
  });
});
