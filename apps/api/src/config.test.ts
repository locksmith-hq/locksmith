import { describe, expect, it } from "vitest";
import { loadEnv } from "./config.js";

describe("loadEnv", () => {
  it("applies defaults for non-secrets", () => {
    const env = loadEnv({ DATABASE_URL: "postgres://u:p@h/db" });
    expect(env.PORT).toBe(8081);
    expect(env.LOG_LEVEL).toBe("info");
  });

  it("fails fast without DATABASE_URL (no default for secrets)", () => {
    expect(() => loadEnv({})).toThrow(/DATABASE_URL/);
  });

  it("never echoes a bad value in the error", () => {
    const bad = "hunter2-not-a-port";
    try {
      loadEnv({ DATABASE_URL: "postgres://u:p@h/db", PORT: bad });
      throw new Error("should have thrown");
    } catch (e) {
      expect(String(e)).toContain("PORT");
      expect(String(e)).not.toContain(bad);
      expect(String(e)).not.toContain("postgres://");
    }
  });
});
