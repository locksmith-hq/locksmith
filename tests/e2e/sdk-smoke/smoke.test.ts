// SDK smoke test against the local stack (`just up`, `just api`): create, list and delete an agent
// through @locksmith/sdk. Run it with `just sdk-smoke`, which signs in as the Keycloak test user
// and passes the short-lived token in a 0600 temp file (LOCKSMITH_SMOKE_TOKEN_FILE).
// It prints only ids and counts: never the token or the enrollment secret.
import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { createLocksmith, unwrap } from "@locksmith/sdk";

const tokenFile = process.env.LOCKSMITH_SMOKE_TOKEN_FILE;
const baseUrl = process.env.API_URL ?? "http://127.0.0.1:8080";

test.skipIf(!tokenFile)("create, list and delete an agent through the SDK", async () => {
  const token = readFileSync(tokenFile as string, "utf8").trim();
  const ls = createLocksmith({ baseUrl, token });
  const name = `sdk-smoke-${Date.now()}`;

  const created = unwrap(await ls.POST("/v1/agents", { body: { name } }));
  const id = created.agent.id;
  try {
    const list = unwrap(await ls.GET("/v1/agents", {}));
    expect(list.items.some((a) => a.id === id)).toBe(true);
  } finally {
    const del = await ls.DELETE("/v1/agents/{agent_id}", { params: { path: { agent_id: id } } });
    expect(del.response.status).toBeLessThan(300);
  }
  const after = unwrap(await ls.GET("/v1/agents", {}));
  expect(after.items.some((a) => a.id === id)).toBe(false);
});
