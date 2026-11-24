import { DEV_ORG_HEADER, send } from "./client.ts";
import type { Json } from "./normalise.ts";

interface Tenant {
  orgId: string;
  /** Dev-auth header binding a request to this org (as `just api` enables). */
  auth: Record<string, string>;
}

/** Two users in two orgs, so scenarios can prove a tenant cannot reach the other's rows. */
export interface Seed {
  /** Unique suffix of this run's org names; the recorder replaces it with `<run>`. */
  run: string;
  a: Tenant;
  b: Tenant;
}

async function createOrg(name: string): Promise<Tenant> {
  const res = await send({ method: "POST", path: "/v1/orgs", body: { name } });
  const body = res.body as { id?: string } | null;
  if (res.status !== 201 || typeof body?.id !== "string") {
    throw new Error(`seed: POST /v1/orgs returned ${res.status} ${JSON.stringify(res.body as Json)}`);
  }
  return { orgId: body.id, auth: { [DEV_ORG_HEADER]: body.id } };
}

/** Fresh orgs with unique names, so reruns against one database stay independent. */
export async function seed(run = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`): Promise<Seed> {
  return { run, a: await createOrg(`contract-a-${run}`), b: await createOrg(`contract-b-${run}`) };
}
