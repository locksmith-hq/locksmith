// Shared sample data for the Agent Gateway pages and the Secret Management lobby.
import { createStore, DAY, HOUR, MIN, NOW, secrets } from "../kit";

export type Secret = (typeof secrets)[number];
export const label = (s: Secret) => `${s.project}/${s.env}/${s.name}`;

/** Every secret and its grants. Grants, Overview and Hosts all read and change this one copy. */
export const useSecrets = createStore<Secret[]>(secrets.map((s) => ({ ...s, grants: s.grants.map((g) => ({ ...g })) })));

export interface Host { host: string; names: string[]; week: number }
export const useHosts = createStore<Host[]>([
  { host: "api.openai.com", names: ["OPENAI_API_KEY"], week: 1842 },
  { host: "api.stripe.com", names: ["STRIPE_SECRET_KEY"], week: 913 },
  { host: "api.github.com", names: ["GITHUB_DEPLOY_TOKEN"], week: 604 },
  { host: "us.i.posthog.com", names: ["POSTHOG_API_KEY"], week: 58 },
  { host: "api.taxes.example", names: ["TAX_API_KEY"], week: 12 },
  { host: "db.billing.example", names: ["DATABASE_URL"], week: 237 },
  { host: "api.mapbox.com", names: ["MAPBOX_TOKEN"], week: 0 },
]);

export interface Req { id: string; host: string; agent: string; name: string; at: number; result: "Allowed" | "Blocked" }
let i = 0;
const rq = (host: string, agent: string, name: string, at: number, result: Req["result"] = "Allowed"): Req => ({ id: `r${++i}`, host, agent, name, at: NOW - at, result });
/** Requests the gateway saw. Blocked ones for a secret the host does not yet allow appear under "Recently blocked". */
export const useReqs = createStore<Req[]>([
  rq("api.openai.com", "claude-laptop", "OPENAI_API_KEY", 40), rq("api.openai.com", "review-bot", "OPENAI_API_KEY", 5 * HOUR), rq("api.openai.com", "claude-laptop", "OPENAI_API_KEY", 1 * DAY), rq("api.openai.com", "claude-laptop", "OPENAI_API_KEY", 2 * DAY),
  rq("api.stripe.com", "claude-laptop", "STRIPE_SECRET_KEY", 2 * MIN), rq("api.stripe.com", "codex-billing", "STRIPE_SECRET_KEY", 6 * MIN), rq("api.stripe.com", "claude-laptop", "STRIPE_SECRET_KEY", 2 * HOUR), rq("api.stripe.com", "ci-deploy", "STRIPE_SECRET_KEY", 1 * DAY),
  rq("api.github.com", "ci-deploy", "GITHUB_DEPLOY_TOKEN", 3 * MIN), rq("api.github.com", "ci-deploy", "GITHUB_DEPLOY_TOKEN", 1 * HOUR), rq("api.github.com", "ci-deploy", "GITHUB_DEPLOY_TOKEN", 1 * DAY),
  rq("us.i.posthog.com", "ci-deploy", "POSTHOG_API_KEY", 1 * DAY), rq("us.i.posthog.com", "ci-deploy", "POSTHOG_API_KEY", 3 * DAY),
  rq("api.taxes.example", "codex-billing", "TAX_API_KEY", 4 * DAY), rq("api.taxes.example", "codex-billing", "TAX_API_KEY", 5 * DAY),
  rq("db.billing.example", "claude-laptop", "DATABASE_URL", 50 * MIN), rq("db.billing.example", "ci-deploy", "DATABASE_URL", 3 * HOUR), rq("db.billing.example", "claude-laptop", "DATABASE_URL", 1 * DAY),
  rq("pastebin.example", "codex-billing", "STRIPE_SECRET_KEY", 45 * MIN, "Blocked"),
  rq("hooks.requestbin.example", "claude-laptop", "OPENAI_API_KEY", 3 * HOUR, "Blocked"),
  rq("errors.sentry.example", "ci-deploy", "SENTRY_AUTH_TOKEN", 1 * DAY, "Blocked"),
]);
/** When the gateway last sent a call to the host, or null if it never has. */
export const lastCall = (reqs: Req[], host: string) => reqs.filter((r) => r.host === host && r.result === "Allowed").reduce<number | null>((m, r) => (m === null || r.at > m ? r.at : m), null);

export const GRANT_MAX = ["1 day", "7 days", "30 days", "No limit"] as const;
export const useGw = createStore({ grantExpiry: "8 hours", needSecond: true, maxGrant: "7 days" as (typeof GRANT_MAX)[number], onBlocked: "Block it and tell an admin", paused: false });

export const EXPIRY: [label: string, secs: number | null][] = [["1 hour", HOUR], ["8 hours", 8 * HOUR], ["1 day", DAY], ["7 days", 7 * DAY], ["30 days", 30 * DAY], ["No expiry", null]];
export const until = (secs: number | null) => (secs === null ? null : NOW + secs);

/** The guardrail that stops giving or extending a grant, or null when it may go ahead. `secs` is how long it would last. */
export function guardrail(s: Secret, secs: number | null, gw: { needSecond: boolean; maxGrant: string }): string | null {
  if (gw.needSecond && s.env === "production") return "Access to production needs a second person";
  const cap = gw.maxGrant === "No limit" ? null : Number.parseInt(gw.maxGrant, 10) * DAY;
  return cap !== null && (secs === null || secs > cap) ? `Longest a grant may last is ${gw.maxGrant}` : null;
}
