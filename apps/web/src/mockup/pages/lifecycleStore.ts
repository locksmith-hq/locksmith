// Shared sample data for the lifecycle pages: one store per project, so dynamic secrets, history, rotation and syncs agree.
import { createStore, NOW, MIN, HOUR, DAY, plural, projects, secrets, agents, type IconName } from "../kit";
import { connections, type Connection } from "../data";

export const ME = "Tomer Levy";
export const pid = (p?: string) => p ?? "acme-api";
export const envsOf = (p: string) => projects.find((x) => x.id === p)?.envs ?? ["production"];
export const conn = (name: string) => connections.find((c) => c.name === name);
export const mins = (m: number) => (m % 60 === 0 ? plural(m / 60, "hour") : plural(m, "minute"));
export const stamp = (t: number) => `${new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
export const dest = (c: Connection) => (c.provider === "GitHub" ? "GitHub Actions" : c.provider === "AWS" ? "AWS Secrets Manager" : c.provider);

// Event handlers advance this clock by a second per change, so "later" is always strictly later.
let tick = 0;
let uid = 100;
const T = () => NOW + ++tick;
const nid = (x: string) => `${x}${++uid}`;

/* ---------- Types ---------- */
export type Act =
  | "Added" | "New version" | "Grant given" | "Grant revoked" | "Deleted" | "Rolled back"
  | "Rotation rule added" | "Rotation rule removed" | "Sync added" | "Sync removed" | "Dynamic secret added" | "Dynamic secret removed";
export const ACT_ICON: Record<Act, IconName> = {
  Added: "plus", "New version": "rotate", "Grant given": "key", "Grant revoked": "x", Deleted: "block", "Rolled back": "arrow",
  "Rotation rule added": "rotate", "Rotation rule removed": "rotate", "Sync added": "relay", "Sync removed": "relay",
  "Dynamic secret added": "power", "Dynamic secret removed": "power",
};
/** Changes to a secret that a rollback can undo. */
const ROLLABLE: Act[] = ["Added", "New version", "Grant given", "Grant revoked", "Deleted"];
const SYNC_ACTS: Act[] = ["Added", "New version", "Deleted", "Rolled back"];
export interface Entry { id: string; at: number; who: string; act: Act; name: string; env: string; note: string; after: string; undone?: boolean; mut?: boolean }
export interface Def { id: string; name: string; conn: string; what: string; ttl: number }
export interface Lease { id: string; def: string; who: string; kind: "Agent" | "Machine"; created: number; expires: number }
export interface Rule { sid: string; mode: "auto" | "manual"; via: string; every: number }
export interface Sync { id: string; env: string; c: Connection; target: string; on: boolean; fail?: string; at: number; okAt: number }
export interface P { defs: Def[]; leases: Lease[]; hist: Entry[]; rules: Rule[]; syncs: Sync[] }

export const kindOf = (name: string): "Agent" | "Machine" => (agents.some((a) => a.name === name) ? "Agent" : "Machine");

/* ---------- Seeds ---------- */
const DEFS: Record<string, Def[]> = {
  "acme-api": [
    { id: "d1", name: "Short-lived AWS role", conn: "Production account", what: "AWS role session for the workers", ttl: 15 },
    { id: "d2", name: "CI deploy role", conn: "Production account", what: "AWS role session that can deploy to ECS", ttl: 30 },
    { id: "d3", name: "Queue consumer role", conn: "Production account", what: "AWS role session, read-only on the job queues", ttl: 10 },
  ],
  billing: [
    { id: "d4", name: "Read-only Postgres user", conn: "billing-db", what: "Database user with select on all tables", ttl: 10 },
    { id: "d5", name: "Migration user", conn: "billing-db", what: "Database user that can change the schema", ttl: 5 },
  ],
};
const LEASES: Record<string, [id: string, def: string, who: string, createdAgo: number, expiresIn: number][]> = {
  "acme-api": [["l1", "d1", "claude-laptop", 4 * MIN, 11 * MIN], ["l2", "d2", "ci-deploy", 9 * MIN, 21 * MIN], ["l3", "d1", "worker-pool-2", 12 * MIN, 3 * MIN], ["l4", "d3", "worker-pool-1", 2 * MIN, 8 * MIN], ["l5", "d1", "review-bot", 7 * MIN, 8 * MIN]],
  billing: [["l6", "d4", "codex-billing", 3 * MIN, 7 * MIN], ["l7", "d4", "invoice-runner", 22 * MIN, 38 * MIN], ["l8", "d5", "migrate-job", 1 * MIN, 4 * MIN]],
};
type Seed = [ago: number, who: string, act: Act, env: string, name: string, note: string];
const HISTORY: Record<string, Seed[]> = {
  "acme-api": [
    [2 * HOUR, "Tomer Levy", "Grant given", "production", "STRIPE_SECRET_KEY", "claude-laptop, expires in 5 hours"],
    [3 * DAY, "Tomer Levy", "New version", "production", "OPENAI_API_KEY", "v7, replaces v6"],
    [3 * DAY + 4 * HOUR, "Ravi Menon", "Grant given", "production", "OPENAI_API_KEY", "review-bot, 7 days"],
    [6 * DAY, "Ravi Menon", "New version", "staging", "DATABASE_URL", "v5, replaces v4"],
    [6 * DAY + 3 * HOUR, "Ravi Menon", "Grant revoked", "staging", "DATABASE_URL", "review-bot"],
    [12 * DAY, "Tomer Levy", "New version", "production", "STRIPE_SECRET_KEY", "v4, replaces v3"],
    [15 * DAY, "Sam Ito", "New version", "development", "OPENAI_API_KEY", "v3, replaces v2"],
    [20 * DAY, "Ravi Menon", "New version", "production", "GITHUB_DEPLOY_TOKEN", "v3, replaces v2"],
    [30 * DAY, "Tomer Levy", "New version", "staging", "STRIPE_SECRET_KEY", "v2, replaces v1"],
    [40 * DAY, "Ravi Menon", "Deleted", "development", "OLD_REDIS_URL", "v2, last used 60 days earlier"],
    [48 * DAY, "Ravi Menon", "New version", "production", "DATABASE_URL", "v2, replaces v1"],
    [70 * DAY, "Sam Ito", "Added", "development", "DATABASE_URL", "v1"],
    [90 * DAY, "Tomer Levy", "Added", "production", "SENTRY_AUTH_TOKEN", "v1"],
  ],
  "acme-web": [
    [1 * DAY, "Sam Ito", "Grant given", "production", "POSTHOG_API_KEY", "ci-deploy, no expiry"],
    [33 * DAY, "Sam Ito", "New version", "development", "MAPBOX_TOKEN", "v2, replaces v1"],
    [60 * DAY, "Lea Fischer", "Grant revoked", "development", "MAPBOX_TOKEN", "claude-laptop"],
    [110 * DAY, "Sam Ito", "Added", "production", "POSTHOG_API_KEY", "v1"],
    [112 * DAY, "Sam Ito", "Added", "development", "MAPBOX_TOKEN", "v1"],
  ],
  billing: [
    [2 * HOUR, "Dana Okafor", "Grant given", "production", "TAX_API_KEY", "codex-billing, expires in 2 hours"],
    [1 * DAY, "Dana Okafor", "New version", "production", "STRIPE_SECRET_KEY", "v6, replaces v5"],
    [14 * DAY, "Dana Okafor", "New version", "staging", "STRIPE_SECRET_KEY", "v3, replaces v2"],
    [25 * DAY, "Lea Fischer", "New version", "production", "TAX_API_KEY", "v2, replaces v1"],
    [60 * DAY, "Dana Okafor", "Deleted", "staging", "TAX_API_KEY", "v1, replaced by a production-only key"],
    [120 * DAY, "Dana Okafor", "Added", "production", "STRIPE_SECRET_KEY", "v1"],
  ],
};
/** What the entry left the secret as; the rollback confirmation and "same as vN" read it. */
function afterOf(act: Act, note: string) {
  const v = /^v(\d+)/.exec(note);
  return act === "New version" || act === "Added" ? (v ? `v${v[1]}` : note) : act === "Deleted" ? "Deleted" : act === "Grant revoked" ? "No grant" : note;
}

const RULES: Record<string, [mode: "auto" | "manual", via: string, every: number]> = {
  "production/STRIPE_SECRET_KEY": ["manual", "", 90], "production/DATABASE_URL": ["auto", "Production account", 30], "production/OPENAI_API_KEY": ["manual", "", 30],
  "production/SENTRY_AUTH_TOKEN": ["manual", "", 60], "production/GITHUB_DEPLOY_TOKEN": ["auto", "acme (GitHub organization)", 30], "staging/DATABASE_URL": ["auto", "Production account", 14],
  "development/DATABASE_URL": ["manual", "", 60], "production/POSTHOG_API_KEY": ["manual", "", 90], "production/TAX_API_KEY": ["manual", "", 30],
};

const C = (name: string) => connections.find((c) => c.name === name)!;
type SyncSeed = [id: string, env: string, conn: string, target: string, lastAgo: number, fail?: string, paused?: boolean];
const SYNCS: Record<string, SyncSeed[]> = {
  "acme-api": [
    ["y1", "production", "acme (GitHub organization)", "acme/api-service, environment production", 4 * MIN],
    ["y2", "production", "acme (GitHub organization)", "acme/api-workers, repository secrets", 1 * DAY],
    ["y3", "production", "Production account", "/acme/api/production", 2 * HOUR, "access denied, the role cannot write to Secrets Manager"],
    ["y4", "staging", "acme (GitHub organization)", "acme/api-service, environment staging", 50 * MIN],
    ["y5", "development", "acme (GitHub organization)", "acme/api-service, Dependabot secrets", 9 * DAY, undefined, true],
  ],
  "acme-web": [
    ["y6", "production", "acme-web on Vercel", "acme-web, Production", 1 * DAY],
    ["y7", "development", "acme-web on Vercel", "acme-web, Preview and Development", 33 * DAY],
    ["y8", "production", "acme (GitHub organization)", "acme/web-app, repository secrets", 1 * DAY],
  ],
  billing: [
    ["y9", "production", "acme (GitHub organization)", "acme/billing-service, environment production", 1 * DAY],
    ["y10", "production", "Production account", "/acme/billing/production", 3 * HOUR, "AWS rate limit, will retry on the next change"],
    ["y11", "staging", "Production account", "/acme/billing/staging", 14 * DAY],
  ],
};

function seed(p: string): P {
  const leases = (LEASES[p] ?? []).map(([id, def, who, c, e]): Lease => ({ id, def, who, kind: kindOf(who), created: NOW - c, expires: NOW + e }));
  const hist = (HISTORY[p] ?? []).map(([a, who, act, env, name, note], i): Entry => ({ id: `h${i}`, at: NOW - a, who, act, env, name, note, after: afterOf(act, note) }));
  const rules = secrets.filter((s) => s.project === p).flatMap((s): Rule[] => { const r = RULES[`${s.env}/${s.name}`]; return r ? [{ sid: s.id, mode: r[0], via: r[1], every: r[2] }] : []; });
  const syncs = (SYNCS[p] ?? []).map(([id, env, c, target, lastAgo, fail, paused]): Sync => {
    const at = NOW - lastAgo;
    return { id, env, c: C(c), target, on: !paused, fail, at, okAt: fail ? at - 6 * HOUR : at };
  });
  return { defs: DEFS[p] ?? [], leases, hist, rules, syncs };
}

const BLANK: P = { defs: [], leases: [], hist: [], rules: [], syncs: [] };
const useStore = createStore<Record<string, P>>(Object.fromEntries(projects.map((x) => [x.id, seed(x.id)])));
/** This project's shared state and an updater that takes a pure `(P) => P`. */
export function useP(p: string) {
  const [all, set] = useStore();
  const up = (f: (s: P) => P) => set((a) => ({ ...a, [p]: f(a[p] ?? BLANK) }));
  return [all[p] ?? BLANK, up] as const;
}

/* ---------- Derived ---------- */
export const secretOf = (p: string, sid: string) => secrets.find((x) => x.project === p && x.id === sid);
/** Current version: the sample version plus every version added in this session. */
export const ver = (s: P, p: string, name: string, env: string) =>
  (secrets.find((x) => x.project === p && x.name === name && x.env === env)?.version ?? 1) +
  s.hist.filter((h) => h.mut && h.name === name && h.env === env && (h.act === "New version" || h.act === "Rolled back")).length;
const mine = (s: P, name: string, env: string) => s.hist.filter((h) => h.name === name && h.env === env);
const lastRot = (s: P, name: string, env: string) => mine(s, name, env).find((h) => h.act === "New version" || h.act === "Added")?.at ?? 0;
export const nextDue = (s: P, r: Rule, name: string, env: string) => lastRot(s, name, env) + r.every * DAY;
export const later = (s: P, e: Entry) => s.hist.filter((r) => r.name === e.name && r.env === e.env && r.at > e.at && !r.undone && ROLLABLE.includes(r.act));
export const canRoll = (s: P, e: Entry) => ROLLABLE.includes(e.act) && !e.undone && later(s, e).length > 0;
const versionAt = (s: P, e: Entry) => {
  const h = mine(s, e.name, e.env).find((x) => x.at <= e.at && (x.act === "New version" || x.act === "Added" || x.act === "Rolled back"));
  const m = h && /^v(\d+)/.exec(h.after);
  return m ? Number(m[1]) : null;
};
/** Secrets of the synced environment that changed since the last good run. */
const changedSince = (s: P, p: string, y: Sync) =>
  secrets.filter((x) => x.project === p && x.env === y.env && s.hist.some((h) => h.name === x.name && h.env === y.env && SYNC_ACTS.includes(h.act) && h.at > y.okAt)).length;
export const syncState = (s: P, p: string, y: Sync): { text: string; tone?: "live" | "warn" | "danger" } => {
  const changed = changedSince(s, p, y);
  return !y.on ? { text: "Paused" } : y.fail ? { text: `Failed: ${y.fail}`, tone: "danger" } : changed ? { text: `Out of date, ${plural(changed, "secret")} changed`, tone: "warn" } : { text: "In sync", tone: "live" };
};
const ruleText = (r: Rule) => `${r.mode === "auto" ? `automatic through ${r.via}` : "by hand"}, every ${plural(r.every, "day")}`;

/* ---------- Changes. Each takes the project's state and returns the next one. ---------- */
type NewEntry = Pick<Entry, "act" | "name" | "env" | "note" | "after">;
/** Record a change in History. */
function rec(s: P, e: NewEntry): P {
  return { ...s, hist: [{ id: nid("h"), at: T(), who: ME, mut: true, ...e }, ...s.hist] };
}

export function rotateNow(s: P, p: string, r: Rule): P {
  const sec = secretOf(p, r.sid);
  if (!sec) return s;
  const cur = ver(s, p, sec.name, sec.env);
  return rec(s, { act: "New version", name: sec.name, env: sec.env, note: `v${cur + 1}, replaces v${cur}`, after: `v${cur + 1}` });
}
export function rollback(s: P, p: string, e: Entry): P {
  const undo = later(s, e);
  const cur = ver(s, p, e.name, e.env);
  const tgt = versionAt(s, e);
  return rec({ ...s, hist: s.hist.map((x) => (undo.includes(x) ? { ...x, undone: true } : x)) }, {
    act: "Rolled back", name: e.name, env: e.env, note: `to how it was ${stamp(e.at)}, undid ${plural(undo.length, "change")}`, after: `v${cur + 1}${tgt ? `, same as v${tgt}` : ""}`,
  });
}

export function addRule(s: P, p: string, r: Rule): P {
  const sec = secretOf(p, r.sid);
  if (!sec) return s;
  return rec({ ...s, rules: [...s.rules, r] }, { act: "Rotation rule added", name: sec.name, env: sec.env, note: ruleText(r), after: ruleText(r) });
}
export function removeRule(s: P, p: string, sid: string): P {
  const sec = secretOf(p, sid);
  if (!sec || !s.rules.some((x) => x.sid === sid)) return s;
  return rec({ ...s, rules: s.rules.filter((x) => x.sid !== sid) }, { act: "Rotation rule removed", name: sec.name, env: sec.env, note: "The secret stays", after: "No rule" });
}

export function addDef(s: P, d: Def): P {
  return rec({ ...s, defs: [...s.defs, d] }, { act: "Dynamic secret added", name: d.name, env: "", note: `on ${d.conn}, lives ${mins(d.ttl)}`, after: d.conn });
}
export function removeDef(s: P, id: string): P {
  const old = s.defs.find((x) => x.id === id);
  if (!old) return s;
  return rec({ ...s, defs: s.defs.filter((x) => x.id !== id), leases: s.leases.filter((l) => l.def !== id) }, { act: "Dynamic secret removed", name: old.name, env: "", note: "Live leases revoked", after: "No definition" });
}
export const revoke = (s: P, id: string): P => ({ ...s, leases: s.leases.filter((l) => l.id !== id) });

export function addSync(s: P, p: string, y: Omit<Sync, "at" | "okAt">): P {
  const t = T();
  const next = rec(s, { act: "Sync added", name: y.target, env: y.env, note: `to ${dest(y.c)} through ${y.c.name}`, after: `${y.env} to ${dest(y.c)}` });
  return { ...next, syncs: [...next.syncs, { ...y, at: t, okAt: t }] };
}
export function removeSync(s: P, id: string): P {
  const y = s.syncs.find((x) => x.id === id);
  if (!y) return s;
  return rec({ ...s, syncs: s.syncs.filter((x) => x.id !== id) }, { act: "Sync removed", name: y.target, env: y.env, note: `to ${dest(y.c)}, copies left in place`, after: "No sync" });
}
export const setSync = (s: P, id: string, f: Partial<Sync>): P => ({ ...s, syncs: s.syncs.map((y) => (y.id === id ? { ...y, ...f } : y)) });
export function syncNow(s: P, id: string): P {
  const y = s.syncs.find((x) => x.id === id);
  if (!y) return s;
  const t = T();
  return setSync(s, id, y.fail ? { at: t } : { at: t, okAt: t });
}
