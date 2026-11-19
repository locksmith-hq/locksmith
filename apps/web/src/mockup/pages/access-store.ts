// Sample data for the Machines and Approvals pages, one copy per project, so both keep their changes while you move between pages.
import { createStore, secrets, projects, members, MIN, HOUR, DAY, NOW } from "../kit";
import { projectMembers } from "../data";

export const ME = "Tomer Levy"; // organization owner
export type Kind = "GitHub Actions" | "Kubernetes" | "Token";
export interface Mach { name: string; kind: Kind; cond: [string, string][]; envs: string[]; last: number | null; tail: string }
/** `who` asked for `agent` to use a secret; they are the same name when an agent asks for itself. */
export interface Req {
  id: number; who: string; agent: string; secretId: string; env: string; hours: number; reason: string; at: number;
  verdict?: "Approved" | "Denied"; by?: string; decided?: number; comment?: string; granted?: number;
}
interface Grant { secretId: string; agent: string; expires: number | null }

export const envsOf = (p: string) => projects.find((x) => x.id === p)?.envs ?? ["development", "staging", "production"];

function perProject<T>(seed: (p: string) => T) {
  const use = createStore<Record<string, T>>({});
  const cache = new Map<string, T>();
  const first = (p: string) => { let v = cache.get(p); if (v === undefined) { v = seed(p); cache.set(p, v); } return v; };
  return (p: string) => {
    const [all, setAll] = use();
    return [all[p] ?? first(p), (f: (v: T) => T) => setAll((a) => ({ ...a, [p]: f(a[p] ?? first(p)) }))] as const;
  };
}

const seedMachines = (project: string): Mach[] => {
  const e = envsOf(project), at = (i: number) => e[Math.max(0, Math.min(i < 0 ? e.length + i : i, e.length - 1))]!, repo = `acme/${project}`;
  return [
    { name: "deploy-production", kind: "GitHub Actions", cond: [["Repository", repo], ["Branch", "main"]], envs: [at(-1)], last: NOW - 4 * MIN, tail: "" },
    { name: "api-workers", kind: "Kubernetes", cond: [["Service account", "prod/api-workers"]], envs: [at(-1)], last: NOW - 40, tail: "" },
    { name: "nightly-export", kind: "Token", cond: [], envs: [at(-1)], last: NOW - 9 * HOUR, tail: "a91c" },
  ];
};

const seedReqs = (project: string): Req[] => {
  const e = envsOf(project), prod = e.at(-1)!, stg = e[Math.max(0, e.length - 2)]!, ps = secrets.filter((s) => s.project === project);
  const pick = (env: string, i: number) => { const l = ps.filter((s) => s.env === env), x = l.length ? l : ps; return x[i % Math.max(x.length, 1)]?.id ?? ""; };
  const q = (id: number, who: string, agent: string, env: string, i: number, hours: number, reason: string, ago: number, extra: Partial<Req> = {}): Req =>
    ({ id, who, agent, env, hours, reason, secretId: pick(env, i), at: NOW - ago, ...extra });
  return [
    q(1, "claude-laptop", "claude-laptop", prod, 0, 4, "Reproduce the refund bug from ticket 4812 against live data shapes.", 6 * MIN),
    q(2, "codex-billing", "codex-billing", prod, 1, 8, "Backfill tax lines for last month's invoices.", 25 * MIN),
    q(3, "review-bot", "review-bot", stg, 0, 1, "Run integration checks on the open pull requests.", 3 * HOUR),
    q(4, "Lea Fischer", "codex-billing", prod, 1, 72, "Dana asked for a second agent on the payout job.", 5 * HOUR),
    q(5, ME, "claude-laptop", prod, 4, 2, "Check the deploy token after the access review.", 7 * HOUR),
    q(6, "ci-deploy", "ci-deploy", stg, 0, 2, "Smoke test after the staging deploy.", 1 * DAY, { verdict: "Approved", by: "Dana Okafor", decided: NOW - 1 * DAY + 4 * MIN, granted: 2 }),
    q(7, "review-bot", "review-bot", prod, 2, 24, "Review runs on production data.", 2 * DAY, { verdict: "Denied", by: ME, decided: NOW - 2 * DAY + 9 * MIN, comment: "Reviews never need production." }),
  ];
};

const seedGrants = (project: string): Grant[] =>
  secrets.filter((s) => s.project === project).flatMap((s) => s.grants.map((g) => ({ secretId: s.id, agent: g.agent, expires: g.expires })));

const useMachines = perProject(seedMachines);
const useReqs = perProject(seedReqs);
const useGrants = perProject(seedGrants);

export const hours = (n: number) => (n === 1 ? "1 hour" : n % 24 === 0 && n >= 48 ? `${n / 24} days` : `${n} hours`);
export const reqLine = (r: Req) => {
  const s = secrets.find((x) => x.id === r.secretId);
  return `${r.who === r.agent ? r.who : `${r.who} wants ${r.agent}`} to use ${s?.name ?? "a removed secret"} in ${r.env} for ${hours(r.hours)}`;
};

export function useAccess(project: string) {
  const [machines, setMachines] = useMachines(project), [reqs, setReqs] = useReqs(project), [, setGrants] = useGrants(project);
  const envs = envsOf(project);
  // Organization owners and admins, and admins of this project. Nobody approves their own request.
  const approvers = members.filter((m) => m.role !== "Member" || projectMembers[project]?.[m.email] === "Admin").map((m) => m.name);
  /** Why the signed-in person cannot decide a request, or "" when they can. */
  const blocked = (r: Req) => r.who === ME ? "You made this request. Someone else has to approve it." : approvers.includes(ME) ? "" : "Only owners, admins and project admins can approve.";

  return {
    envs, prod: envs.at(-1)!, machines, reqs, blocked,
    addMachine: (m: Mach) => setMachines((ms) => [m, ...ms]),
    revokeMachine: (name: string) => setMachines((ms) => ms.filter((m) => m.name !== name)),
    decide: (r: Req, verdict: "Approved" | "Denied", comment: string, h: number) => {
      setReqs((xs) => xs.map((x) => (x.id === r.id ? { ...x, verdict, by: ME, decided: NOW, comment: comment.trim() || undefined, granted: verdict === "Approved" ? h : undefined } : x)));
      if (verdict === "Approved") setGrants((gs) => [...gs.filter((g) => !(g.secretId === r.secretId && g.agent === r.agent)), { secretId: r.secretId, agent: r.agent, expires: NOW + h * HOUR }]);
    },
  };
}
