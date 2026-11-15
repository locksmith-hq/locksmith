// Dev-only stand-in for the Tauri commands, loaded by api.ts when the page runs in a plain
// browser under `vite` (never inside Tauri, never in a build). `?mock=error|empty|locked` or the
// corner select switches the scenario.
import type { AuditEvent, HttpTokenInfo, LeaseInfo } from "@locksmith/api-types";

type Scenario = "normal" | "error" | "empty" | "locked";
const SCENARIOS: Scenario[] = ["normal", "error", "empty", "locked"];
const pick = new URLSearchParams(location.search).get("mock") as Scenario | null;
const scenario: Scenario = pick && SCENARIOS.includes(pick) ? pick : "normal";

const now = Math.floor(Date.now() / 1000);
const lease = (id: string, command: string, project: string, env: string, scopes: string[], left: number, state = "active"): LeaseInfo =>
  ({ id, root_pid: 4100, command, project, env, scopes, created_at: now - 3600, expires_at: now + left, state });

let locked = scenario === "locked";
let leases: LeaseInfo[] = scenario === "normal" ? [
  lease("ls_8f2a1c04", "claude", "acme-api", "development", ["run", "git", "http", "aws"], 3 * 3600 + 12 * 60),
  lease("ls_51d9e7b2", "cursor-agent --workspace acme-web", "acme-web", "development", ["run", "http"], 47 * 60),
  lease("ls_c03e44a1", "codex exec", "billing", "staging", ["run", "db"], 6 * 60),
  lease("ls_77ab0910", "claude", "acme-api", "production", ["run", "git", "aws"], -1500, "revoked"),
  lease("ls_2e6f1d88", "aider", "billing", "staging", ["db"], -2800, "expired"),
] : [];

const KEYS: Record<string, string[]> = {
  "acme-api/development": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY", "STRIPE_SECRET_KEY"],
  "billing/staging": ["DATABASE_URL"],
  "default/development": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "GITHUB_TOKEN", "OPENAI_API_KEY", "STRIPE_SECRET_KEY"],
};

let tokens: HttpTokenInfo[] = scenario === "normal" ? [
  { prefix: "lsk_9c1e", key: "STRIPE_SECRET_KEY", project: "acme-api", env: "development", hosts: ["api.stripe.com"], placement: "header:Authorization", lease: "ls_8f2a1c04", created_at: now - 2400 },
  { prefix: "lsk_40ad", key: "OPENAI_API_KEY", project: "acme-web", env: "development", hosts: ["api.openai.com"], placement: "header:Authorization", lease: "ls_51d9e7b2", created_at: now - 900 },
] : [];

const ACTS: [string, string, string | null, string][] = [
  ["SESSION_START", "ALLOW", "acme-api/development", "session"],
  ["ACCESS", "ALLOW", "acme-api/development/GITHUB_TOKEN git:github.com/acme/api", "git_host_allowed"],
  ["TOKEN_ISSUE", "ALLOW", "lsk_9c1e api.stripe.com", "http_host_allowed"],
  ["ACCESS", "ALLOW", "acme-api/development/STRIPE_SECRET_KEY http:api.stripe.com", "http_host_allowed"],
  ["BLOCKED", "DENY", "http:pastebin.com", "http_host_not_allowed"],
  ["ACCESS", "ALLOW", "billing/staging/DATABASE_URL db:pg.billing.internal", "db_allowed"],
  ["BLOCKED", "DENY", "aws_not_allowed:s3:DeleteObject", "aws_action_denied"],
  ["REVOKE", "ALLOW", "ls_77ab0910", "user"],
  ["UNLOCK", "ALLOW", null, "user"],
  ["SECRET_PUT", "ALLOW", "acme-api/development/OPENAI_API_KEY", "user"],
];
const events: AuditEvent[] = scenario === "normal" ? Array.from({ length: 30 }, (_, i) => {
  const [action, decision, target, policy_rule] = ACTS[(i * 7) % ACTS.length]!;
  return {
    seq: i + 1, ts: now - (30 - i) * 137, session_id: action === "UNLOCK" ? null : "ls_8f2a1c04",
    actor_pid: 4100 + i, actor_exe: action === "ACCESS" ? "/usr/bin/git" : "/usr/local/bin/smith",
    action, target, policy_rule, decision,
  };
}) : [];

const unavailable = { code: "Unavailable", message: "locksmithd: connection refused" };
const wait = () => new Promise((r) => setTimeout(r, 180));

export async function invoke<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  await wait();
  if (scenario === "error") throw unavailable;
  const r = ((): unknown => {
    switch (cmd) {
      case "status": return { locked, leases: leases.map((l) => ({ ...l })) };
      case "lock": locked = true; return null;
      case "unlock_secure": locked = false; return "submitted";
      case "revoke": {
        const hit = leases.filter((l) => l.state === "active" && (args.id == null || l.id === args.id));
        hit.forEach((l) => {
          l.state = "revoked";
          const t = Math.floor(Date.now() / 1000);
          events.push({ seq: events.length + 1, ts: t, session_id: l.id, actor_pid: 1, actor_exe: "/Applications/Locksmith.app", action: "REVOKE", target: l.id, policy_rule: "user", decision: "ALLOW" });
        });
        return hit.length;
      }
      case "audit_list": return events.slice(-Number(args.limit));
      case "audit_verify": return { events: events.length, broken_at: null, detail: "hash chain intact" };
      case "key_names": return KEYS[`${args.project}/${args.env}`] ?? [];
      case "put_secret_secure": return "submitted";
      case "token_list": return tokens;
      case "token_revoke": tokens = tokens.filter((t) => t.prefix !== args.token); return 1;
      case "relay_info": return scenario === "empty"
        ? { git_port: null, http_port: null, aws_port: null, ca_hosts: [] }
        : { git_port: 47211, http_port: 47212, aws_port: null, ca_hosts: ["api.stripe.com", "api.openai.com"] };
      default: throw { code: "BadRequest", message: `unknown command ${cmd}` };
    }
  })();
  return r as T;
}

// Scenario switcher, outside the app tree so it never appears in a real build.
const sel = document.createElement("select");
sel.setAttribute("aria-label", "Mock scenario");
sel.style.cssText = "position:fixed;right:8px;bottom:8px;z-index:99;font:12px system-ui";
for (const s of SCENARIOS) sel.add(new Option(`mock: ${s}`, s, false, s === scenario));
sel.onchange = () => { location.search = `?mock=${sel.value}`; };
document.body.append(sel);
