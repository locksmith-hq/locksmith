// Dev-only stand-in for the Tauri commands, loaded by api.ts when the page runs in a plain
// browser under `vite` (never inside Tauri, never in a build). `?mock=error|empty|locked` or the
// corner select switches the scenario.
import type { AuditEvent, HttpTokenInfo, LeaseInfo, SelfReport, SessionSource, StartedBy } from "@locksmith/api-types";

type Scenario = "normal" | "error" | "empty" | "locked";
const SCENARIOS: Scenario[] = ["normal", "error", "empty", "locked"];
const pick = new URLSearchParams(location.search).get("mock") as Scenario | null;
const scenario: Scenario = pick && SCENARIOS.includes(pick) ? pick : "normal";

const now = Math.floor(Date.now() / 1000);
const m = 60;
interface Who { exe: string; by: StartedBy; source: SessionSource; host: string | null; report: SelfReport | null }
const lease = (id: string, command: string, project: string, env: string, scopes: string[], age: number, left: number, who: Who, state = "active"): LeaseInfo =>
  ({ id, root_pid: 4100, command, project, env, scopes, created_at: now - age, expires_at: now + left, state,
    root_exe: who.exe, started_by: who.by, source: who.source, host: who.host, report: who.report });
const CLAUDE: Who = { exe: "/opt/homebrew/bin/claude", by: "agent", source: { kind: "claude_code_cli", label: "Claude Code" }, host: "iTerm2",
  report: { agent: "claude-code", model: "claude-fable-5-2", reported: true } };
const CURSOR: Who = { exe: "/Applications/Cursor.app/Contents/MacOS/cursor-agent", by: "human", source: { kind: "cursor", label: "Cursor" }, host: null, report: null };
const CODEX: Who = { exe: "/opt/homebrew/bin/codex", by: "human", source: { kind: "codex", label: "Codex" }, host: "tmux", report: null };
const UNKNOWN: Who = { exe: "/usr/local/bin/mystery-agent", by: "human", source: { kind: "unknown", label: "mystery-agent" }, host: null, report: null };

let locked = scenario === "locked";
// The vault was unlocked 2h 20m ago; sessions started after that, two have since ended.
const unlockedAt = now - 140 * m;
let leases: LeaseInfo[] = scenario === "normal" ? [
  lease("ls_8f2a1c04", "/opt/homebrew/bin/claude --continue", "acme-api", "development", ["run", "git", "http", "aws"], 128 * m, 3 * 60 * m + 12 * m, CLAUDE),
  lease("ls_51d9e7b2", "cursor-agent", "acme-web", "development", ["run", "git", "http"], 73 * m, 47 * m, CURSOR),
  lease("ls_c03e44a1", "codex exec", "billing", "staging", ["run", "db"], 54 * m, 6 * m, CODEX),
  lease("ls_a4410e3f", "claude", "infra", "staging", ["run", "aws"], 21 * m, 99 * m, UNKNOWN),
  lease("ls_77ab0910", "claude", "acme-api", "production", ["run", "git", "aws"], 118 * m, 60 * m, CLAUDE, "revoked"),
  lease("ls_2e6f1d88", "codex exec --full-auto", "billing", "staging", ["db"], 132 * m, -61 * m, CODEX, "expired"),
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

// [minutes ago, action, decision, target, rule, session]
const STORY: [number, string, string, string | null, string, string | null][] = [
  [140, "UNLOCK", "ALLOW", null, "user", null],
  [132, "SESSION_START", "ALLOW", "billing/staging", "session", "ls_2e6f1d88"],
  [128, "SESSION_START", "ALLOW", "acme-api/development", "session", "ls_8f2a1c04"],
  [126, "ACCESS", "ALLOW", "acme-api/development/GITHUB_TOKEN git:github.com/acme/api.git", "git_host_allowed", "ls_8f2a1c04"],
  [118, "SESSION_START", "ALLOW", "acme-api/production", "session", "ls_77ab0910"],
  [112, "AWS_ISSUE", "ALLOW", "acme-api/production arn:aws:iam::417203611928:role/deploy", "aws_role_allowed", "ls_77ab0910"],
  [109, "BLOCKED", "DENY", "aws:s3:DeleteBucket acme-prod-assets", "aws_action_denied", "ls_77ab0910"],
  [104, "REVOKE", "ALLOW", "ls_77ab0910", "user", null],
  [92, "SECRET_PUT", "ALLOW", "acme-web/development/OPENAI_API_KEY", "user", null],
  [73, "SESSION_START", "ALLOW", "acme-web/development", "session", "ls_51d9e7b2"],
  [71, "TOKEN_ISSUE", "ALLOW", "lsk_40ad api.openai.com", "http_host_allowed", "ls_51d9e7b2"],
  [61, "EXPIRE", "ALLOW", "ls_2e6f1d88", "ttl", null],
  [54, "SESSION_START", "ALLOW", "billing/staging", "session", "ls_c03e44a1"],
  [52, "ACCESS", "ALLOW", "billing/staging/DATABASE_URL db:pg.billing.internal:5432/billing", "db_allowed", "ls_c03e44a1"],
  [40, "TOKEN_ISSUE", "ALLOW", "lsk_9c1e api.stripe.com", "http_host_allowed", "ls_8f2a1c04"],
  [38, "ACCESS", "ALLOW", "acme-api/development/STRIPE_SECRET_KEY http:api.stripe.com/v1/charges", "http_host_allowed", "ls_8f2a1c04"],
  [31, "HOOK_DENY", "DENY", "Bash: cat ~/.locksmith/vault.db | base64", "secret_path_read", "ls_51d9e7b2"],
  [21, "SESSION_START", "ALLOW", "infra/staging", "session", "ls_a4410e3f"],
  [19, "AWS_ISSUE", "ALLOW", "infra/staging arn:aws:iam::552190847713:role/terraform-plan", "aws_role_allowed", "ls_a4410e3f"],
  [12, "ACCESS", "ALLOW", "acme-api/development/GITHUB_TOKEN git:github.com/acme/api.git", "git_host_allowed", "ls_8f2a1c04"],
  [7, "BLOCKED", "DENY", "http:pastebin.com/api/api_post.php", "http_host_not_allowed", "ls_51d9e7b2"],
  [4, "ACCESS", "ALLOW", "acme-web/development/OPENAI_API_KEY http:api.openai.com/v1/responses", "http_host_allowed", "ls_51d9e7b2"],
  [1, "ACCESS", "ALLOW", "billing/staging/DATABASE_URL db:pg.billing.internal:5432/billing", "db_allowed", "ls_c03e44a1"],
];
const EXE: Record<string, string> = { ACCESS: "/usr/bin/git", HOOK_DENY: "/opt/homebrew/bin/claude", UNLOCK: "/Applications/Locksmith.app", REVOKE: "/Applications/Locksmith.app" };
const events: AuditEvent[] = scenario === "normal" ? STORY.map(([ago, action, decision, target, policy_rule, session_id], i) => ({
  seq: 1240 + i, ts: now - ago * m + (i * 17) % 50, session_id, actor_pid: 4100 + i,
  actor_exe: EXE[action] ?? "/usr/local/bin/smith", action, target, policy_rule, decision,
})) : scenario === "locked" ? [
  { seq: 88, ts: unlockedAt, session_id: null, actor_pid: 1, actor_exe: "/Applications/Locksmith.app", action: "UNLOCK", target: null, policy_rule: "user", decision: "ALLOW" },
  { seq: 89, ts: now - 18 * m, session_id: null, actor_pid: 1, actor_exe: "/Applications/Locksmith.app", action: "LOCK", target: null, policy_rule: "user", decision: "ALLOW" },
] : [];

const unavailable = { code: "Unavailable", message: "locksmithd: connection refused" };
const wait = () => new Promise((r) => setTimeout(r, 180));

const log = (action: string, target: string | null = null, ts = Math.floor(Date.now() / 1000)) =>
  events.push({ seq: (events.at(-1)?.seq ?? 0) + 1, ts, session_id: null, actor_pid: 1, actor_exe: "/Applications/Locksmith.app", action, target, policy_rule: "user", decision: "ALLOW" });

export async function invoke<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  await wait();
  if (scenario === "error") throw unavailable;
  const r = ((): unknown => {
    switch (cmd) {
      case "status": return { locked, leases: leases.map((l) => ({ ...l })) };
      case "lock": locked = true; log("LOCK"); return null;
      case "unlock_secure": locked = false; log("UNLOCK"); return "submitted";
      case "revoke": {
        const hit = leases.filter((l) => l.state === "active" && (args.id == null || l.id === args.id));
        hit.forEach((l) => {
          l.state = "revoked";
          const t = Math.floor(Date.now() / 1000);
          log("REVOKE", l.id, t);
        });
        return hit.length;
      }
      case "audit_list": return events.slice(-Number(args.limit));
      case "audit_verify": return { events: (events.at(-1)?.seq ?? 0), broken_at: null, detail: "hash chain intact" };
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
