// Sample data for the console mockup. Nothing here is read from a control plane.
import type { IconName } from "./kit";
import { NOW } from "./time";

const m = 60,
  h = 3600,
  d = 86400;

export interface Project {
  id: string;
  description: string;
  envs: string[];
}
interface Grant {
  agent: string;
  expires: number | null;
}
export interface Secret {
  id: string;
  project: string;
  env: string;
  name: string;
  version: number;
  updated: number;
  lastUsed: number | null;
  grants: Grant[];
}
export interface Agent {
  name: string;
  description: string;
  icon: IconName;
  machine: string;
  enrolled: number;
  lastSeen: number;
}
export interface Session {
  id: string;
  agent: string;
  project: string;
  env: string;
  secrets: string[];
  started: number;
  expires: number;
  state: "active" | "revoked" | "expired";
  endedAt?: number;
}
type Outcome = "ok" | "denied" | "redaction_failed";
export interface Event {
  seq: number;
  at: number;
  label: string;
  target: string;
  actor: string;
  outcome: Outcome;
  digest: string;
}

export const projects: Project[] = [
  {
    id: "acme-api",
    description: "Public REST API and background workers",
    envs: ["development", "staging", "production"],
  },
  { id: "acme-web", description: "Customer web app", envs: ["development", "production"] },
  { id: "billing", description: "Invoices, payouts and the Stripe integration", envs: ["staging", "production"] },
];

export const agents: Agent[] = [
  {
    name: "claude-laptop",
    description: "Claude Code on Tomer's MacBook",
    icon: "s_claude",
    machine: "tomer-mbp",
    enrolled: NOW - 21 * d,
    lastSeen: NOW - 40,
  },
  {
    name: "ci-deploy",
    description: "GitHub Actions deploy job",
    icon: "s_terminal",
    machine: "gha-runner",
    enrolled: NOW - 64 * d,
    lastSeen: NOW - 3 * m,
  },
  {
    name: "codex-billing",
    description: "Codex working on the billing service",
    icon: "s_code",
    machine: "dana-linux",
    enrolled: NOW - 9 * d,
    lastSeen: NOW - 6 * m,
  },
  {
    name: "review-bot",
    description: "Pull request reviewer",
    icon: "s_spark",
    machine: "review-vm-2",
    enrolled: NOW - 2 * d,
    lastSeen: NOW - 5 * h,
  },
];

let n = 0;
const s = (
  project: string,
  env: string,
  name: string,
  version: number,
  updatedAgo: number,
  usedAgo: number | null,
  grants: Grant[],
): Secret => ({
  id: `sec_${++n}`,
  project,
  env,
  name,
  version,
  updated: NOW - updatedAgo,
  lastUsed: usedAgo === null ? null : NOW - usedAgo,
  grants,
});
const g = (agent: string, inSecs: number | null = null): Grant => ({
  agent,
  expires: inSecs === null ? null : NOW + inSecs,
});

export const secrets: Secret[] = [
  s("acme-api", "production", "STRIPE_SECRET_KEY", 4, 12 * d, 2 * m, [g("ci-deploy"), g("claude-laptop", 5 * h)]),
  s("acme-api", "production", "DATABASE_URL", 2, 48 * d, 3 * m, [g("ci-deploy")]),
  s("acme-api", "production", "OPENAI_API_KEY", 7, 3 * d, 40, [g("claude-laptop", 5 * h), g("review-bot", 6 * d)]),
  s("acme-api", "production", "SENTRY_AUTH_TOKEN", 1, 90 * d, 9 * d, []),
  s("acme-api", "production", "GITHUB_DEPLOY_TOKEN", 3, 20 * d, 3 * m, [g("ci-deploy")]),
  s("acme-api", "staging", "STRIPE_SECRET_KEY", 2, 30 * d, 2 * h, [g("claude-laptop")]),
  s("acme-api", "staging", "DATABASE_URL", 5, 6 * d, 50 * m, [g("claude-laptop"), g("ci-deploy")]),
  s("acme-api", "development", "OPENAI_API_KEY", 3, 15 * d, 12 * m, [g("claude-laptop")]),
  s("acme-api", "development", "DATABASE_URL", 1, 70 * d, 12 * m, [g("claude-laptop")]),
  s("acme-web", "production", "POSTHOG_API_KEY", 1, 110 * d, 1 * d, [g("ci-deploy")]),
  s("acme-web", "development", "MAPBOX_TOKEN", 2, 33 * d, null, []),
  s("billing", "production", "STRIPE_SECRET_KEY", 6, 1 * d, 6 * m, [g("codex-billing", 2 * h)]),
  s("billing", "production", "TAX_API_KEY", 2, 25 * d, 4 * d, [g("codex-billing", 2 * h)]),
  s("billing", "staging", "STRIPE_SECRET_KEY", 3, 14 * d, 6 * m, [g("codex-billing")]),
];

// Agent tokens live 15 minutes, so every bar ends within a quarter of an hour.
export const sessions: Session[] = [
  {
    id: "tok_8f2a1c04",
    agent: "claude-laptop",
    project: "acme-api",
    env: "production",
    secrets: ["OPENAI_API_KEY", "STRIPE_SECRET_KEY"],
    started: NOW - 2 * m,
    expires: NOW + 13 * m,
    state: "active",
  },
  {
    id: "tok_51d9e7b2",
    agent: "ci-deploy",
    project: "acme-api",
    env: "production",
    secrets: ["GITHUB_DEPLOY_TOKEN", "DATABASE_URL"],
    started: NOW - 6 * m,
    expires: NOW + 9 * m,
    state: "active",
  },
  {
    id: "tok_c03e44a1",
    agent: "codex-billing",
    project: "billing",
    env: "production",
    secrets: ["STRIPE_SECRET_KEY"],
    started: NOW - 13 * m,
    expires: NOW + 110,
    state: "active",
  },
  {
    id: "tok_77ab9d10",
    agent: "review-bot",
    project: "acme-api",
    env: "production",
    secrets: ["OPENAI_API_KEY"],
    started: NOW - 5 * h - 15 * m,
    expires: NOW - 5 * h,
    state: "expired",
    endedAt: NOW - 5 * h,
  },
  {
    id: "tok_1b22f0c9",
    agent: "codex-billing",
    project: "billing",
    env: "staging",
    secrets: ["STRIPE_SECRET_KEY"],
    started: NOW - 50 * m,
    expires: NOW - 40 * m,
    state: "revoked",
    endedAt: NOW - 44 * m,
  },
];

const hex = (i: number) => ((0x9e3779b1 * (i + 7)) >>> 0).toString(16).padStart(8, "0");
const e = (i: number, ago: number, label: string, target: string, actor: string, outcome: Outcome = "ok"): Event => ({
  seq: 18420 - i,
  at: NOW - ago,
  label,
  target,
  actor,
  outcome,
  digest: hex(i),
});

export const events: Event[] = [
  e(0, 40, "Secret used", "acme-api/production/OPENAI_API_KEY → api.openai.com", "claude-laptop"),
  e(1, 2 * m, "Secret used", "acme-api/production/STRIPE_SECRET_KEY → api.stripe.com", "claude-laptop"),
  e(2, 2 * m + 20, "Session started", "tok_8f2a1c04", "claude-laptop"),
  e(3, 3 * m, "Secret used", "acme-api/production/GITHUB_DEPLOY_TOKEN → api.github.com", "ci-deploy"),
  e(4, 4 * m, "Blocked", "acme-api/production/SENTRY_AUTH_TOKEN, no grant", "ci-deploy", "denied"),
  e(5, 6 * m, "Secret used", "billing/production/STRIPE_SECRET_KEY → api.stripe.com", "codex-billing"),
  e(
    6,
    9 * m,
    "Redaction failed",
    "billing/production/TAX_API_KEY, response withheld",
    "codex-billing",
    "redaction_failed",
  ),
  e(7, 31 * m, "Access granted", "acme-api/production/STRIPE_SECRET_KEY to claude-laptop, 6h", "tomer"),
  e(8, 44 * m, "Session revoked", "tok_1b22f0c9", "dana"),
  e(
    9,
    45 * m,
    "Blocked",
    "billing/staging/STRIPE_SECRET_KEY → pastebin.example, host not allowed",
    "codex-billing",
    "denied",
  ),
  e(10, 5 * h, "Secret used", "acme-api/production/OPENAI_API_KEY → api.openai.com", "review-bot"),
  e(11, 1 * d, "Version added", "billing/production/STRIPE_SECRET_KEY v6", "dana"),
  e(12, 2 * d, "Agent enrolled", "review-bot", "tomer"),
  e(13, 3 * d, "Version added", "acme-api/production/OPENAI_API_KEY v7", "tomer"),
];

// The hub: every product, grouped. A product without `href` is on the roadmap and not built yet.
export interface Product {
  id: string;
  name: string;
  icon: IconName;
  tint: "a" | "b" | "c" | "d";
  group: string;
  blurb: string;
  href?: string;
}
export const products: Product[] = [
  {
    id: "access",
    name: "Agent Gateway",
    icon: "relay",
    tint: "a",
    group: "Products",
    href: "#/access",
    blurb:
      "Give AI agents working access to APIs, Git, AWS and databases. The gateway uses the credential for them, so no agent ever holds it.",
  },
  {
    id: "secrets",
    name: "Secret Management",
    icon: "key",
    tint: "d",
    group: "Products",
    href: "#/secrets",
    blurb: "Keep secrets per project and environment, with versions, rotation and sync to where your apps run.",
  },
  {
    id: "certs",
    name: "Certificates",
    icon: "doc",
    tint: "b",
    group: "Products",
    blurb: "Issue, renew and revoke X.509 certificates for TLS, mTLS and code signing from your own authorities.",
  },
  {
    id: "keys",
    name: "KMS",
    icon: "lock",
    tint: "c",
    group: "Products",
    blurb:
      "Create and hold encryption and signing keys. Apps encrypt, decrypt, sign and verify without exporting a key.",
  },
  {
    id: "broker",
    name: "Access Broker",
    icon: "db",
    tint: "b",
    group: "Products",
    blurb: "People and agents reach databases and servers through brokered, recorded sessions. No standing passwords.",
  },
  {
    id: "scan",
    name: "Security",
    icon: "search",
    tint: "d",
    group: "Products",
    blurb: "Scan repositories, builds and agent transcripts for exposed secrets, and trace each finding to its source.",
  },
];
// Organization pages that are named in the sidebar but not built in this mockup.
export const extras: Product[] = [
  {
    id: "integrations",
    name: "Integrations",
    icon: "s_code",
    tint: "a",
    group: "",
    blurb: "Connect agents (Claude Code, Cursor, Codex), CI systems and cloud accounts.",
  },
  {
    id: "billing",
    name: "Usage and billing",
    icon: "clock",
    tint: "a",
    group: "",
    blurb: "Seats, agents and gateway requests this month. A billing problem never blocks unlock or export.",
  },
  {
    id: "settings",
    name: "Settings",
    icon: "s_window",
    tint: "a",
    group: "",
    blurb: "Name, region, sign-in methods and data export for this workspace.",
  },
];

export const workspaces = [
  { name: "Tomer", org: false, sub: "Personal" },
  { name: "Acme", org: true, sub: "5 members · 2 teams" },
];
export const members = [
  { name: "Tomer Levy", email: "tomer@acme.example", role: "Owner", team: "Platform", seen: NOW - 2 * m },
  { name: "Dana Okafor", email: "dana@acme.example", role: "Admin", team: "Billing", seen: NOW - 44 * m },
  { name: "Ravi Menon", email: "ravi@acme.example", role: "Member", team: "Platform", seen: NOW - 3 * h },
  { name: "Lea Fischer", email: "lea@acme.example", role: "Member", team: "Billing", seen: NOW - 2 * d },
  { name: "Sam Ito", email: "sam@acme.example", role: "Member", team: "Platform", seen: NOW - 6 * d },
];

// Each product is its own space: these are the sidebar items you get inside it. First item is the landing page.
export const spaces: Record<string, [tab: string, label: string, icon: IconName, group?: string][]> = {
  access: [
    ["sessions", "Sessions", "clock"],
    ["agents", "Agents", "sessions"],
    ["grants", "Grants", "key"],
    ["hosts", "Allowed hosts", "http"],
    ["activity", "Activity", "doc"],
    ["settings", "Settings", "s_window"],
  ],
  secrets: [
    ["secrets", "Secrets", "key", "Secrets"],
    ["dynamic", "Dynamic secrets", "power", "Secrets"],
    ["history", "History", "clock", "Secrets"],
    ["rotation", "Rotation", "rotate", "Lifecycle"],
    ["syncs", "Syncs", "relay", "Lifecycle"],
    ["access", "Agent access", "s_terminal", "Access"],
    ["members", "Members", "sessions", "Access"],
    ["machines", "Machines", "run", "Access"],
    ["approvals", "Approvals", "token", "Access"],
    ["activity", "Activity", "doc", "Observe"],
    ["settings", "Settings", "s_window", "Project"],
  ],
  // Secret Management before a project is open.
  "secrets-lobby": [
    ["overview", "Overview", "grid"],
    ["projects", "Projects", "key"],
    ["sharing", "Secret sharing", "arrow"],
  ],
  certs: [
    ["certificates", "Certificates", "doc"],
    ["authorities", "Authorities", "shield"],
    ["templates", "Profiles", "grid"],
    ["settings", "Settings", "s_window"],
  ],
  keys: [
    ["keys", "Keys", "lock"],
    ["clients", "Clients", "s_terminal"],
    ["activity", "Activity", "doc"],
    ["settings", "Settings", "s_window"],
  ],
  broker: [
    ["resources", "Resources", "db"],
    ["accounts", "Accounts", "sessions"],
    ["sessions", "Sessions", "clock"],
    ["recordings", "Recordings", "s_window"],
    ["settings", "Settings", "s_window"],
  ],
  scan: [
    ["findings", "Findings", "alert"],
    ["sources", "Sources", "git"],
    ["rules", "Rules", "shield"],
    ["settings", "Settings", "s_window"],
  ],
};

// One-time links that hand a secret to a person outside the workspace.
export interface Share {
  id: string;
  label: string;
  by: string;
  created: number;
  expires: number;
  views: number;
  maxViews: number;
}
export const shares: Share[] = [
  {
    id: "shr_4k2",
    label: "Staging DB password for the contractor",
    by: "Tomer Levy",
    created: NOW - 3 * h,
    expires: NOW + 21 * h,
    views: 0,
    maxViews: 1,
  },
  {
    id: "shr_9aa",
    label: "Stripe test key for the design agency",
    by: "Dana Okafor",
    created: NOW - 2 * d,
    expires: NOW + 5 * d,
    views: 2,
    maxViews: 5,
  },
  {
    id: "shr_1zc",
    label: "Wi-Fi for the offsite",
    by: "Ravi Menon",
    created: NOW - 6 * d,
    expires: NOW + 1 * d,
    views: 1,
    maxViews: 1,
  },
];

// Who can open which project. Org owners and admins reach every project; a member only the ones listed here.
export type ProjectRole = "Admin" | "Developer" | "Viewer";
export const projectMembers: Record<string, Record<string, ProjectRole>> = {
  "acme-api": { "ravi@acme.example": "Admin", "sam@acme.example": "Developer" },
  "acme-web": { "sam@acme.example": "Developer", "lea@acme.example": "Viewer" },
  billing: { "lea@acme.example": "Developer" },
};

// What each not-yet-built Secret Management page is for, shown on its placeholder.
export const about: Record<string, string> = {
  "secrets-lobby/overview":
    "Health across all your projects: secrets not rotated in a long time, grants about to expire, and secrets nobody has used.",
  "secrets/dynamic":
    "Credentials created on demand and destroyed after use, such as a database user that lives ten minutes.",
  "secrets/history": "Every change as a timeline. Roll back one secret or a whole environment to a point in time.",
  "secrets/rotation": "Replace a value on a schedule, with reminders for secrets that must be rotated by hand.",
  "secrets/syncs": "Push secrets to where your apps run: CI, cloud secret stores and hosting platforms.",
  "secrets/machines": "CI jobs and workloads that are not AI agents: tokens and workload identity.",
  "secrets/approvals": "Requests waiting for a yes: an agent asking to use a secret for a limited time.",
};

// Organization roles and what each may do. Built-in roles are fixed; custom ones can be edited.
export const permissions: [area: string, key: string, label: string][] = [
  ["Organization", "org.users", "Invite, remove and change users"],
  ["Organization", "org.billing", "See usage and manage billing"],
  ["Organization", "org.settings", "Change organization settings"],
  ["Secret Management", "sm.projects", "Create and delete projects"],
  ["Secret Management", "sm.all", "Open every project without being added"],
  ["Secret Management", "sm.share", "Share a secret through a link"],
  ["Agent Gateway", "gw.agents", "Enroll and remove agents"],
  ["Agent Gateway", "gw.revoke", "Revoke sessions"],
  ["Agent Gateway", "gw.pause", "Pause all agents"],
  ["Approvals", "ap.approve", "Approve access requests"],
];
export interface Role {
  name: string;
  builtIn: boolean;
  can: string[];
}
const ALL = permissions.map(([, k]) => k);
export const roles: Role[] = [
  { name: "Owner", builtIn: true, can: ALL },
  { name: "Admin", builtIn: true, can: ALL.filter((k) => k !== "org.billing") },
  { name: "Member", builtIn: true, can: ["sm.share", "gw.revoke"] },
];
export const groups = [
  { name: "Platform", projects: "acme-api, acme-web", about: "Runs the API and the web app" },
  { name: "Billing", projects: "billing", about: "Owns invoices and payouts" },
];

// Integrations: one shared set of connections to outside systems. Products pick from these; they never configure their own.
export const kinds = ["Agents", "Source and CI", "Cloud", "Databases", "Identity", "Notifications"] as const;
export type Kind = (typeof kinds)[number];
export interface Connection {
  id: string;
  kind: Kind;
  provider: string;
  name: string;
  icon: IconName;
  uses: [product: string, what: string][];
  scope: string;
  problem?: string;
}
export const providers: Record<Kind, string[]> = {
  Agents: ["Claude Code", "Cursor", "Codex", "Gemini CLI"],
  "Source and CI": ["GitHub", "GitLab", "CircleCI"],
  Cloud: ["AWS", "Google Cloud", "Vercel"],
  Databases: ["Postgres", "MySQL"],
  Identity: ["Google Workspace", "Okta", "Any OIDC provider"],
  Notifications: ["Slack", "Email", "Webhook"],
};
export const connections: Connection[] = [
  {
    id: "c1",
    kind: "Agents",
    provider: "Claude Code",
    name: "Claude Code plugin",
    icon: "s_claude",
    uses: [["Agent Gateway", "2 agents"]],
    scope: "All projects",
  },
  {
    id: "c2",
    kind: "Agents",
    provider: "Codex",
    name: "Codex plugin",
    icon: "s_code",
    uses: [["Agent Gateway", "1 agent"]],
    scope: "All projects",
  },
  {
    id: "c3",
    kind: "Source and CI",
    provider: "GitHub",
    name: "acme (GitHub organization)",
    icon: "git",
    uses: [
      ["Agent Gateway", "2 targets"],
      ["Secret Management", "3 syncs"],
      ["Security", "4 sources"],
    ],
    scope: "All projects",
  },
  {
    id: "c4",
    kind: "Cloud",
    provider: "AWS",
    name: "Production account",
    icon: "aws",
    uses: [
      ["Agent Gateway", "1 target"],
      ["Secret Management", "1 rotation"],
      ["KMS", "root key"],
    ],
    scope: "acme-api, billing",
  },
  {
    id: "c5",
    kind: "Cloud",
    provider: "Vercel",
    name: "acme-web on Vercel",
    icon: "http",
    uses: [["Secret Management", "2 syncs"]],
    scope: "acme-web",
  },
  {
    id: "c6",
    kind: "Databases",
    provider: "Postgres",
    name: "billing-db",
    icon: "db",
    uses: [
      ["Secret Management", "1 dynamic secret"],
      ["Access Broker", "1 resource"],
    ],
    scope: "billing",
  },
  {
    id: "c7",
    kind: "Identity",
    provider: "Okta",
    name: "Okta sign-in and provisioning",
    icon: "shield",
    uses: [["Organization", "sign-in for 5 users"]],
    scope: "Organization",
    problem: "Provisioning token expires in 3 days",
  },
  {
    id: "c8",
    kind: "Notifications",
    provider: "Slack",
    name: "#security channel",
    icon: "alert",
    uses: [["Organization", "blocked requests, expiring grants"]],
    scope: "Organization",
  },
];
