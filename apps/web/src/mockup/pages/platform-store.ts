// Shared sample data for the workspace-level Notifications and MCP pages (and the top-bar bell).
// Lives outside React so switches and disconnections survive moving between pages.
import { agents, createStore, DAY, HOUR, MIN, NOW } from "../kit";

/* ---------- Notification center ---------- */

export interface Notice { id: string; at: number; read: boolean; title: string; body: string; product: string; level: "info" | "action" | "urgent"; href?: string }

const n = (id: string, ago: number, read: boolean, level: Notice["level"], product: string, title: string, body: string, href?: string): Notice =>
  ({ id, at: NOW - ago, read, level, product, title, body, href });

export const useNotices = createStore<Notice[]>([
  n("n1", 6 * MIN, false, "urgent", "Security", "A live Stripe key was found in acme-web", "The scan of acme-web found a Stripe live key in src/checkout.ts on main, line 41. Anyone who can read the repository can use it.", "#/app/scan/findings"),
  n("n2", 12 * MIN, false, "action", "Secret Management", "claude-laptop is waiting for access to STRIPE_SECRET_KEY", "It asked for the production key in billing for 2 hours and gave the reason: replay a failed payout. Nothing is shared until someone approves.", "#/secrets/billing/approvals"),
  n("n3", 40 * MIN, false, "action", "Agent Gateway", "codex-billing loses access to STRIPE_SECRET_KEY in 2 hours", "Its grant on billing/production/STRIPE_SECRET_KEY ends at that point. Its running session will start getting refusals.", "#/access/grants"),
  n("n4", 80 * MIN, false, "info", "Organization", "Dana Okafor signed in from a new device", "A Chrome browser on Windows in Lisbon, Portugal. Her usual sign-ins are from a Mac in Tel Aviv.", "#/members"),
  n("n5", 3 * HOUR, false, "urgent", "Secret Management", "Rotation of OPENAI_API_KEY failed in acme-api production", "OpenAI answered 401: the admin key used for rotation was revoked. The old value is still live and has not changed.", "#/integrations"),
  n("n6", 5 * HOUR, true, "action", "Agent Gateway", "A request from ci-deploy was blocked", "It tried to use acme-api/production/SENTRY_AUTH_TOKEN but has no grant for it.", "#/access/grants"),
  n("n13", 9 * HOUR, true, "info", "Agent Gateway", "A request from codex-billing to pastebin.example was blocked", "The host is not on the allowed list, so the gateway did not send it. No secret left the gateway.", "#/access/hosts"),
  n("n8", 30 * HOUR, true, "action", "Secret Management", "The sync of acme-api staging to GitHub Actions failed", "GitHub rejected the token: it has expired. The values in GitHub are now out of date.", "#/integrations"),
  n("n9", 34 * HOUR, true, "action", "Certificates", "api.acme.example expires in 12 days", "The certificate was issued by Acme Internal CA and is not set to renew on its own.", "#/app/certs/certificates"),
  n("n10", 2 * DAY + 3 * HOUR, true, "action", "Access Broker", "Ravi Menon asked for a 30-minute session on billing-db", "He wants production access to fix a stuck invoice. It was approved by Dana Okafor and has ended.", "#/app/broker/sessions"),
  n("n12", 5 * DAY, true, "info", "Agent Gateway", "Tomer Levy paused all agents for 20 minutes", "A drill: every agent was refused during that time, then resumed on its own.", "#/access/agents"),
  n("n14", 6 * DAY, true, "info", "Secret Management", "Dana Okafor approved a request from codex-billing", "TAX_API_KEY in billing production, for 2 hours.", "#/secrets/billing/approvals"),
]);

export type ChannelId = "inapp" | "slack" | "email" | "webhook";
interface Sent { channel: ChannelId; to: string; ok: boolean; note: string }
const okTo = (channel: ChannelId, to: string): Sent => ({ channel, to, ok: true, note: "Delivered" });
const failTo = (channel: ChannelId, to: string, note: string): Sent => ({ channel, to, ok: false, note });

/** Per notice: the one action that resolves it, and who was told. */
export interface NoticeMeta { action: string; sent: Sent[] }
export const META: Record<string, NoticeMeta> = {
  n1: { action: "Open finding", sent: [okTo("inapp", "Tomer Levy, Dana Okafor"), okTo("slack", "#security channel"), okTo("email", "tomer@acme.example, dana@acme.example"), failTo("webhook", "hooks.acme.example", "503 from hooks.acme.example")] },
  n2: { action: "Review request", sent: [okTo("inapp", "Dana Okafor, Tomer Levy"), okTo("slack", "#security channel"), okTo("email", "dana@acme.example")] },
  n3: { action: "Open grants", sent: [okTo("inapp", "Dana Okafor"), okTo("slack", "#security channel")] },
  n4: { action: "Review sign-ins", sent: [okTo("inapp", "Dana Okafor"), okTo("email", "dana@acme.example")] },
  n5: { action: "Fix the connection", sent: [okTo("inapp", "Ravi Menon, Dana Okafor"), okTo("slack", "#security channel"), okTo("email", "ravi@acme.example, dana@acme.example")] },
  n6: { action: "Grant access", sent: [okTo("inapp", "Tomer Levy, Dana Okafor"), okTo("slack", "#security channel")] },
  n13: { action: "Open allowed hosts", sent: [okTo("inapp", "Tomer Levy, Dana Okafor"), okTo("slack", "#security channel")] },
  n8: { action: "Reconnect GitHub", sent: [okTo("inapp", "Ravi Menon"), okTo("email", "ravi@acme.example")] },
  n9: { action: "Open certificate", sent: [okTo("inapp", "Tomer Levy, Dana Okafor"), okTo("email", "tomer@acme.example, dana@acme.example")] },
  n10: { action: "Open session", sent: [okTo("inapp", "Dana Okafor, Tomer Levy"), okTo("slack", "#security channel")] },
  n12: { action: "Open agents", sent: [okTo("inapp", "Tomer Levy, Dana Okafor"), okTo("slack", "#security channel"), okTo("email", "tomer@acme.example, dana@acme.example")] },
  n14: { action: "Open approvals", sent: [okTo("inapp", "Dana Okafor"), okTo("slack", "#security channel")] },
};

export const CHANNEL_NAME: Record<ChannelId, string> = { inapp: "In-app inbox", slack: "Slack", email: "Email", webhook: "Webhook" };

export interface Channel { id: ChannelId; use: string; status: "connected" | "attention" | "off"; target: string; problem?: string }
export const useChannels = createStore<Channel[]>([
  { id: "inapp", use: "Always on. The bell and the Notifications inbox for every signed-in person.", status: "connected", target: "Every signed-in person" },
  { id: "slack", use: "Alerts the whole team can see, in one shared channel.", status: "connected", target: "#security channel" },
  { id: "email", use: "Detail a person may want to keep or forward.", status: "connected", target: "security@acme.example" },
  { id: "webhook", use: "Sends each event as JSON to a system of your own.", status: "attention", target: "https://hooks.acme.example/locksmith", problem: "The last 3 deliveries got a 503 from hooks.acme.example" },
]);

export type Who = "Owners and admins" | "Project admins" | "The person involved" | "Everyone";
export const WHO: Who[] = ["Owners and admins", "Project admins", "The person involved", "Everyone"];
export interface EventKind { id: string; product: string; label: string; about: string; urgent?: boolean }
export const EVENTS: EventKind[] = [
  { id: "gw.blocked", product: "Agent Gateway", label: "Request blocked", about: "An agent asked for something its grants or policies refuse." },
  { id: "gw.expiring", product: "Agent Gateway", label: "Grant expiring", about: "A grant ends within 24 hours." },
  { id: "gw.paused", product: "Agent Gateway", label: "Agents paused", about: "Someone paused every agent at once." },
  { id: "sm.approval", product: "Secret Management", label: "Approval waiting", about: "A request needs a yes before access is given." },
  { id: "sm.rotation", product: "Secret Management", label: "Rotation failed", about: "A scheduled rotation did not finish." },
  { id: "sm.sync", product: "Secret Management", label: "Sync failed", about: "Secrets did not reach their destination." },
  { id: "sc.critical", product: "Security", label: "Critical finding", about: "A live secret was found in code or a transcript." },
  { id: "ce.expiring", product: "Certificates", label: "Certificate expiring", about: "A certificate expires within 30 days." },
  { id: "ab.session", product: "Access Broker", label: "Session needs approval", about: "Someone asked for a brokered database or server session." },
  { id: "org.signin", product: "Organization", label: "New sign-in", about: "A person signed in from a device not seen before." },
];
export interface Rule { on: ChannelId[]; who: Who }
const rule = (who: Who, ...on: ChannelId[]): Rule => ({ who, on });
export const useRules = createStore<Record<string, Rule>>({
  "gw.blocked": rule("Owners and admins", "slack"),
  "gw.expiring": rule("Project admins", "slack", "email"),
  "gw.paused": rule("Owners and admins", "slack", "email"),
  "sm.approval": rule("Project admins", "slack", "email"),
  "sm.rotation": rule("Project admins", "slack", "email"),
  "sm.sync": rule("Project admins", "email"),
  "sc.critical": rule("Owners and admins", "slack", "email", "webhook"),
  "ce.expiring": rule("Owners and admins", "email"),
  "ab.session": rule("Owners and admins", "slack"),
  "org.signin": rule("The person involved", "email"),
});

/* ---------- MCP ---------- */

export type Layer = "hub" | "agent" | "local";
export type Kind = "read" | "act" | "change" | "credential";
export const KIND_LABEL: Record<Kind, string> = { read: "Reads", act: "Acts under policy", change: "Changes things", credential: "Hands over a credential" };
export interface Tool { id: string; layer: Layer; name: string; about: string; kind: Kind; on: boolean; risk?: string }

const CRED_ABOUT = "Creates a dynamic secret that lives minutes and is scoped to one job, and gives it to the agent. The only tool that puts a credential in the agent's hands.";
const CRED_RISK = "This puts a real, working credential into the agent's context. Anything that can read the agent's conversation can read it. It expires within 10 minutes and works for one job only, but until then it can be used outside Locksmith's gateway and its recording.";
const t = (layer: Layer, name: string, about: string, kind: Kind, on = true, risk?: string): Tool => ({ id: `${layer}.${name}`, layer, name, about, kind, on, risk });

export const useTools = createStore<Tool[]>([
  t("hub", "list_projects", "List the projects the signed-in person can open.", "read"),
  t("hub", "list_secret_names", "List the names of secrets in a project. Never their values.", "read"),
  t("hub", "read_activity", "Read recent activity: who used or changed what.", "read"),
  t("hub", "list_findings", "List exposed-secret findings and their status.", "read"),
  t("hub", "list_approvals", "List requests waiting for a yes.", "read"),
  t("hub", "list_grants", "List which agents have access to which keys, and until when.", "read"),
  t("hub", "approve_request", "Approve an access request that is waiting for this person.", "change", false, "An assistant could approve a request for you. If it is misled by text it read somewhere, it could approve something you would refuse. It uses your permissions, so it can approve anything you can."),
  t("hub", "revoke_grant", "Take away an agent's access to a key at once.", "change", false, "A wrong call cuts off an agent in the middle of a job. Running work for that agent fails straight away."),
  t("hub", "rotate_secret", "Start a rotation of one secret. The new value is stored and never shown.", "change", false, "A rotation replaces a live value. Apps that have not picked up the new one yet may fail until they sync."),
  t("agent", "list_keys", "List the key names this agent may use.", "read"),
  t("agent", "explain_block", "Explain why a request was blocked and what would fix it.", "read"),
  t("agent", "start_session", "Open a working session. Returns a session id, not a key.", "act"),
  t("agent", "call_api", "Call an API through the gateway with a named key. The agent gets the response, never the key.", "act"),
  t("agent", "run_git", "Run a git command through a relay that holds the credential.", "act"),
  t("agent", "run_db_query", "Run a database command through a relay that holds the credential.", "act"),
  t("agent", "request_access", "Ask a person for access to a key the agent does not have. Nothing is granted until someone approves.", "act"),
  t("agent", "issue_short_lived_credential", CRED_ABOUT, "credential", false, CRED_RISK),
  t("local", "list_keys", "List the key names available on this machine.", "read"),
  t("local", "explain_block", "Explain why a request was blocked and what would fix it.", "read"),
  t("local", "start_session", "Open a working session with the desktop app. Returns a session id, not a key.", "act"),
  t("local", "call_api", "Call an API through the desktop app with a named key. The agent gets the response, never the key.", "act"),
  t("local", "run_git", "Run a git command through the desktop app, which holds the credential.", "act"),
  t("local", "run_db_query", "Run a database command through the desktop app, which holds the credential.", "act"),
  t("local", "issue_short_lived_credential", CRED_ABOUT, "credential", false, CRED_RISK),
]);

export const useServers = createStore<Record<Layer, boolean>>({ hub: true, agent: true, local: true });

/** Per agent name: may it connect to the Agent MCP. */
export const useAgentAccess = createStore<Record<string, boolean>>(Object.fromEntries(agents.map((a) => [a.name, true])));

export type App = "Claude Code" | "Cursor" | "Codex" | "Gemini CLI" | "Other";
export const APPS: App[] = ["Claude Code", "Cursor", "Codex", "Gemini CLI", "Other"];
export interface Client { id: string; app: App; host: string; layer: Layer; as: string; last: number }
export const useClients = createStore<Client[]>([
  { id: "k1", app: "Claude Code", host: "tomer-mbp", layer: "hub", as: "Tomer Levy", last: NOW - 14 * MIN },
  { id: "k2", app: "Cursor", host: "dana-mbp", layer: "hub", as: "Dana Okafor", last: NOW - 2 * HOUR },
  { id: "k3", app: "Claude Code", host: "tomer-mbp", layer: "agent", as: "claude-laptop", last: NOW - 40 },
  { id: "k4", app: "Codex", host: "dana-linux", layer: "agent", as: "codex-billing", last: NOW - 6 * MIN },
  { id: "k5", app: "Other", host: "gha-runner", layer: "agent", as: "ci-deploy", last: NOW - 3 * MIN },
  { id: "k6", app: "Gemini CLI", host: "review-vm", layer: "agent", as: "review-bot", last: NOW - 5 * HOUR },
  { id: "k7", app: "Claude Code", host: "tomer-mbp", layer: "local", as: "Tomer Levy (desktop app)", last: NOW - 25 * MIN },
  { id: "k8", app: "Cursor", host: "ravi-mbp", layer: "local", as: "Ravi Menon (desktop app)", last: NOW - 1 * DAY },
]);
