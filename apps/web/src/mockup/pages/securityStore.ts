// Security product: the shared sample world. One store, so every Security page and detail view agrees.
import { agents, createStore, NOW, MIN, HOUR, DAY } from "../kit";

export type Sev = "Critical" | "High" | "Low";
export type Status = "Open" | "Resolved" | "Not a secret";
type SrcKind = "Repository" | "CI log" | "Agent transcript";
export type Group = "Repositories" | "CI logs" | "Agent transcripts";
type Line = [n: number, text: string, hit?: boolean];
export interface Finding {
  id: string; kind: string; rule: string; secret?: string; src: SrcKind; srcId: string; srcName: string; spot: string; file?: string;
  first: number; sev: Sev; rotated: boolean; rotationOpened: boolean; status: Status; who: string; lines: Line[]; reason?: string;
}
export interface Source { id: string; name: string; group: Group; last: number | null; on: boolean }
interface Detector { id: string; name: string; about: string; on: boolean }
const START_SETTINGS = { onPush: true, blockMerge: true, transcripts: true, autoRotate: false };
export type Settings = typeof START_SETTINGS;
export interface World { findings: Finding[]; sources: Source[]; det: Detector[]; paths: string[]; settings: Settings; seq: number }

export const href = (tab: string, id?: string) => `#/app/scan/${tab}${id ? `/${encodeURIComponent(id)}` : ""}`;
export const unid = (sub?: string) => { if (!sub) return ""; try { return decodeURIComponent(sub); } catch { return sub; } };
export const rank: Record<Sev, number> = { Critical: 0, High: 1, Low: 2 };
export const sevLabel = (f: Finding) => (f.sev === "Critical" ? "Critical: still valid" : f.sev === "Low" && f.rotated ? "Low: already rotated" : f.sev);
/** Safety net: whatever is shown, long runs of letters and digits become dots. */
export const mask = (t: string) => t.replace(/[A-Za-z0-9]{24,}/g, "••••••••");

/* ---------- seed ---------- */
type Seed = Omit<Finding, "rotationOpened" | "file"> & Partial<Pick<Finding, "rotationOpened">>;
const mk = (s: Seed): Finding => ({ rotationOpened: false, ...s, file: s.src === "Repository" ? s.spot.split(":")[0] : undefined });

const SEED_FINDINGS: Finding[] = [
  mk({ id: "f1", kind: "Stripe key", rule: "stripe", secret: "billing/production/STRIPE_SECRET_KEY", src: "Repository", srcId: "s3", srcName: "acme/billing", spot: "src/charge.ts:42", first: NOW - 2 * DAY, sev: "Critical", rotated: false, status: "Open", who: "Dana Okafor, commit 9c41e7a", lines: [[40, "import Stripe from \"stripe\";"], [41, ""], [42, "const stripe = new Stripe(\"sk_live_••••••••\");", true], [43, "export const charge = (cents: number) =>"]] }),
  mk({ id: "f2", kind: "AWS access key", rule: "aws", src: "Repository", srcId: "s4", srcName: "acme/infra", spot: "terraform/prod/main.tf:18", first: NOW - 5 * DAY, sev: "Critical", rotated: false, status: "Open", who: "Ravi Menon, commit 51be0d2", lines: [[16, "provider \"aws\" {"], [17, "  region     = \"us-east-1\""], [18, "  access_key = \"AKIA••••••••••••\"", true], [19, "}"]] }),
  mk({ id: "f3", kind: "OpenAI key", rule: "openai", secret: "acme-api/production/OPENAI_API_KEY", src: "Agent transcript", srcId: "t0", srcName: "claude-laptop", spot: "session from 09:12 today", first: NOW - 3 * HOUR, sev: "High", rotated: false, status: "Open", who: "claude-laptop, run by Tomer Levy", lines: [[212, "user: why does the summary call return 401?"], [213, "user: export OPENAI_API_KEY=sk-proj-••••••••", true], [214, "assistant: Thanks. Do not paste keys into prompts."]] }),
  mk({ id: "f4", kind: "GitHub token", rule: "gh", secret: "acme-api/production/GITHUB_DEPLOY_TOKEN", src: "CI log", srcId: "s5", srcName: "GitHub Actions: ci-deploy", spot: "run 1842, deploy.log:311", first: NOW - DAY, sev: "High", rotated: false, status: "Open", who: "GitHub Actions, workflow deploy.yml", lines: [[309, "+ git remote set-url origin"], [310, "+ https://x-access-token:ghp_••••••••@github.example/acme/acme-api", true], [311, "Pushing to origin main"]] }),
  mk({ id: "f5", kind: "Private key", rule: "pk", src: "Repository", srcId: "s4", srcName: "acme/infra", spot: "scripts/bootstrap.sh:7", first: NOW - 9 * DAY, sev: "High", rotated: false, status: "Open", who: "Sam Ito, commit 02fa8c1", lines: [[6, "cat > /tmp/deploy_key <<EOF"], [7, "-----BEGIN PRIVATE KEY-----", true], [8, "••••••••••••••••••••••••••••"], [9, "EOF"]] }),
  mk({ id: "f6", kind: "High-entropy string", rule: "ent", src: "Repository", srcId: "s2", srcName: "acme/acme-web", spot: "src/config.ts:12", first: NOW - 12 * DAY, sev: "Low", rotated: false, status: "Not a secret", who: "Lea Fischer, commit e77d310", reason: "Public map style id, shipped to every browser.", lines: [[11, "export const map = {"], [12, "  style: \"mapbox://styles/acme/••••••••\"", true], [13, "};"]] }),
  mk({ id: "f7", kind: "Stripe key", rule: "stripe", secret: "acme-api/staging/STRIPE_SECRET_KEY", src: "Repository", srcId: "s1", srcName: "acme/acme-api", spot: "tests/payments.test.ts:9", first: NOW - 20 * DAY, sev: "Low", rotated: true, status: "Resolved", who: "Ravi Menon, commit b3c9a14", lines: [[8, "describe(\"payments\", () => {"], [9, "  const key = \"sk_test_••••••••\";", true], [10, "});"]] }),
  mk({ id: "f8", kind: "Stripe key", rule: "stripe", secret: "billing/staging/STRIPE_SECRET_KEY", src: "Agent transcript", srcId: "t2", srcName: "codex-billing", spot: "session from 3 days ago", first: NOW - 14 * DAY, sev: "Low", rotated: true, status: "Resolved", who: "codex-billing, run by Dana Okafor", lines: [[88, "user: use sk_live_•••••••• for the refund test"], [89, "assistant: Use a test key instead."]] }),
  mk({ id: "f9", kind: "High-entropy string", rule: "ent", src: "Repository", srcId: "s1", srcName: "acme/acme-api", spot: "src/lib/ids.ts:5", first: NOW - 6 * DAY, sev: "Low", rotated: false, status: "Open", who: "Ravi Menon, commit 7a2d9e1", lines: [[4, "// Namespace for generated ids"], [5, "export const NS = \"••••••••••••\";", true], [6, "export const id = () => crypto.randomUUID();"]] }),
];

// Found the first time a source is scanned: a believable result for the sample scan.
const DISCOVERIES: Record<string, Seed> = {
  s1: { id: "f11", kind: "AWS access key", rule: "aws", src: "Repository", srcId: "s1", srcName: "acme/acme-api", spot: "config/aws.yml:4", first: NOW, sev: "Critical", rotated: false, status: "Open", who: "Ravi Menon, commit c81f0a7", lines: [[3, "aws:"], [4, "  access_key: AKIA••••••••••••", true], [5, "  region: us-east-1"]] },
  t2: { id: "f12", kind: "Stripe key", rule: "stripe", secret: "billing/production/STRIPE_SECRET_KEY", src: "Agent transcript", srcId: "t2", srcName: "codex-billing", spot: "session from 20 minutes ago", first: NOW, sev: "High", rotated: false, status: "Open", who: "codex-billing, run by Dana Okafor", lines: [[41, "user: the refund fails, key is sk_live_••••••••", true], [42, "assistant: I will use the gateway instead."]] },
};

const SEED_SOURCES: Source[] = [
  { id: "s1", name: "acme/acme-api", group: "Repositories", last: NOW - 12 * MIN, on: true },
  { id: "s2", name: "acme/acme-web", group: "Repositories", last: NOW - 12 * MIN, on: true },
  { id: "s3", name: "acme/billing", group: "Repositories", last: NOW - 2 * HOUR, on: true },
  { id: "s4", name: "acme/infra", group: "Repositories", last: NOW - 2 * HOUR, on: true },
  { id: "s5", name: "GitHub Actions: ci-deploy", group: "CI logs", last: NOW - 3 * MIN, on: true },
  { id: "s6", name: "GitHub Actions: billing tests", group: "CI logs", last: NOW - DAY, on: false },
  ...agents.map((a, i): Source => ({ id: `t${i}`, name: a.name, group: "Agent transcripts", last: a.name === "review-bot" ? null : NOW - (i + 1) * 20 * MIN, on: a.name !== "review-bot" })),
];

const SEED_DET: Detector[] = [
  { id: "stripe", name: "Stripe key", about: "Keys that start with sk_live_ or rk_live_. These can move real money.", on: true },
  { id: "aws", name: "AWS access key", about: "Access key ids that start with AKIA, with a secret key nearby.", on: true },
  { id: "openai", name: "OpenAI key", about: "Keys that start with sk- or sk-proj-, as used by the OpenAI API.", on: true },
  { id: "gh", name: "GitHub token", about: "Personal, app and deploy tokens that start with ghp_, ghs_ or github_pat_.", on: true },
  { id: "pk", name: "Private key block", about: "Text between BEGIN and END PRIVATE KEY lines.", on: true },
  { id: "ent", name: "High-entropy string", about: "Long random-looking text. Finds unknown kinds of secret, but flags many harmless ids.", on: false },
];

export const useWorld = createStore<World>({
  findings: SEED_FINDINGS,
  sources: SEED_SOURCES,
  det: SEED_DET,
  paths: ["tests/fixtures/**", "docs/examples/**", "**/*.snap"],
  settings: START_SETTINGS,
  seq: 1,
});

/* ---------- derived ---------- */
export const openCount = (w: World, srcId: string) => w.findings.filter((f) => f.srcId === srcId && f.status === "Open").length;

export const offReason = (s: Source, st: Settings): string | null =>
  s.group === "Agent transcripts" && !st.transcripts ? "Off because Scan agent transcripts is off in Settings." : s.on ? null : "Scanning is off for this source.";

/** Glob such as `tests/fixtures/**` or `**` + `/*.snap` against a file path. */
const globMatch = (glob: string, path: string) => {
  try {
    // oxlint-disable-next-line no-control-regex -- \u0000 and \u0001 are deliberate private placeholders for ** handling
    const re = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*\//g, "\u0000").replace(/\*\*/g, "\u0001").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]").replace(/\u0000/g, "(?:.*/)?").replace(/\u0001/g, ".*");
    return new RegExp(`^${re}$`).test(path);
  } catch { return false; }
};
export const ignored = (paths: string[], f: Finding) => !!f.file && paths.some((p) => globMatch(p, f.file ?? ""));

/* ---------- changes (pure: world in, world out) ---------- */
const upd = (w: World, id: string, fn: (f: Finding) => Finding): World => ({ ...w, findings: w.findings.map((f) => (f.id === id ? fn(f) : f)) });
export const resolve = (w: World, id: string) => upd(w, id, (f) => (f.status === "Open" ? { ...f, status: "Resolved" } : f));
export const dismiss = (w: World, id: string, reason: string) => upd(w, id, (f) => ({ ...f, status: "Not a secret", reason }));
export const reopen = (w: World, id: string) => upd(w, id, (f) => ({ ...f, status: "Open", reason: undefined }));

/** Open findings in ignored files become "Not a secret"; ones whose path is no longer ignored come back. */
export function reconcile(w: World, paths: string[]): { world: World; moved: number } {
  let moved = 0;
  const findings = w.findings.map((f): Finding => {
    if (f.status === "Open" && ignored(paths, f)) { moved++; return { ...f, status: "Not a secret", reason: "Ignored path" }; }
    if (f.status === "Not a secret" && f.reason === "Ignored path" && !ignored(paths, f)) { moved++; return { ...f, status: "Open", reason: undefined }; }
    return f;
  });
  return { world: { ...w, paths, findings }, moved };
}

/** A sample scan. The first scan of a source with a prepared result finds one new finding; later scans find nothing. */
export function scan(w: World, ids: string[]): { world: World; msg: string } {
  let scanned = 0, added = 0;
  const findings = [...w.findings];
  const sources = w.sources.map((s) => {
    if (!ids.includes(s.id) || offReason(s, w.settings)) return s;
    scanned++;
    const d = DISCOVERIES[s.id];
    const fresh = d && !findings.some((f) => f.id === d.id) ? mk(d) : null;
    if (fresh) {
      added++;
      let f = fresh;
      if (ignored(w.paths, f)) f = { ...f, status: "Not a secret", reason: "Ignored path" };
      else if (w.settings.autoRotate && f.secret) f = { ...f, rotationOpened: true };
      findings.unshift(f);
    }
    return { ...s, last: NOW };
  });
  const msg = scanned === 0 ? "Nothing to scan: the chosen sources are off." : `Scanned ${scanned === 1 ? "1 source" : `${scanned} sources`}. ${added ? `${added} new finding${added > 1 ? "s" : ""}.` : "No new findings."}`;
  return { world: { ...w, findings, sources }, msg };
}
