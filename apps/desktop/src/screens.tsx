import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import type {
  AuditEvent, AuditVerifyView, HttpTokenInfo, LeaseInfo, RelayInfo, SourceKind, StatusView,
} from "@locksmith/api-types";
import * as api from "./api";
import { ApiError, auditOutcomeMatches, type AuditOutcomeFilter, type Client, type Environment, type Project, type Secret, type SecretVersion } from "@locksmith/control-plane-client";
import { Icon, type IconName } from "@locksmith/ui";

export interface ScreenProps {
  st: StatusView | null;
  /** Runs an action, shows its rejection under the vault banner and refreshes status. */
  act: <T>(fn: () => Promise<T>, label?: (r: T) => string) => Promise<void>;
  /** Switches the main screen. */
  go: (tab: "Overview" | "Sessions" | "Keys" | "Tokens" | "Agents" | "Projects" | "Secrets" | "Relays" | "Audit") => void;
}

export const msg = (e: unknown) =>
  e && typeof e === "object" && "message" in e ? String((e as { message: unknown }).message) : String(e);
export const errCode = (e: unknown) =>
  e && typeof e === "object" && "code" in e ? String((e as { code: unknown }).code) : "";
export const plural = (n: number, word: string) => `${n} ${n === 1 ? word : `${word}s`}`;

const pad = (n: number) => String(n).padStart(2, "0");
export const clock = (ts: number) => { const d = new Date(ts * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const clockS = (ts: number) => `${clock(ts)}:${pad(new Date(ts * 1000).getSeconds())}`;
const stamp = (ts: number) => {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${clockS(ts)}`;
};
const left = (s: number) =>
  s <= 0 ? "expired" : s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
/** The agent is the basename of the session command's first word: "/opt/homebrew/bin/codex exec" is "codex". */
export const agent = (command: string) => command.trim().split(/\s+/)[0]!.split("/").pop() || command;
const nowSecs = () => Math.floor(Date.now() / 1000);
const isBad = (e: AuditEvent) => e.decision.toUpperCase() === "DENY" || e.action === "BLOCKED" || e.action === "HOOK_DENY";
const kind = (e: AuditEvent) => isBad(e) ? "blocked" : e.action === "REVOKE" || e.action === "TOKEN_REVOKE" ? "revoked" : "allowed";
const LABELS: Record<string, string> = {
  HOOK_DENY: "Blocked hook", BLOCKED: "Blocked", ACCESS: "Key used", TOKEN_ISSUE: "Token issued", TOKEN_REVOKE: "Token revoked",
  SESSION_START: "Session started", SESSION_END: "Session ended", REVOKE: "Revoked", EXPIRE: "Expired", SECRET_PUT: "Key saved",
  UNLOCK: "Vault unlocked", LOCK: "Vault locked", AWS_ISSUE: "AWS credentials issued",
};
/** Ledger actions in sentence case; unknown ones fall back to their own name, de-shouted. */
const label = (action: string) => LABELS[action] ?? (action[0]!.toUpperCase() + action.slice(1).toLowerCase().replace(/_/g, " "));
/** Ledger payloads break only after "/" and ":", never mid-token. */
const breakable = (s: string) =>
  s.split(/(?<=[/:])/).map((part, i) => <Fragment key={i}>{i > 0 && <wbr />}{part}</Fragment>);
const reducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
const STRIKE_MS = 480;
const SOON_S = 600;

/** Loads once per `deps` change and reports its own failure inline. */
function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState("");
  const load = useCallback(async () => {
    try { setData(await fn()); setErr(""); } catch (e) { setErr(msg(e)); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { void load(); }, [load]);
  return { data, err, load, alert: err ? <Alert>{err}</Alert> : null };
}

const Alert = ({ children }: { children: React.ReactNode }) =>
  <p role="alert" className="alert"><Icon name="alert" />{children}</p>;
const Loading = ({ what }: { what: string }) => <p className="state" aria-busy="true">Reading {what}…</p>;
const Empty = ({ icon, children }: { icon: IconName; children: React.ReactNode }) =>
  <div className="state empty"><span className="state-ic"><Icon name={icon} /></span><div>{children}</div></div>;

const SCOPE_ICONS = ["run", "git", "http", "db", "aws"];
const Scopes = ({ scopes }: { scopes: readonly string[] }) => (
  <ul className="scopes" aria-label={scopes.length ? `Scopes granted: ${scopes.join(", ")}` : "No scopes granted"}>
    {scopes.map((s) => (
      <li key={s} className="scope">{SCOPE_ICONS.includes(s) && <Icon name={s as IconName} />}{s}</li>
    ))}
  </ul>
);

const Head = ({ id, title, sub, children }: { id: string; title: string; sub?: React.ReactNode; children?: React.ReactNode }) => (
  <div className="screen-head">
    <div>
      <h1 id={id}>{title}</h1>
      {sub && <p className="lede">{sub}</p>}
    </div>
    {children}
  </div>
);

export function Overview({ st, act, go }: ScreenProps) {
  // A wider window than the rows shown, so ended rows can find their REVOKE time.
  const ev = useLoad(() => api.auditList(40), [st]);
  const ver = useLoad(api.auditVerify, []);
  const cp = useCpCounts();
  const [striking, setStriking] = useState<string | null>(null);
  const now = nowSecs();
  const live = (st?.leases.filter((l) => l.state === "active") ?? []).sort((a, b) => a.expires_at - b.expires_at);
  const ended = st?.leases.filter((l) => l.state !== "active") ?? [];
  const events = [...(ev.data ?? [])].reverse().slice(0, 10);
  const leaseOf = (id: string | null) => st?.leases.find((l) => l.id === id);
  const revokeOne = async (id: string) => {
    if (!reducedMotion()) {
      setStriking(id);
      await new Promise((r) => setTimeout(r, STRIKE_MS));
    }
    await act(() => api.revoke(id), (n) => `Revoked ${plural(n, "session")}`);
    setStriking(null);
  };
  return (
    <section className="overview" aria-labelledby="h-overview">
      <h1 id="h-overview" className="sr-only">Overview</h1>

      <div className="sec-h">
        <h2>Sessions</h2>
        {st && <span className="n">{live.length} active{ended.length > 0 && ` · ${ended.length} ended`}</span>}
      </div>
      {!st ? <Loading what="sessions" /> : (
        <Timeline live={live} ended={ended} events={ev.data ?? []} now={now} locked={st.locked} striking={striking} onRevoke={revokeOne} />
      )}

      {cp && (
        <section aria-label="Control plane counts">
          <div className="sec-h spaced"><h2>Control plane</h2></div>
          <p className="quiet-state" data-testid="cp-counts">
            Projects: <b data-testid="count-projects">{cp.projects ?? "n/a"}</b> · Agents: <b data-testid="count-agents">{cp.agents ?? "n/a"}</b>
          </p>
        </section>
      )}

      <div className="sec-h spaced">
        <h2 id="h-events">Activity</h2>
        <button type="button" className="link" onClick={() => go("Audit")}>Open audit</button>
      </div>
      {ev.alert}
      {!ev.data && !ev.err ? <Loading what="the ledger" /> : events.length === 0 ? (
        <p className="quiet-state">Nothing in the ledger yet.</p>
      ) : (
        <ol className="log" aria-labelledby="h-events">
          {events.map((e) => {
            const k = kind(e);
            const who = leaseOf(e.session_id);
            const target = e.target ?? "";
            return (
              <li key={e.seq} data-kind={k}>
                <time className="mono" dateTime={new Date(e.ts * 1000).toISOString()} title={stamp(e.ts)}>{clockS(e.ts)}</time>
                <span className="mk" aria-hidden="true" />
                <span className="what">{label(e.action)}</span>
                <span className="mono tgt" title={target}>{target}</span>
                <span className="who-s" title={e.session_id ?? e.actor_exe}>
                  {who ? <>{agent(who.command)} <span className="mono">{e.session_id}</span></> : e.session_id ? <span className="mono">{e.session_id}</span> : e.actor_exe.split("/").pop()}
                </span>
              </li>
            );
          })}
        </ol>
      )}
      {ver.data && (ver.data.broken_at === null
        ? <p className="log-foot"><Icon name="shield" />Ledger chain verified · {ver.data.events.toLocaleString("en-US")} entries</p>
        : <p className="log-foot bad"><Icon name="broken" />Ledger BROKEN at seq {ver.data.broken_at}</p>)}
    </section>
  );
}

/** Round clock steps for the lease axis, in seconds. */
const STEPS = [300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];

interface TimelineProps {
  live: LeaseInfo[]; ended: LeaseInfo[]; events: AuditEvent[]; now: number; locked: boolean;
  striking: string | null; onRevoke: (id: string) => void;
}

/** Every live lease on one axis from now to the latest expiry, so who holds access and until when reads at a glance. */
function Timeline({ live, ended, events, now, locked, striking, onRevoke }: TimelineProps) {
  const span = Math.max(1800, ...live.map((l) => l.expires_at - now)) * 1.06;
  const step = STEPS.find((s) => span / s <= 5) ?? 86400;
  // shortcut: ticks align to UTC multiples of the step, so half-hour time zones see :30 labels on hourly steps; fine for a glance axis.
  const ticks: number[] = [];
  // Ticks too close to "now" or the right edge would collide with its label, so they are left out.
  for (let t = Math.ceil((now + 1) / step) * step; t < now + span; t += step) if ((t - now) / span > 0.12 && (t - now) / span < 0.95) ticks.push(t);
  const x = (t: number) => `${(Math.max(0, t - now) / span) * 100}%`;
  const grid = ticks.map((t) => <i key={t} className="tick" style={{ left: x(t) }} />);
  const revokedAt = (id: string) => events.find((e) => e.action === "REVOKE" && e.target === id)?.ts;
  const endedLabel = (l: LeaseInfo) => {
    if (l.state === "expired") return `expired ${clock(l.expires_at)}`;
    const t = l.state === "revoked" ? revokedAt(l.id) : undefined;
    return t ? `revoked ${clock(t)}` : l.state;
  };
  return (
    <div className="tl-list" role="list" aria-label="Sessions">
      {live.length > 0 && <div className="tl-row tl-axis" aria-hidden="true">
        <span>Agent</span><span>Scopes</span>
        <span className="tl">
          <b className="tick-l now" style={{ left: 0 }}>now</b>
          {grid}{ticks.map((t) => <b key={t} className="tick-l mono" style={{ left: x(t) }}>{clock(t)}</b>)}
        </span>
        <span className="r">Left</span><span />
      </div>}
      {live.length === 0 && (
        <div className="tl-row tl-empty" role="listitem">
          {locked
            ? <p>No sessions. The vault is locked, so no agent can start one until you unlock it.</p>
            : <p><b>No active sessions.</b> Agents get access only inside a session you start from a terminal: <code>smith session start -- &lt;agent&gt;</code></p>}
        </div>
      )}
      {live.map((l) => {
        const rest = l.expires_at - now;
        const soon = rest < SOON_S;
        const name = agent(l.command);
        return (
          <div key={l.id} role="listitem" className="tl-row" data-soon={soon || undefined} data-striking={striking === l.id || undefined}
            aria-label={`${name} session ${l.id}`}>
            <Who l={l} />
            <ScopeText scopes={l.scopes} />
            <span className="tl" aria-hidden="true">{grid}<span className="bar" style={{ width: x(l.expires_at) }} /></span>
            <span className="r mono left" title={`Expires ${clock(l.expires_at)}`}>
              {left(rest)}<span className="sr-only"> left, expires {clock(l.expires_at)}</span>
            </span>
            <button type="button" className="btn sm quiet danger-text reveal" aria-label={`Revoke ${name} session ${l.id}`} disabled={striking !== null}
              onClick={() => onRevoke(l.id)}>Revoke</button>
          </div>
        );
      })}
      {ended.length > 0 && <div className="tl-div" role="presentation"><span>Recently ended</span></div>}
      {ended.map((l) => (
        <div key={l.id} role="listitem" className="tl-row ended" data-state={l.state} aria-label={`${agent(l.command)} session ${l.id}, ${endedLabel(l)}`}>
          <Who l={l} struck />
          <ScopeText scopes={l.scopes} />
          <span className="tl mono end">{endedLabel(l)}</span>
          <span /><span />
        </div>
      ))}
    </div>
  );
}

const Who = ({ l, struck }: { l: LeaseInfo; struck?: boolean }) => {
  const name = agent(l.command);
  return (
    <span className="who" title={l.command}>
      <span className="who-1"><SourceMark kind={l.source.kind} />{struck ? <s className="who-name">{name}</s> : <b className="who-name">{name}</b>}<span className="mono id">{l.id}</span></span>
      <span className="who-2">{l.project} / <span className={l.env === "production" ? "prod" : undefined}>{l.env}</span></span>
      {(l.report?.model ?? l.report?.agent) || l.started_by === "agent" ? <span className="who-2 who-3"><span className="src-lbl">{l.source.label} ·</span> <ReportedModel l={l} /></span> : null}
    </span>
  );
};

const ScopeText = ({ scopes }: { scopes: readonly string[] }) => (
  <ul className="scopes-t mono" aria-label={scopes.length ? `Scopes granted: ${scopes.join(", ")}` : "No scopes granted"}>
    {scopes.map((s) => <li key={s}>{s}</li>)}
  </ul>
);

const SOURCE_GLYPH: Record<SourceKind, IconName> = {
  claude_code_cli: "s_terminal", codex: "s_terminal", gemini_cli: "s_terminal", aider: "s_terminal", opencode: "s_terminal", grok: "s_terminal",
  claude_desktop_app: "s_window",
  cursor: "s_code", windsurf: "s_code", vscode: "s_code", jetbrains: "s_code", copilot: "s_code",
  other: "s_spark", unknown: "s_unknown",
};
const isClaude = (k: SourceKind) => k === "claude_code_cli" || k === "claude_desktop_app";
/** Source glyph; the two Claude kinds get the Claude mark, labelled so it is findable and announced. */
const SourceMark = ({ kind }: { kind: SourceKind }) => isClaude(kind)
  ? <span className="src-claude" role="img" aria-label="Claude" title="Claude"><Icon name="s_claude" /></span>
  : <Icon name={SOURCE_GLYPH[kind] ?? "s_unknown"} />;
/** The agent's own model claim with its 'unverified' tooltip; nothing for a human-started session that reported none. */
const ReportedModel = ({ l }: { l: LeaseInfo }) => {
  const claim = l.report?.model ?? l.report?.agent;
  const text = claim ? `${claim} (reported by agent)` : l.started_by === "agent" ? "model not reported" : null;
  return text && <span className={claim ? "reported" : "muted"} title={`${text}. ${SELF_REPORTED}`}>{text}</span>;
};
const SELF_REPORTED = "Self-reported by the agent and unverified. Locksmith never uses it to decide anything.";
const useNow = () => {
  const [n, setN] = useState(nowSecs);
  useEffect(() => { const t = setInterval(() => setN(nowSecs()), 1000); return () => clearInterval(t); }, []);
  return n;
};

export function Sessions({ st, act }: ScreenProps) {
  const now = useNow();
  const [open, setOpen] = useState<string | null>(null);
  const all = st?.leases ?? [];
  const live = all.filter((l) => l.state === "active").sort((a, b) => a.expires_at - b.expires_at);
  const ended = all.filter((l) => l.state !== "active").sort((a, b) => b.expires_at - a.expires_at);
  const row = (l: LeaseInfo) => {
    const active = l.state === "active";
    const r = l.report;
    const rest = l.expires_at - now;
    const name = l.source.label;
    return (
      <li key={l.id} className="sess" data-state={l.state} data-open={open === l.id || undefined}>
        <div className="sess-main">
          <button type="button" className="sess-toggle" aria-expanded={open === l.id} aria-label={`${name} session ${l.id}`}
            onClick={() => setOpen(open === l.id ? null : l.id)}>
            <span className="av" data-kind={l.source.kind}><SourceMark kind={l.source.kind} /></span>
            <span className="who">
              <span className="who-1">
                <b className="who-name">{name}</b>
                {l.host && <span className="muted"> in {l.host}</span>}
                <span className="badge" data-by={l.started_by}>{l.started_by === "agent" ? "Agent started" : "Human started"}</span>
              </span>
              <span className="who-2">
                {l.project} / <span className={l.env === "production" ? "prod" : undefined}>{l.env}</span>
                {(l.report?.model ?? l.report?.agent) || l.started_by === "agent" ? <> · <ReportedModel l={l} /></> : null}
              </span>
            </span>
          </button>
          <Scopes scopes={l.scopes} />
          <span className="r mono left">
            {active ? <>{left(rest)}<span className="sr-only"> left, expires {clock(l.expires_at)}</span></> : l.state}
          </span>
          {active
            ? <button type="button" className="btn sm quiet danger-text" aria-label={`Revoke ${name} session ${l.id}`}
                onClick={() => act(() => api.revoke(l.id), (n) => `Revoked ${plural(n, "session")}`)}>Revoke</button>
            : <span />}
        </div>
        {open === l.id && (
          <dl className="sess-det">
            <dt>Session</dt><dd className="mono">{l.id}</dd>
            <dt>Command</dt><dd className="mono">{l.command}</dd>
            <dt>Root</dt><dd className="mono">{l.root_exe || "unknown"} · pid {l.root_pid}</dd>
            <dt>Created</dt><dd className="mono">{stamp(l.created_at)}</dd>
            <dt>{active ? "Expires" : "Expired or ended"}</dt><dd className="mono">{stamp(l.expires_at)}</dd>
            {l.inject && <><dt>Keys</dt><dd>{l.inject.length ? `${l.inject.join(", ")} (${l.inject.length} injectable)` : "none injectable"}; every other key is relay-only</dd></>}
            {r && (r.agent || r.model) && <><dt>Reported</dt><dd title={SELF_REPORTED}>{[r.agent, r.model].filter(Boolean).join(" · ")} (reported by agent, unverified)</dd></>}
          </dl>
        )}
      </li>
    );
  };
  return (
    <section className="screen" aria-labelledby="h-sessions">
      <Head id="h-sessions" title="Sessions" sub="Every agent that has been given access, who started it and when it runs out." />
      {!st ? <Loading what="sessions" /> : all.length === 0 ? (
        <Empty icon="sessions">
          {st.locked
            ? <><b>No sessions.</b> The vault is locked, so no agent can start one until you unlock it.</>
            : <><b>No sessions yet.</b> Agents get access only inside a session: start one with <code>smith session start -- &lt;agent&gt;</code></>}
        </Empty>
      ) : (
        <>
          {live.length > 0 && <ul className="sess-list" aria-label="Active sessions">{live.map(row)}</ul>}
          {ended.length > 0 && (
            <>
              <div className="sec-h spaced"><h2>Recently ended</h2></div>
              <ul className="sess-list" aria-label="Ended sessions">{ended.map(row)}</ul>
            </>
          )}
          <p className="log-foot">Source and host are hints read from process names and paths. Any process running as you can imitate them.</p>
        </>
      )}
    </section>
  );
}

const uniq = (xs: string[]) => [...new Set(xs)];

export function Keys({ st }: ScreenProps) {
  const tokens = useLoad(api.tokenList, []);
  const live = st?.leases.filter((l) => l.state === "active") ?? [];
  const seen = [...(st?.leases ?? []), ...(tokens.data ?? [])];
  // Until the user picks, follow the first live session's project and environment.
  const [pickedProject, setProject] = useState<string | null>(null);
  const [pickedEnv, setEnv] = useState<string | null>(null);
  const project = pickedProject ?? live[0]?.project ?? "default";
  const env = pickedEnv ?? live[0]?.env ?? "development";
  const users = live.filter((l) => l.project === project && l.env === env && l.scopes.includes("run"));
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const names = useLoad(() => api.keyNames(project, env), [project, env]);
  const put = async (key: string) => {
    setErr("");
    setNote("");
    try {
      const r = await api.putSecretSecure(project, env, key);
      setNote(r === "submitted" ? `Key ${key} saved.` : `Key ${key}: cancelled, nothing changed.`);
      if (key === name.trim()) setName("");
    } catch (x) { setErr(msg(x)); }
    await names.load();
  };
  const submit = (e: React.FormEvent) => { e.preventDefault(); void put(name.trim()); };
  return (
    <section className="screen" aria-labelledby="h-keys">
      <Head id="h-keys" title="Keys" sub="Key names only. Values go in and out through a native Locksmith prompt, never this window." />
      <div className="toolbar">
        <label className="field">Project<input list="dl-projects" value={project} onChange={(e) => setProject(e.target.value)} spellCheck={false} /></label>
        <label className="field">Environment<input list="dl-envs" value={env} onChange={(e) => setEnv(e.target.value)} spellCheck={false} /></label>
        <datalist id="dl-projects">{uniq(seen.map((x) => x.project)).map((v) => <option key={v} value={v} />)}</datalist>
        <datalist id="dl-envs">{uniq(seen.map((x) => x.env)).map((v) => <option key={v} value={v} />)}</datalist>
        {users.length > 0 && (
          <p className="usable">
            <span className="live-dot" aria-hidden="true" />
            <span>Usable now by {users.map((l, i) => <Fragment key={l.id}>{i > 0 && ", "}<span className="mono">{l.id}</span> ({agent(l.command)})</Fragment>)}
              <span className="muted"> · sessions on {project} / {env} with <code>run</code> scope</span></span>
          </p>
        )}
      </div>
      {names.alert}
      {err && <Alert>{err}</Alert>}
      {!names.data && !names.err ? <Loading what="key names" /> : names.data?.length === 0 ? (
        <Empty icon="key">No keys in {project} / {env} yet. Add the first one below.</Empty>
      ) : names.data && (
        <ul className="list keys" aria-label={`Key names in ${project} / ${env}`}>
          {names.data.map((n) => (
            <li key={n} className="row">
              <span className="ic"><Icon name="key" /></span>
              <span className="mono strong">{n}</span>
              <button type="button" className="btn sm" aria-label={`Rotate ${n}`} onClick={() => put(n)}><Icon name="rotate" />Rotate</button>
            </li>
          ))}
        </ul>
      )}

      <form className="panel add" onSubmit={submit} aria-labelledby="h-add">
        <div>
          <h2 id="h-add">Add or rotate a key</h2>
          <p className="muted small">The value is typed into a native Locksmith prompt, never into this window.</p>
        </div>
        <label className="field">Key name<input value={name} onChange={(e) => setName(e.target.value)} spellCheck={false} placeholder="e.g. NPM_TOKEN" /></label>
        <button type="submit" className="btn primary" disabled={!name.trim()}><Icon name="plus" />Add or rotate key</button>
      </form>
      <p aria-live="polite" className="done">{note}</p>
    </section>
  );
}

export function Tokens({ st }: ScreenProps) {
  const t = useLoad(api.tokenList, []);
  const [err, setErr] = useState("");
  const scopes = (lease: string) => st?.leases.find((l) => l.id === lease && l.state === "active")?.scopes;
  const revokeToken = async (x: HttpTokenInfo) => {
    setErr("");
    try { await api.tokenRevoke(x.prefix); } catch (e) { setErr(msg(e)); }
    await t.load();
  };
  return (
    <section className="screen" aria-labelledby="h-tokens">
      <Head id="h-tokens" title="Tokens" sub={<>Opaque <code>lsk_</code> tokens stand in for a key on one host. Only the prefix is shown.</>} />
      {t.alert}
      {err && <Alert>{err}</Alert>}
      {!t.data && !t.err ? <Loading what="tokens" /> : t.data?.length === 0 ? (
        <Empty icon="token">
          <b>No live tokens.</b> Inside a session, mint one with
          <code className="block">smith token issue &lt;KEY&gt; --provider &lt;name&gt;</code>
        </Empty>
      ) : t.data && (
        <div className="sessions">
          {t.data.map((x) => {
            const sc = scopes(x.lease);
            return (
              <article key={x.prefix} className="card token" aria-label={`Token ${x.prefix}`}>
                <span className="av av2" aria-hidden="true"><Icon name="token" /></span>
                <div className="who">
                  <b className="mono">{x.prefix}</b>
                  <span className="mono" title={x.key}>{x.key}</span>
                </div>
                <div className="who">
                  <b className="hosts">{x.hosts.map((h) => <span key={h} className="mono">{h}</span>)}</b>
                  <span><span className="mono">{x.placement}</span> · {stamp(x.created_at).slice(5, 16)}</span>
                </div>
                <div className="who">
                  {sc ? <Scopes scopes={sc} /> : <b className="muted">Session ended</b>}
                  <span title={`${x.project} / ${x.env} · ${x.lease}`}>{x.project} / {x.env} · <span className="mono">{x.lease}</span></span>
                </div>
                <button type="button" className="btn sm danger-text" aria-label={`Revoke token ${x.prefix}`} onClick={() => revokeToken(x)}>Revoke</button>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

// Only commands that exist in crates/smith-cli (git_cmd.rs, http_cmd.rs, run_cmd.rs, db_cmd.rs).
const RELAYS: { key: keyof Pick<RelayInfo, "git_port" | "http_port" | "aws_port"> | null; name: string; icon: IconName; setup: string[] }[] = [
  { key: "git_port", name: "Git forwarder", icon: "git", setup: ["smith git setup"] },
  { key: "http_port", name: "HTTP relay", icon: "http", setup: ["smith token issue <KEY> --provider <name>", "smith http status"] },
  { key: "aws_port", name: "AWS SigV4 relay", icon: "aws", setup: ["smith run --aws <profile> -- <command>"] },
  { key: null, name: "Database relay", icon: "db", setup: ["smith db connect <name> -- <command>"] },
];

export function Relays(_: ScreenProps) {
  const r = useLoad(api.relayInfo, []);
  const info = r.data;
  return (
    <section className="screen" aria-labelledby="h-relays">
      <Head id="h-relays" title="Relays" sub="Each relay signs or forwards requests on an agent's behalf; the key stays in Locksmith." />
      {r.alert}
      {!info && !r.err ? <Loading what="relays" /> : info && (
        <>
          <div className="relays">
            {RELAYS.map((x) => {
              const port = x.key && info[x.key];
              const up = !x.key || port != null;
              return (
                <article key={x.name} className="card relay" aria-labelledby={`relay-${x.icon}`}>
                  <div className="relay-h">
                    <span className="av av3" aria-hidden="true"><Icon name={x.icon} /></span>
                    <h2 id={`relay-${x.icon}`}>{x.name}</h2>
                    <span className="pill" data-up={up}>
                      {!x.key ? "Per target" : port == null ? "Not running" : <>Port <span className="mono">{port}</span></>}
                    </span>
                  </div>
                  <div className="cmds">{x.setup.map((c) => <code key={c} className="block">{c}</code>)}</div>
                </article>
              );
            })}
          </div>
          <div className="sec-h spaced"><h2>Explicit-proxy CA hosts</h2><span className="n">{info.ca_hosts.length}</span></div>
          {info.ca_hosts.length === 0 ? <Empty icon="shield">No hosts use the Locksmith CA.</Empty> : (
            <ul className="chips">{info.ca_hosts.map((h) => <li key={h} className="scope"><Icon name="http" />{h}</li>)}</ul>
          )}
        </>
      )}
    </section>
  );
}

export function Audit(_: ScreenProps) {
  const ev = useLoad(() => api.auditList(200), []);
  const [filter, setFilter] = useState("");
  const [ver, setVer] = useState<AuditVerifyView | null>(null);
  const [err, setErr] = useState("");
  const q = filter.trim().toLowerCase();
  const rows = [...(ev.data ?? [])].reverse().filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q));
  const verify = async () => {
    setErr("");
    try { setVer(await api.auditVerify()); } catch (e) { setErr(msg(e)); }
  };
  return (
    <section className="screen" aria-labelledby="h-audit">
      <Head id="h-audit" title="Audit" sub="Every access, block and change, newest first, in a hash-chained ledger.">
        <label className="search"><Icon name="search" /><span className="sr-only">Filter</span>
          <input type="search" value={filter} onChange={(e) => setFilter(e.target.value)} spellCheck={false} placeholder="Filter by action, key, host or session" />
        </label>
        <button type="button" className="btn" onClick={verify}><Icon name="shield" />Verify ledger</button>
      </Head>
      <div aria-live="assertive">
        {ver && (ver.broken_at === null
          ? <p className="verdict ok"><Icon name="shield" />Ledger intact: {ver.events} events checked, hash chain unbroken.</p>
          : <p className="verdict broken"><Icon name="broken" />Ledger BROKEN at seq {ver.broken_at}. {ver.detail}</p>)}
      </div>
      {ev.alert}
      {err && <Alert>{err}</Alert>}
      {!ev.data && !ev.err ? <Loading what="the ledger" /> : rows.length === 0 ? (
        <Empty icon="doc">{q ? "No events match this filter." : "Nothing in the ledger yet."}</Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <caption className="sr-only">Audit events, newest first</caption>
            <thead><tr><th className="num">Seq</th><th>Time</th><th>Action</th><th>Decision</th><th>Target</th><th>Rule</th><th>Session</th><th>Actor</th></tr></thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.seq} data-bad={isBad(e)}>
                  <td className="num mono muted">{e.seq}</td>
                  <td className="mono nowrap">{stamp(e.ts)}</td>
                  <td className="strong">{e.action}</td>
                  <td><span className="dec">{e.decision}</span></td>
                  <td className="mono wrap">{breakable(e.target ?? "")}</td>
                  <td className="mono">{e.policy_rule}</td>
                  <td className="mono">{e.session_id ?? ""}</td>
                  <td className="mono" title={e.actor_exe}>{e.actor_exe.split("/").pop()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Agents and their grants, from the control plane. Create shows the enrollment secret once. */
export function Agents(_: ScreenProps) {
  const [cfg, setCfg] = useState({ url: api.controlPlane.url(), org: api.controlPlane.org() });
  const [client, setClient] = useState(api.agentsClient);
  const [agents, setAgents] = useState<api.Agent[] | null>(null);
  const [grants, setGrants] = useState<Record<string, api.AgentGrant[]>>({});
  const [err, setErr] = useState("");
  // Component state only: never stored or logged, gone when dismissed.
  const [secret, setSecret] = useState<{ agent: string; value: string } | null>(null);
  const [name, setName] = useState("");
  const [secretId, setSecretId] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    if (!client) return;
    try {
      const list = await client.listAgents();
      const g = await Promise.all(list.map((a) => client.listGrants(a.id)));
      setAgents(list);
      setGrants(Object.fromEntries(list.map((a, i) => [a.id, g[i]!])));
    } catch (e) { setErr(msg(e)); }
  }, [client]);
  useEffect(() => { void load(); }, [load]);

  const run = async (f: () => Promise<void>) => {
    setErr("");
    try { await f(); } catch (e) { setErr(msg(e)); }
    await load();
  };

  return (
    <section className="screen" aria-labelledby="h-agents">
      <Head id="h-agents" title="Agents" sub="Agents use secrets through the gateway without ever holding them. Grants say which secrets an agent may relay." />
      <form className="card" aria-label="Control plane" onSubmit={(e) => {
        e.preventDefault();
        api.controlPlane.save(cfg.url, cfg.org);
        setAgents(null);
        setClient(api.agentsClient());
      }}>
        <input aria-label="Control plane URL" value={cfg.url} onChange={(e) => setCfg({ ...cfg, url: e.target.value.trim() })} />
        <input aria-label="Org id" value={cfg.org} onChange={(e) => setCfg({ ...cfg, org: e.target.value.trim() })} />
        <button type="submit" className="btn sm">Connect</button>
      </form>
      {err && <Alert>{err}</Alert>}
      {!client ? <Empty icon="key">Enter an org id to list agents.</Empty> : (
        <>
          {secret && (
            <div className="card" role="region" aria-label="Enrollment secret">
              <p>Enrollment secret for {secret.agent}. It is shown once and cannot be retrieved again.</p>
              <code className="block" data-testid="enrollment-secret">{secret.value}</code>
              <button type="button" className="btn sm" onClick={() => setSecret(null)}>Dismiss</button>
            </div>
          )}
          <form className="card" aria-label="Create agent" onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              const r = await client.createAgent({ name, description: "" });
              setSecret({ agent: r.agent.name, value: r.enrollment_secret });
              setName("");
            });
          }}>
            <input aria-label="Agent name" required value={name} onChange={(e) => setName(e.target.value)} />
            <button type="submit" className="btn primary sm">Create agent</button>
          </form>
          {!agents ? <Loading what="agents" /> : agents.length === 0 ? <Empty icon="key"><b>No agents yet.</b></Empty> : (
            <div className="sessions">
              {agents.map((a) => (
                <article key={a.id} className="card" aria-label={`Agent ${a.name}`}>
                  <div className="who"><b>{a.name}</b><span className="mono">{a.id}</span></div>
                  <ul>
                    {(grants[a.id] ?? []).map((g) => (
                      <li key={g.id}>
                        <span className="mono">{g.secret_name}</span> ({g.mode}) {g.expires_at ? `expires ${g.expires_at}` : "no expiry"}
                        <button type="button" className="btn sm danger-text" aria-label={`Revoke ${g.secret_name} for ${a.name}`}
                          onClick={() => void run(() => client.revokeGrant(a.id, g.id))}>Revoke</button>
                      </li>
                    ))}
                  </ul>
                  <form onSubmit={(e) => {
                    e.preventDefault();
                    void run(async () => {
                      await client.createGrant(a.id, { secret_id: secretId[a.id] ?? "", mode: "relay", expires_at: null });
                      setSecretId({ ...secretId, [a.id]: "" });
                    });
                  }}>
                    <input aria-label={`Secret id for ${a.name}`} required value={secretId[a.id] ?? ""}
                      onChange={(e) => setSecretId({ ...secretId, [a.id]: e.target.value.trim() })} />
                    <button type="submit" className="btn sm">Grant</button>
                  </form>
                  <button type="button" className="btn sm danger-text" aria-label={`Delete ${a.name}`}
                    onClick={() => void run(() => client.deleteAgent(a.id))}>Delete agent</button>
                </article>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}

/** The org's control-plane audit ledger (events plus chain status), read-only. */

export function OrgAudit(_: ScreenProps) {
  const client = api.agentsClient();
  const [status, setStatus] = useState<api.AuditStatus | null>(null);
  const [events, setEvents] = useState<api.OrgAuditEvent[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const inflight = useRef(false);
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState<AuditOutcomeFilter>("all");

  useEffect(() => {
    if (!client) return;
    client.auditStatus().then(setStatus, (e) => setErr(msg(e)));
    client.listAuditEvents().then((p) => { setEvents(p.items); setNext(p.next ?? null); }, (e) => setErr(msg(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const more = () => {
    if (!client || inflight.current || !next) return;
    inflight.current = true;
    setLoadingMore(true);
    client.listAuditEvents({ cursor: next }).then(
      (p) => { setEvents((cur) => [...(cur ?? []), ...p.items]); setNext(p.next ?? null); setErr(""); },
      (e) => setErr(msg(e)),
    ).finally(() => { inflight.current = false; setLoadingMore(false); });
  };
  const v = status?.latest_verify;

  return (
    <section className="screen" aria-labelledby="h-org-audit">
      <Head id="h-org-audit" title="Org audit" sub="The control plane's hash-chained ledger of relays and changes, newest first." />
      {err && <Alert>{err}</Alert>}
      {!client ? <Empty icon="doc">Connect a control plane on the Agents screen to see its audit ledger.</Empty> : (
        <>
          {status && (
            <div className="card" role="region" aria-label="Chain status">
              <p>Head seq {status.head_seq}. Latest checkpoint: {status.latest_checkpoint ? `seq ${status.latest_checkpoint.seq} at ${status.latest_checkpoint.at}` : "none yet"}.</p>
              <p data-testid="verify-result">
                {!v ? "Not verified yet." : v.ok ? `Verified OK at ${v.finished_at}.` : `Verification FAILED at ${v.finished_at}${v.broken_seq != null ? `, first broken seq ${v.broken_seq}` : ""}.`}
              </p>
            </div>
          )}
          <label>
            Outcome{" "}
            <select aria-label="Outcome filter" value={filter} onChange={(e) => setFilter(e.target.value as AuditOutcomeFilter)}>
              <option value="all">All</option>
              <option value="denied">Denied</option>
              <option value="redaction_failed">Redaction failed</option>
            </select>
          </label>
          {!events ? <Loading what="the org ledger" /> : events.length === 0 ? <Empty icon="doc">Nothing in the ledger yet.</Empty> : !events.some((e) => auditOutcomeMatches(e, filter)) ? <Empty icon="doc">No matching events{next ? " loaded yet" : ""}.</Empty> : (
            <div className="table-wrap">
              <table className="grid">
                <caption className="sr-only">Org audit events, newest first</caption>
                <thead><tr><th className="num">Seq</th><th>Time</th><th>Kind</th><th>Actor</th><th>Target</th><th>Outcome</th></tr></thead>
                <tbody>
                  {events.filter((e) => auditOutcomeMatches(e, filter)).map((e) => (
                    <tr key={e.id}>
                      <td className="num mono muted">{e.seq}</td><td className="mono nowrap">{e.at}</td><td className="strong">{e.kind}</td>
                      <td className="mono">{e.actor}</td><td className="mono wrap">{breakable(e.target ?? "")}</td><td>{e.outcome}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {next && <button type="button" className="btn sm" disabled={loadingMore} onClick={more}>Load more</button>}
        </>
      )}
    </section>
  );
}

/** Control-plane counts for the Overview, best effort: a failed count shows "n/a", never an error. */
function useCpCounts() {
  const [c, setC] = useState<{ projects?: number; agents?: number } | null>(null);
  useEffect(() => {
    const client = api.agentsClient();
    if (!client) return;
    let live = true;
    void Promise.allSettled([(async () => (await client.listProjects()).length)(), (async () => (await client.listAgents()).length)()])
      .then(([p, a]) => { if (live) setC({ projects: p.status === "fulfilled" ? p.value : undefined, agents: a.status === "fulfilled" ? a.value : undefined }); });
    return () => { live = false; };
  }, []);
  return c;
}

/** Control-plane errors in words: 403 and 409 say what to do, anything else shows its message. */
const cpErr = (e: unknown) =>
  e instanceof ApiError && e.status === 403 ? "Not allowed: your role cannot do this in this org."
  : e instanceof ApiError && e.status === 409 ? `Conflict: ${e.message || "that name is already taken, or the item still has contents"}.`
  : msg(e);

const NoClient = ({ what }: { what: string }) => <Empty icon="key">Connect a control plane on the Agents screen to see {what}.</Empty>;

/** Row actions shared by projects and environments: rename, and delete with a confirm step. */
function RowActions({ name, onRename, onDelete }: { name: string; onRename: (n: string) => Promise<unknown>; onDelete: () => Promise<unknown> }) {
  const [mode, setMode] = useState<"" | "edit" | "confirm">("");
  const [value, setValue] = useState(name);
  if (mode === "edit") {
    return (
      <form onSubmit={(e) => { e.preventDefault(); void onRename(value).then(() => setMode(""), () => {}); }}>
        <input aria-label={`New name for ${name}`} required value={value} onChange={(e) => setValue(e.target.value)} />
        <button type="submit" className="btn sm">Save</button>
        <button type="button" className="btn sm quiet" onClick={() => setMode("")}>Cancel</button>
      </form>
    );
  }
  if (mode === "confirm") {
    return (
      <span role="alertdialog" aria-label={`Delete ${name}?`}>
        Delete {name}?{" "}
        <button type="button" className="btn sm danger-text" onClick={() => void onDelete().then(() => setMode(""), () => setMode(""))}>Confirm delete</button>
        <button type="button" className="btn sm quiet" onClick={() => setMode("")}>Cancel</button>
      </span>
    );
  }
  return (
    <>
      <button type="button" className="btn sm" onClick={() => setMode("edit")}>Rename {name}</button>
      <button type="button" className="btn sm danger-text" onClick={() => setMode("confirm")}>Delete {name}</button>
    </>
  );
}

function CreateForm({ label, onCreate }: { label: string; onCreate: (name: string) => Promise<unknown> }) {
  const [name, setName] = useState("");
  return (
    <form className="card" aria-label={`Create ${label}`} onSubmit={(e) => { e.preventDefault(); void onCreate(name).then(() => setName(""), () => {}); }}>
      <input aria-label={`${label} name`} required value={name} onChange={(e) => setName(e.target.value)} />
      <button type="submit" className="btn primary sm">Create {label}</button>
    </form>
  );
}

/** Loads a control-plane list, reloads after each mutation, and keeps the error from the last failure. */
function useCpList<T>(fn: () => Promise<T[]>, deps: unknown[]) {
  const [items, setItems] = useState<T[] | null>(null);
  const [err, setErr] = useState("");
  const load = useCallback(async () => {
    try { setItems(await fn()); } catch (e) { setErr(cpErr(e)); setItems((cur) => cur ?? []); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { setItems(null); void load(); }, [load]);
  /** Runs a mutation; a rejection is shown and rethrown-free so forms keep their input. */
  const run = async (f: () => Promise<unknown>) => {
    setErr("");
    try { await f(); } catch (e) { setErr(cpErr(e)); throw e; }
    await load();
  };
  return { items, err, run };
}

/** Projects, and the environments of the selected project, from the control plane. */
export function Projects(_: ScreenProps) {
  const client = api.agentsClient();
  if (!client) return <section className="screen" aria-labelledby="h-projects"><Head id="h-projects" title="Projects" /><NoClient what="projects" /></section>;
  return <ProjectsView client={client} />;
}

function ProjectsView({ client }: { client: Client }) {
  const [sel, setSel] = useState<Project | null>(null);
  const ps = useCpList(() => client.listProjects(), [client]);
  const es = useCpList<Environment>(() => (sel ? client.listEnvironments(sel.id) : Promise.resolve([])), [client, sel?.id]);
  return (
    <section className="screen" aria-labelledby="h-projects">
      <Head id="h-projects" title="Projects" sub="Projects hold environments, and environments hold secrets." />
      {ps.err && <Alert>{ps.err}</Alert>}
      <CreateForm label="project" onCreate={(n) => ps.run(() => client.createProject({ name: n }))} />
      {!ps.items ? <Loading what="projects" /> : ps.items.length === 0 ? <Empty icon="key"><b>No projects yet.</b></Empty> : (
        <ul>
          {ps.items.map((p) => (
            <li key={p.id}>
              <button type="button" className="link" aria-pressed={sel?.id === p.id} onClick={() => setSel(p)}>{p.name}</button>
              <RowActions name={p.name}
                onRename={(name) => ps.run(() => client.updateProject(p.id, { name }))}
                onDelete={() => ps.run(async () => { await client.deleteProject(p.id); if (sel?.id === p.id) setSel(null); })} />
            </li>
          ))}
        </ul>
      )}
      {sel && (
        <section aria-label={`Environments of ${sel.name}`}>
          <div className="sec-h spaced"><h2>Environments of {sel.name}</h2></div>
          {es.err && <Alert>{es.err}</Alert>}
          <CreateForm label="environment" onCreate={(n) => es.run(() => client.createEnvironment(sel.id, { name: n }))} />
          {!es.items ? <Loading what="environments" /> : es.items.length === 0 ? <Empty icon="key"><b>No environments yet.</b></Empty> : (
            <ul>
              {es.items.map((e) => (
                <li key={e.id}>
                  {e.name}
                  <RowActions name={e.name}
                    onRename={(name) => es.run(() => client.updateEnvironment(sel.id, e.id, { name }))}
                    onDelete={() => es.run(() => client.deleteEnvironment(sel.id, e.id))} />
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </section>
  );
}

/** Secret metadata from the control plane: names, descriptions, version counts. Never a value or key material. */
export function Secrets(_: ScreenProps) {
  const client = api.agentsClient();
  if (!client) return <section className="screen" aria-labelledby="h-secrets"><Head id="h-secrets" title="Secrets" /><NoClient what="secret metadata" /></section>;
  return <SecretsView client={client} />;
}

function SecretsView({ client }: { client: Client }) {
  const [pid, setPid] = useState("");
  const [eid, setEid] = useState("");
  const [open, setOpen] = useState<Secret | null>(null);
  const ps = useCpList(() => client.listProjects(), [client]);
  const project = pid || ps.items?.[0]?.id || "";
  const es = useCpList<Environment>(() => (project ? client.listEnvironments(project) : Promise.resolve([])), [client, project]);
  const env = eid || es.items?.[0]?.id || "";
  const ss = useCpList<Secret>(() => (project && env ? client.listSecrets(project, env) : Promise.resolve([])), [client, project, env]);
  return (
    <section className="screen" aria-labelledby="h-secrets">
      <Head id="h-secrets" title="Secrets" sub="Metadata only. Secret values never leave the vault and are not shown here." />
      {(ps.err || es.err || ss.err) && <Alert>{ps.err || es.err || ss.err}</Alert>}
      {!ps.items ? <Loading what="projects" /> : ps.items.length === 0 ? <Empty icon="key"><b>No projects yet, so no secrets.</b></Empty> : (
        <>
          <label>Project{" "}
            <select aria-label="Project" value={project} onChange={(e) => { setPid(e.target.value); setEid(""); setOpen(null); }}>
              {ps.items.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
          {es.items && es.items.length === 0 ? <Empty icon="key">No environments in this project.</Empty> : es.items && (
            <label>Environment{" "}
              <select aria-label="Environment" value={env} onChange={(e) => { setEid(e.target.value); setOpen(null); }}>
                {es.items.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
              </select>
            </label>
          )}
          {env && (!ss.items ? <Loading what="secrets" /> : ss.items.length === 0 ? <Empty icon="key">No secrets in this environment.</Empty> : (
            <ul>
              {ss.items.map((s) => (
                <li key={s.id}>
                  <button type="button" className="link" onClick={() => setOpen(s)}>{s.name}</button> ({plural(s.version_count, "version")})
                </li>
              ))}
            </ul>
          ))}
          {open && <SecretDetail client={client} secret={open} onClose={() => setOpen(null)} />}
        </>
      )}
    </section>
  );
}

function SecretDetail({ client, secret, onClose }: { client: Client; secret: Secret; onClose: () => void }) {
  const { project_id: p, environment_id: e, id } = secret;
  const s = useLoad(() => client.getSecret(p, e, id), [p, e, id]);
  const v = useLoad<SecretVersion[]>(() => client.listSecretVersions(p, e, id), [p, e, id]);
  const d = s.data ?? secret;
  return (
    <div className="card" role="region" aria-label={`Secret ${secret.name}`}>
      <b>{d.name}</b>
      {d.description && <p>{d.description}</p>}
      <p className="muted small">Updated {d.updated_at}</p>
      {s.alert}{v.alert}
      {!v.data && !v.err ? <Loading what="versions" /> : v.data && (v.data.length === 0 ? <p className="quiet-state">No versions yet.</p> : (
        <table className="grid">
          <caption className="sr-only">Versions of {secret.name}</caption>
          <thead><tr><th className="num">Version</th><th>Key</th><th>Created</th></tr></thead>
          <tbody>{v.data.map((x) => <tr key={x.version}><td className="num mono">{x.version}</td><td className="mono">{x.key_id}</td><td className="mono nowrap">{x.created_at}</td></tr>)}</tbody>
        </table>
      ))}
      <button type="button" className="btn sm quiet" onClick={onClose}>Close</button>
    </div>
  );
}

const layerName = (l: string) => (l === "hub" ? "Hub (people)" : "Gateway (agents)");

/** One switch per MCP tool, grouped by layer; saved through the control plane. */
export function McpTools(_: ScreenProps) {
  const client = api.agentsClient();
  const [tools, setTools] = useState<api.McpToolSetting[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!client) return;
    let live = true;
    client.listMcpTools().then((t) => live && setTools(t), (e) => live && setErr(msg(e)));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const toggle = async (t: api.McpToolSetting, enabled: boolean) => {
    if (!client) return;
    setErr("");
    try {
      const u = await client.setMcpTool(t.layer, t.tool, enabled);
      setTools((cur) => cur?.map((x) => (x.layer === u.layer && x.tool === u.tool ? u : x)) ?? cur);
    } catch (e) { setErr(msg(e)); }
  };
  return (
    <section className="screen" aria-labelledby="h-mcp-tools">
      <Head id="h-mcp-tools" title="MCP tools" sub="Which tools the Hub and the Gateway offer to MCP clients." />
      {err && <Alert>{err}</Alert>}
      {!client ? <Empty icon="key">Connect a control plane on the Agents screen to manage MCP tools.</Empty>
        : !tools ? (err ? null : <Loading what="MCP tools" />)
        : tools.length === 0 ? <Empty icon="key">No MCP tools.</Empty>
        : (["hub", "agent"] as const).map((layer) => {
          const rows = tools.filter((t) => t.layer === layer);
          if (rows.length === 0) return null;
          return (
            <div key={layer} className="card" role="group" aria-label={`${layerName(layer)} tools`}>
              <h2>{layerName(layer)}</h2>
              <ul>
                {rows.map((t) => (
                  <li key={t.tool}>
                    <label>
                      <input type="checkbox" role="switch" aria-label={`${t.tool} (${layer})`} checked={t.enabled} onChange={(e) => void toggle(t, e.target.checked)} />{" "}
                      <strong>{t.tool}</strong>
                    </label>{" "}
                    <span className="muted">{t.description} {t.default_enabled ? "On by default" : "Off by default"}{t.overridden ? ", changed" : ""}</span>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
    </section>
  );
}

/** MCP clients that have signed in, with revoke. */
export function McpClients(_: ScreenProps) {
  const client = api.agentsClient();
  const [clients, setClients] = useState<api.McpClient[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!client) return;
    let live = true;
    client.listMcpClients().then((c) => live && setClients(c), (e) => live && setErr(msg(e)));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const revoke = async (c: api.McpClient) => {
    if (!client) return;
    setErr("");
    try {
      const u = await client.revokeMcpClient(c.id);
      setClients((cur) => cur?.map((x) => (x.id === u.id ? u : x)) ?? cur);
    } catch (e) { setErr(msg(e)); }
  };
  const label = (c: api.McpClient) => c.client_name || c.client_id;
  return (
    <section className="screen" aria-labelledby="h-mcp-clients">
      <Head id="h-mcp-clients" title="MCP clients" sub="Apps that signed in over MCP. Revoking one refuses its next call." />
      {err && <Alert>{err}</Alert>}
      {!client ? <Empty icon="sessions">Connect a control plane on the Agents screen to see MCP clients.</Empty>
        : !clients ? (err ? null : <Loading what="MCP clients" />)
        : clients.length === 0 ? <Empty icon="sessions">No MCP clients have signed in yet.</Empty>
        : (
          <div className="table-wrap">
            <table className="grid">
              <caption className="sr-only">MCP clients</caption>
              <thead><tr><th>Client</th><th>Layer</th><th>Principal</th><th>Last seen</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {clients.map((c) => (
                  <tr key={c.id}>
                    <td className="strong">{label(c)}</td><td>{layerName(c.layer)}</td><td className="mono">{c.principal}</td><td className="mono nowrap">{c.last_seen_at}</td>
                    <td>{c.revoked_at ? `Revoked ${c.revoked_at}` : "Active"}</td>
                    <td>{!c.revoked_at && <button type="button" className="btn sm" onClick={() => void revoke(c)}>Revoke {label(c)}</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </section>
  );
}
