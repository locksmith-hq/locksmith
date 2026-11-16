import { Fragment, useCallback, useEffect, useState } from "react";
import type {
  AuditEvent, AuditVerifyView, HttpTokenInfo, LeaseInfo, RelayInfo, StatusView,
} from "@locksmith/api-types";
import * as api from "./api";
import { Icon, type IconName } from "./brand";

export interface ScreenProps {
  st: StatusView | null;
  /** Runs an action, shows its rejection under the vault banner and refreshes status. */
  act: <T>(fn: () => Promise<T>, label?: (r: T) => string) => Promise<void>;
  /** Switches the main screen. */
  go: (tab: "Overview" | "Keys" | "Tokens" | "Relays" | "Audit") => void;
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
      <span className="who-1">{struck ? <s className="who-name">{name}</s> : <b className="who-name">{name}</b>}<span className="mono id">{l.id}</span></span>
      <span className="who-2">{l.project} / <span className={l.env === "production" ? "prod" : undefined}>{l.env}</span></span>
    </span>
  );
};

const ScopeText = ({ scopes }: { scopes: readonly string[] }) => (
  <ul className="scopes-t mono" aria-label={scopes.length ? `Scopes granted: ${scopes.join(", ")}` : "No scopes granted"}>
    {scopes.map((s) => <li key={s}>{s}</li>)}
  </ul>
);

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
