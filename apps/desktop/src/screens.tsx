import { Fragment, useCallback, useEffect, useState } from "react";
import type {
  AuditEvent, AuditVerifyView, HttpTokenInfo, LeaseInfo, RelayInfo, StatusView,
} from "@locksmith/api-types";
import * as api from "./api";
import { KeyCut, KeyCutLegend } from "./brand";

export interface ScreenProps {
  st: StatusView | null;
  /** Runs an action, shows its rejection in the band and refreshes status. */
  act: <T>(fn: () => Promise<T>, label?: (r: T) => string) => Promise<void>;
}

export const msg = (e: unknown) =>
  e && typeof e === "object" && "message" in e ? String((e as { message: unknown }).message) : String(e);
export const errCode = (e: unknown) =>
  e && typeof e === "object" && "code" in e ? String((e as { code: unknown }).code) : "";

const pad = (n: number) => String(n).padStart(2, "0");
const clock = (ts: number) => { const d = new Date(ts * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const stamp = (ts: number) => {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${clock(ts)}:${pad(d.getSeconds())}`;
};
const left = (s: number) =>
  s <= 0 ? "expired" : s < 60 ? `${s} s` : s < 3600 ? `${Math.floor(s / 60)} min` : `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
const agent = (command: string) => command.split(" ")[0]!.split("/").pop() || command;
const nowSecs = () => Math.floor(Date.now() / 1000);
const isBad = (e: AuditEvent) => e.decision === "DENY" || e.action === "BLOCKED";
/** Ledger payloads break only after "/" and ":", never mid-token. */
const breakable = (s: string) =>
  s.split(/(?<=[/:])/).map((part, i) => <Fragment key={i}>{i > 0 && <wbr />}{part}</Fragment>);
const reducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
const STRIKE_MS = 480;
const revokedLabel = (n: number) => `Revoked ${n} ${n === 1 ? "session" : "sessions"}`;

/** Loads once per `deps` change and reports its own failure inline. */
function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState("");
  const load = useCallback(async () => {
    try { setData(await fn()); setErr(""); } catch (e) { setErr(msg(e)); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { void load(); }, [load]);
  return { data, err, load, alert: err ? <p role="alert" className="alert inline">{err}</p> : null };
}

const Loading = ({ what }: { what: string }) => <p className="state" aria-busy="true">Reading {what}…</p>;

export function Overview({ st, act }: ScreenProps) {
  // A wider window than the 8 shown, so struck rows can find their REVOKE time.
  const ev = useLoad(() => api.auditList(40), [st]);
  const [striking, setStriking] = useState<string | null>(null);
  const now = nowSecs();
  const live = st?.leases.filter((l) => l.state === "active") ?? [];
  const struck = st?.leases.filter((l) => l.state !== "active") ?? [];
  const events = [...(ev.data ?? [])].reverse().slice(0, 8);
  const revokeOne = async (id: string) => {
    if (!reducedMotion()) {
      setStriking(id);
      await new Promise((r) => setTimeout(r, STRIKE_MS));
    }
    await act(() => api.revoke(id), revokedLabel);
    setStriking(null);
  };
  return (
    <section className="overview" aria-labelledby="h-overview">
      <h1 id="h-overview" className="sr-only">Overview</h1>
      <div className="overview-main">
        <h2 className="h2">Keying schedule {st && <span>{live.length} active</span>}</h2>
        {st?.locked && (
          <p className="note">The vault is locked: agents cannot start sessions or use keys until you unlock it. Unlock opens a native Locksmith prompt; the passphrase never enters this window.</p>
        )}
        {!st ? <Loading what="the schedule" /> : live.length === 0 ? (
          <p className="state">No keys cut right now. Start one with <code>smith session start -- &lt;agent&gt;</code>.</p>
        ) : (
          <table className="grid schedule">
            <caption className="sr-only">Active sessions</caption>
            <thead><tr><th>Session</th><th>Agent</th><th>Project / env</th><th><KeyCutLegend /></th><th className="num">Time left</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {live.map((l) => (
                <tr key={l.id} data-striking={striking === l.id || undefined}>
                  <td className="id">{l.id}</td>
                  <td title={l.command}>{agent(l.command)}</td>
                  <td><span className="stack">{l.project}<span className="quiet">{l.env}</span></span></td>
                  <td><KeyCut scopes={l.scopes} /></td>
                  <td className="num strong" data-soon={l.expires_at - now < 600}>{left(l.expires_at - now)}</td>
                  <td className="end">
                    <button type="button" className="link danger" aria-label={`Revoke ${l.id}`} disabled={striking !== null}
                      onClick={() => revokeOne(l.id)}>Revoke</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {struck.length > 0 && <Struck leases={struck} events={ev.data ?? []} />}
      </div>

      <aside className="overview-side" aria-labelledby="h-events">
        <h2 className="h2" id="h-events">Latest events</h2>
        {ev.alert}
        {!ev.data && !ev.err ? <Loading what="the ledger" /> : events.length === 0 ? (
          <p className="state">Nothing in the ledger yet.</p>
        ) : (
          <ol className="events">
            {events.map((e) => (
              <li key={e.seq} data-bad={isBad(e)}>
                <time className="id" dateTime={new Date(e.ts * 1000).toISOString()}>{clock(e.ts)}</time>
                <strong>{e.action}</strong>
                <span className="id ev-target">{breakable(e.target ?? e.policy_rule)}</span>
              </li>
            ))}
          </ol>
        )}
      </aside>
    </section>
  );
}

function Struck({ leases, events }: { leases: LeaseInfo[]; events: AuditEvent[] }) {
  const revokedAt = (id: string) => events.find((e) => e.action === "REVOKE" && e.target === id)?.ts;
  const ended = (l: LeaseInfo) => {
    if (l.state === "expired") return `expired ${clock(l.expires_at)}`;
    const t = l.state === "revoked" ? revokedAt(l.id) : undefined;
    return t ? `revoked ${clock(t)}` : l.state;
  };
  return (
    <>
      <h2 className="h2 spaced">Struck from the schedule</h2>
      <table className="grid struck">
        <caption className="sr-only">Ended sessions</caption>
        <thead><tr><th>Session</th><th>Agent</th><th>Project / env</th><th>Ended</th></tr></thead>
        <tbody>
          {leases.map((l) => (
            <tr key={l.id} data-state={l.state}>
              <td className="id"><s>{l.id}</s></td>
              <td>{agent(l.command)}</td>
              <td>{l.project} <span className="quiet">/ {l.env}</span></td>
              <td>{ended(l)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
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
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      const r = await api.putSecretSecure(project, env, name.trim());
      setNote(r === "submitted" ? `Key ${name.trim()} saved.` : `Key ${name.trim()}: cancelled, nothing changed.`);
      setName("");
    } catch (x) { setErr(msg(x)); }
    await names.load();
  };
  return (
    <section className="screen" aria-labelledby="h-keys">
      <h1 id="h-keys" className="h1">Keys</h1>
      <div className="fields">
        <label className="field">Project<input list="dl-projects" value={project} onChange={(e) => setProject(e.target.value)} spellCheck={false} /></label>
        <label className="field">Environment<input list="dl-envs" value={env} onChange={(e) => setEnv(e.target.value)} spellCheck={false} /></label>
        <datalist id="dl-projects">{uniq(seen.map((x) => x.project)).map((v) => <option key={v} value={v} />)}</datalist>
        <datalist id="dl-envs">{uniq(seen.map((x) => x.env)).map((v) => <option key={v} value={v} />)}</datalist>
      </div>
      {users.length > 0 && (
        <p className="usable">
          Usable now by {users.map((l, i) => <Fragment key={l.id}>{i > 0 && ", "}<span className="id">{l.id}</span> ({agent(l.command)})</Fragment>)}
          <span className="quiet"> &middot; sessions on {project} / {env} with <code>run</code> scope</span>
        </p>
      )}
      {names.alert}
      {!names.data && !names.err ? <Loading what="key names" /> : names.data?.length === 0 ? (
        <p className="state">No keys in {project} / {env} yet. Add the first one below.</p>
      ) : names.data && (
        <table className="grid">
          <caption className="sr-only">Key names in {project} / {env}</caption>
          <thead><tr><th>Key name</th></tr></thead>
          <tbody>{names.data.map((n) => <tr key={n}><td className="id">{n}</td></tr>)}</tbody>
        </table>
      )}

      <form className="add" onSubmit={submit} aria-labelledby="h-add">
        <h2 id="h-add" className="h2">Add or rotate a key</h2>
        <div className="fields">
          <label className="field wide">Key name<input value={name} onChange={(e) => setName(e.target.value)} spellCheck={false} placeholder="e.g. NPM_TOKEN" /></label>
          <button type="submit" className="btn primary" disabled={!name.trim()}>Add or rotate key</button>
        </div>
        <p className="quiet">The value is typed into a native Locksmith prompt, never into this window.</p>
      </form>
      {err && <p role="alert" className="alert inline">{err}</p>}
      <p aria-live="polite" className="done">{note}</p>
    </section>
  );
}

export function Tokens({ st }: ScreenProps) {
  const t = useLoad(api.tokenList, []);
  const [err, setErr] = useState("");
  const scopes = (lease: string) => st?.leases.find((l) => l.id === lease)?.scopes;
  const revokeToken = async (x: HttpTokenInfo) => {
    setErr("");
    try { await api.tokenRevoke(x.prefix); } catch (e) { setErr(msg(e)); }
    await t.load();
  };
  return (
    <section className="screen" aria-labelledby="h-tokens">
      <h1 id="h-tokens" className="h1">Tokens</h1>
      <p className="lede">Opaque <code>lsk_</code> tokens stand in for a key on one host. Only the prefix is shown.</p>
      {t.alert}
      {err && <p role="alert" className="alert inline">{err}</p>}
      {!t.data && !t.err ? <Loading what="tokens" /> : t.data?.length === 0 ? (
        <p className="state">No live tokens. Inside a session, mint one with <code>smith token issue &lt;KEY&gt; --provider &lt;name&gt;</code>.</p>
      ) : t.data && (
        <table className="grid">
          <caption className="sr-only">Live tokens</caption>
          <thead><tr><th>Token / session</th><th>Key</th><th>Host / placement</th><th><KeyCutLegend /></th><th className="num">Created</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {t.data.map((x) => {
              const sc = scopes(x.lease);
              return (
                <tr key={x.prefix}>
                  <td className="id"><span className="stack">{x.prefix}<span className="quiet">{x.lease}</span></span></td>
                  <td className="id">{x.key}</td>
                  <td><span className="stack">{x.hosts.join(", ")}<span className="quiet id">{x.placement}</span></span></td>
                  <td>{sc ? <KeyCut scopes={sc} /> : <span className="quiet">session ended</span>}</td>
                  <td className="num">{stamp(x.created_at).slice(5, 16)}</td>
                  <td className="end"><button type="button" className="link danger" aria-label={`Revoke token ${x.prefix}`} onClick={() => revokeToken(x)}>Revoke</button></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

// Only commands that exist in crates/smith-cli (git_cmd.rs, http_cmd.rs, run_cmd.rs, db_cmd.rs).
const RELAYS: { key: keyof Pick<RelayInfo, "git_port" | "http_port" | "aws_port"> | null; name: string; setup: string[] }[] = [
  { key: "git_port", name: "Git forwarder", setup: ["smith git setup"] },
  { key: "http_port", name: "HTTP relay", setup: ["smith token issue <KEY> --provider <name>", "smith http status"] },
  { key: "aws_port", name: "AWS SigV4 relay", setup: ["smith run --aws <profile> -- <command>"] },
  { key: null, name: "Database relay", setup: ["smith db connect <name> -- <command>"] },
];

export function Relays(_: ScreenProps) {
  const r = useLoad(api.relayInfo, []);
  const info = r.data;
  return (
    <section className="screen" aria-labelledby="h-relays">
      <h1 id="h-relays" className="h1">Relays</h1>
      <p className="lede">Each relay signs or forwards requests on an agent's behalf; the key stays in Locksmith.</p>
      {r.alert}
      {!info && !r.err ? <Loading what="relays" /> : info && (
        <>
          <table className="grid">
            <caption className="sr-only">Relays</caption>
            <thead><tr><th>Relay</th><th className="num">Port</th><th>Set up</th></tr></thead>
            <tbody>
              {RELAYS.map((x) => {
                const port = x.key && info[x.key];
                return (
                  <tr key={x.name}>
                    <th scope="row">{x.name}</th>
                    <td className="num">{!x.key ? <span className="quiet">per target</span> : port == null ? <span className="quiet">not running</span> : <span className="id">{port}</span>}</td>
                    <td><span className="cmds">{x.setup.map((c) => <code key={c}>{c}</code>)}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <h2 className="h2 spaced">Explicit-proxy CA hosts</h2>
          {info.ca_hosts.length === 0 ? <p className="state">No hosts use the Locksmith CA.</p> : (
            <ul className="hosts">{info.ca_hosts.map((h) => <li key={h} className="id">{h}</li>)}</ul>
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
      <div className="screen-head">
        <h1 id="h-audit" className="h1">Audit</h1>
        <label className="field search"><span className="sr-only">Filter</span><input type="search" value={filter} onChange={(e) => setFilter(e.target.value)} spellCheck={false} placeholder="Filter by action, key, host or session" /></label>
        <button type="button" className="btn" onClick={verify}>Verify ledger</button>
      </div>
      <div aria-live="assertive">
        {ver && (ver.broken_at === null
          ? <p className="verdict ok">Ledger intact: {ver.events} events checked, hash chain unbroken.</p>
          : <p className="verdict broken">Ledger BROKEN at seq {ver.broken_at}. {ver.detail}</p>)}
      </div>
      {ev.alert}
      {err && <p role="alert" className="alert inline">{err}</p>}
      {!ev.data && !ev.err ? <Loading what="the ledger" /> : rows.length === 0 ? (
        <p className="state">{q ? "No events match this filter." : "Nothing in the ledger yet."}</p>
      ) : (
        <table className="grid audit">
          <caption className="sr-only">Audit events, newest first</caption>
          <thead><tr><th className="num">Seq</th><th>Time</th><th>Action</th><th>Decision</th><th>Target</th><th>Rule</th><th>Session</th><th>Actor</th></tr></thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.seq} data-bad={isBad(e)}>
                <td className="num id">{e.seq}</td>
                <td className="num">{stamp(e.ts)}</td>
                <td className="strong">{e.action}</td>
                <td>{e.decision}</td>
                <td className="id wrap">{breakable(e.target ?? "")}</td>
                <td className="id">{e.policy_rule}</td>
                <td className="id">{e.session_id ?? ""}</td>
                <td className="id" title={e.actor_exe}>{e.actor_exe.split("/").pop()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
