// Lifecycle pages inside one Secret Management project: dynamic secrets, history, rotation, syncs. Sample data only.
// All four read one store per project (lifecycleStore), so a change on one page shows on the others.
import { Fragment, useState, type FormEvent } from "react";
import { Empty, Head, Icon, NOW, DAY, MIN, ago, inTime, plural, Switch, secrets, type PageProps, type Pages } from "../kit";
import { connections } from "../data";
import {
  ACT_ICON, addDef, addRule, addSync, canRoll, conn, dest, envsOf, mins, nextDue, pid, removeDef, removeRule, removeSync, revoke, rollback, rotateNow, setSync, syncNow, syncState, useP,
  type Entry, type Rule,
} from "./lifecycleStore";
import { RollbackAsk } from "./lifecycleUi";
import "./lifecycle.css";

/* ---------- Dynamic secrets ---------- */
// Page: credentials that are created when asked for and destroyed when they expire, with the ones alive right now.
function Dynamic({ project, say }: PageProps) {
  const p = pid(project);
  const [s, up] = useP(p);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const targets = connections.filter((c) => c.kind === "Databases" || c.kind === "Cloud");
  const live = s.leases;
  const add = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const c = targets.find((t) => t.id === f.get("conn"));
    if (!c) return;
    up((x) => addDef(x, { id: `d_${crypto.randomUUID().slice(0, 6)}`, name: String(f.get("name")), conn: c.name, what: c.kind === "Databases" ? "Database user" : "Cloud role session", ttl: Number(f.get("ttl")) }));
    say(`Added ${f.get("name")}. Agents with a grant can now ask for it`);
    setAdding(false);
  };
  return (
    <section>
      <Head title="Dynamic secrets" sub={`Credentials that exist only while something uses them. Each one is created on request and deleted when its lifetime ends, in ${p}.`}>
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding}><Icon name="plus" />Add definition</button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add definition">
          <h2>Add a definition</h2>
          <div className="add lc-add">
            <label className="field">Name<input name="name" required autoFocus placeholder="Read-only Postgres user" autoComplete="off" /></label>
            <label className="field">Connection<select name="conn">{targets.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.provider})</option>)}</select></label>
            <label className="field">Lives for<select name="ttl" defaultValue={10}>{[5, 10, 15, 30].map((m) => <option key={m} value={m}>{mins(m)}</option>)}</select></label>
            <button type="submit" className="btn primary">Add definition</button>
            <button type="button" className="btn quiet" onClick={() => setAdding(false)}>Cancel</button>
          </div>
          <p className="hint">Locksmith uses the connection to create the credential when an agent or machine with a grant asks, and deletes it when the time is up. Nobody sees the value; the gateway applies it for the caller.</p>
        </form>
      )}
      {s.defs.length === 0 ? (
        <Empty icon="power"><b>No dynamic secrets in {p}.</b> Add a definition for a database or cloud connection, then an agent can ask for a credential that expires on its own.</Empty>
      ) : (
        <ul className="list">
          {s.defs.map((d) => {
            const n = live.filter((l) => l.def === d.id).length;
            return (
              <li key={d.id} className="row lc-row">
                <span className="ic"><Icon name={conn(d.conn)?.icon ?? "power"} /></span>
                <div>
                  <b>{d.name}</b> <span className="muted small">on {d.conn}</span>
                  <p>{d.what}. Lives {mins(d.ttl)}.</p>
                  {removing === d.id && (
                    <p className="alert" role="alert" style={{ margin: "10px 0 0" }}>
                      {n ? `Removing this revokes ${plural(n, "live lease")} now and stops new ones.` : "Removing this stops new leases. Nothing is live."}
                      <button type="button" className="btn sm danger" onClick={() => { up((x) => removeDef(x, d.id)); setRemoving(null); say(`Removed ${d.name}`); }}>Remove anyway</button>
                      <button type="button" className="btn sm quiet" onClick={() => setRemoving(null)}>Keep</button>
                    </p>
                  )}
                </div>
                <span className="meta">
                  <span className="lc-st" data-t={n ? "live" : undefined}>{n ? `${n} live` : "None live"}</span>
                  <button type="button" className="btn sm quiet danger-text" aria-label={`Remove ${d.name}`} onClick={() => setRemoving(d.id)}>Remove</button>
                </span>
              </li>
            );
          })}
        </ul>
      )}
      <div className="lc-sub"><h2>Live leases</h2></div>
      {live.length === 0 ? (
        <Empty icon="clock"><b>Nothing is live.</b> A lease appears here when an agent or machine asks for one, and disappears when it expires or you revoke it.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Definition</th><th>Asked by</th><th>Created</th><th>Expires</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {live.map((l) => {
                const d = s.defs.find((x) => x.id === l.def);
                return (
                  <tr key={l.id}>
                    <td className="strong">{d?.name ?? "Removed definition"}</td>
                    <td><span className="mono">{l.who}</span> <span className="badge" data-by={l.kind === "Agent" ? "agent" : undefined}>{l.kind}</span></td>
                    <td className="muted">{ago(l.created)}</td>
                    <td><span className="lc-st" data-t={l.expires - NOW < 5 * MIN ? "warn" : undefined}>{inTime(l.expires)}</span></td>
                    <td className="num"><button type="button" className="btn sm quiet danger-text" aria-label={`Revoke lease for ${l.who}`} onClick={() => { up((x) => revoke(x, l.id)); say(`Revoked the lease for ${l.who}`); }}>Revoke</button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/* ---------- History ---------- */
// Page: every change to this project's secrets and settings as a timeline by day, with a way back to an earlier state.
function History({ project, say }: PageProps) {
  const p = pid(project);
  const [s, up] = useP(p);
  const [env, setEnv] = useState("All");
  const [q, setQ] = useState("");
  const [asking, setAsking] = useState<string | null>(null);
  const base = s.hist.filter((h) => h.name.toLowerCase().includes(q.trim().toLowerCase()));
  const shown = base.filter((h) => env === "All" || h.env === env);
  const filtered = env !== "All" || q !== "";
  const days: [string, Entry[]][] = [];
  for (const r of shown) {
    const n = Math.max(0, Math.floor((NOW - r.at) / DAY));
    const label = n === 0 ? "Today" : n === 1 ? "Yesterday" : `${n} days ago`;
    const g = days.find((d) => d[0] === label);
    if (g) g[1].push(r); else days.push([label, [r]]);
  }
  return (
    <section>
      <Head title="History" sub={`Every change to the secrets and lifecycle settings in ${p}: who did it and what changed. Values are never shown.`} />
      <div className="toolbar">
        <fieldset className="seg inline">
          <legend className="sr-only">Environment</legend>
          {["All", ...envsOf(p)].map((e) => (
            <label key={e}><input type="radio" name="hist-env" checked={env === e} onChange={() => setEnv(e)} />{e}<span className="n">{e === "All" ? base.length : base.filter((r) => r.env === e).length}</span></label>
          ))}
        </fieldset>
        <label className="search"><span className="sr-only">Find by secret name</span><Icon name="search" /><input type="search" placeholder="Find by name" value={q} onChange={(e) => setQ(e.target.value)} /></label>
      </div>
      {days.length === 0 ? (
        <Empty icon="clock">
          {filtered ? <><b>Nothing matches these filters.</b> <button type="button" className="btn sm" onClick={() => { setEnv("All"); setQ(""); }}>Clear filters</button></> : <><b>No changes in {p}.</b> Add or change a secret and it shows up here.</>}
        </Empty>
      ) : days.map(([label, items]) => (
        <Fragment key={label}>
          <h3 className="lc-day">{label}</h3>
          <ul className="list">
            {items.map((e) => (
              <li key={e.id} className="row lc-row" data-undone={e.undone ? "true" : undefined}>
                <span className="ic"><Icon name={ACT_ICON[e.act]} /></span>
                <div>
                  <b>{e.act}</b> <span className="mono">{e.name}</span> {e.env && <span className="badge">{e.env}</span>}
                  <p>{e.who}: {e.note}</p>
                  {asking === e.id && <RollbackAsk s={s} e={e} onCancel={() => setAsking(null)} onApply={() => { up((x) => rollback(x, p, e)); setAsking(null); say(`Rolled back ${e.name} in ${e.env}`); }} />}
                </div>
                <span className="meta">
                  <span title="Time of the change">{ago(e.at)}</span>
                  {e.undone ? <span className="lc-st">Undone</span> : canRoll(s, e) && (
                    <button type="button" className="btn sm" aria-expanded={asking === e.id} aria-label={`Roll back ${e.name} in ${e.env} to here`} onClick={() => setAsking(asking === e.id ? null : e.id)}>Roll back to here</button>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </Fragment>
      ))}
    </section>
  );
}

/* ---------- Rotation ---------- */
const rotTargets = connections.filter((c) => c.kind === "Cloud" || c.kind === "Databases" || c.kind === "Source and CI");

// Page: a schedule of how and when each secret is replaced, with overdue ones first.
function Rotation({ project, say }: PageProps) {
  const p = pid(project);
  const [s, up] = useP(p);
  const [adding, setAdding] = useState(false);
  const [mode, setMode] = useState<"auto" | "manual">("auto");
  const mine = secrets.filter((x) => x.project === p);
  const free = mine.filter((x) => !s.rules.some((r) => r.sid === x.id));
  const rows = s.rules.flatMap((r) => { const sec = mine.find((x) => x.id === r.sid); return sec ? [{ r, sec, due: nextDue(s, r, sec.name, sec.env) }] : []; }).sort((a, b) => a.due - b.due);
  const late = rows.filter((x) => x.due < NOW).length;
  const rotate = (r: Rule, name: string) => {
    up((x) => rotateNow(x, p, r));
    say(r.mode === "auto" ? `Rotated ${name} through ${r.via}. Next in ${plural(r.every, "day")}` : `Recorded that you rotated ${name}. Next reminder in ${plural(r.every, "day")}`);
  };
  const add = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const sec = free.find((x) => x.id === f.get("sid"));
    if (!sec) return;
    up((x) => addRule(x, p, { sid: sec.id, mode, via: mode === "auto" ? String(f.get("via")) : "", every: Number(f.get("every")) }));
    say(`Added a rotation rule for ${sec.name}`);
    setAdding(false);
  };
  return (
    <section>
      <Head title="Rotation" sub={`How and how often each secret in ${p} is replaced, so a leaked value stops working on a schedule.`}>
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding || free.length === 0} title={free.length === 0 ? "Every secret already has a rule" : undefined}><Icon name="plus" />Add rotation rule</button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add rotation rule">
          <h2>Add a rotation rule</h2>
          <div className="add lc-add">
            <label className="field">Secret<select name="sid" autoFocus>{free.map((x) => <option key={x.id} value={x.id}>{x.name} ({x.env})</option>)}</select></label>
            <label className="field">How<select value={mode} onChange={(e) => setMode(e.target.value as "auto" | "manual")}><option value="auto">Automatically, through a connection</option><option value="manual">Remind me to do it by hand</option></select></label>
            {mode === "auto" && <label className="field">Connection<select name="via">{rotTargets.map((c) => <option key={c.id}>{c.name}</option>)}</select></label>}
            <label className="field">Every<select name="every" defaultValue={30}>{[7, 14, 30, 60, 90].map((d) => <option key={d} value={d}>{plural(d, "day")}</option>)}</select></label>
            <button type="submit" className="btn primary">Add rule</button>
            <button type="button" className="btn quiet" onClick={() => setAdding(false)}>Cancel</button>
          </div>
          <p className="hint">{mode === "auto" ? "Locksmith creates the new value through the connection, saves it as a new version and keeps agent grants working. Nobody sees either value." : "Locksmith reminds the project admins when the secret is due. You change it at the source, then mark it as rotated here."}</p>
        </form>
      )}
      {rows.length === 0 ? (
        <Empty icon="rotate"><b>No rotation rules in {p}.</b> Add a rule for a secret to replace it on a schedule or get a reminder when it is due.</Empty>
      ) : (<>
        <p className="muted small" style={{ margin: "0 0 12px" }}>{late ? `${late} overdue, shown first.` : "Nothing is overdue."} {plural(free.length, "secret")} without a rule.</p>
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Secret</th><th>How</th><th>Every</th><th>Next due</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {rows.map(({ r, sec, due }) => {
                const left = due - NOW;
                const t = left < 0 ? "danger" : left < 7 * DAY ? "warn" : "live";
                return (
                  <tr key={sec.id}>
                    <td><span className="strong mono">{sec.name}</span> <span className="badge">{sec.env}</span></td>
                    <td>{r.mode === "auto" ? <>Automatic, through {r.via}</> : "Reminder to rotate by hand"}</td>
                    <td className="nowrap">{plural(r.every, "day")}</td>
                    <td className="nowrap">{left < 0 ? `${plural(Math.ceil(-left / DAY), "day")} ago` : inTime(due)}</td>
                    <td><span className="lc-st" data-t={t}>{left < 0 ? "Overdue" : left < 7 * DAY ? "Due soon" : "On schedule"}</span></td>
                    <td className="num nowrap">
                      <button type="button" className="btn sm" aria-label={`${r.mode === "auto" ? "Rotate" : "Mark as rotated:"} ${sec.name} in ${sec.env}`} onClick={() => rotate(r, sec.name)}>{r.mode === "auto" ? "Rotate now" : "Mark as rotated"}</button>
                      <button type="button" className="btn sm quiet danger-text" aria-label={`Remove the rule for ${sec.name} in ${sec.env}`} title="The secret stays; it just stops being rotated" onClick={() => { up((x) => removeRule(x, p, sec.id)); say(`Removed the rule for ${sec.name}`); }}>Remove rule</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </>)}
    </section>
  );
}

/* ---------- Syncs ---------- */
const syncTargets = connections.filter((c) => c.kind === "Source and CI" || c.kind === "Cloud");

// Page: copies of an environment's secrets pushed to where apps run, shown as source to destination.
function Syncs({ project, say }: PageProps) {
  const p = pid(project);
  const envs = envsOf(p);
  const [s, up] = useP(p);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const count = (env: string) => secrets.filter((x) => x.project === p && x.env === env).length;
  const add = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const c = syncTargets.find((t) => t.id === f.get("conn"));
    if (!c) return;
    up((x) => addSync(x, p, { id: `y_${crypto.randomUUID().slice(0, 6)}`, env: String(f.get("env")), c, target: String(f.get("target")), on: true }));
    say(`Added a sync to ${dest(c)}`);
    setAdding(false);
  };
  return (
    <section>
      <Head title="Syncs" sub={`Keep copies of ${p} secrets where your apps run. Locksmith pushes again each time a secret changes.`}>
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding}><Icon name="plus" />Add sync</button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add sync">
          <h2>Add a sync</h2>
          <div className="add lc-add">
            <label className="field">Copy from<select name="env">{envs.map((e) => <option key={e}>{e}</option>)}</select></label>
            <label className="field">To connection<select name="conn">{syncTargets.map((c) => <option key={c.id} value={c.id}>{c.name} ({dest(c)})</option>)}</select></label>
            <label className="field">Target<input name="target" required placeholder="acme/api-service" autoComplete="off" /></label>
            <button type="submit" className="btn primary">Add and sync</button>
            <button type="button" className="btn quiet" onClick={() => setAdding(false)}>Cancel</button>
          </div>
          <p className="hint">The first push happens now. The destination then holds real values, so anyone who can read it can read them. Locksmith can only push; it never reads them back.</p>
        </form>
      )}
      {s.syncs.length === 0 ? (
        <Empty icon="relay"><b>No syncs in {p}.</b> Add one to push an environment to GitHub Actions, Vercel or AWS so the app can read it there.</Empty>
      ) : (
        <ul className="list">
          {s.syncs.map((y) => {
            const st = syncState(s, p, y);
                        return (
              <li key={y.id} className="row lc-row">
                <span className="ic"><Icon name={y.c.icon} /></span>
                <div>
                  <span className="lc-route"><b>{y.env}</b><Icon name="arrow" /><b>{dest(y.c)}</b><span className="mono small">{y.target}</span></span>
                  <p><span className="lc-st" data-t={st.tone}>{st.text}</span> · {plural(count(y.env), "secret")} · last run {ago(y.at)} · via {y.c.name}</p>
                  {removing === y.id && (
                    <p className="alert" role="alert" style={{ margin: "10px 0 0" }}>
                      Removing this stops copying {plural(count(y.env), "secret")} to {dest(y.c)}. What is already there stays and goes stale; Locksmith does not delete it.
                      <button type="button" className="btn sm danger" onClick={() => { up((x) => removeSync(x, y.id)); setRemoving(null); say("Removed the sync"); }}>Remove sync</button>
                      <button type="button" className="btn sm quiet" onClick={() => setRemoving(null)}>Keep</button>
                    </p>
                  )}
                </div>
                <span className="meta">
                  <Switch label={`Keep ${y.env} synced to ${y.target}`} checked={y.on} onChange={(on) => { up((x) => setSync(x, y.id, { on })); say(on ? "Sync resumed" : "Sync paused. Nothing is pushed until you resume"); }} />
                  <button type="button" className="btn sm" disabled={!y.on} aria-label={`Sync ${y.env} to ${y.target} now`} onClick={() => { up((x) => syncNow(x, y.id)); say(y.fail ? `Still failing: ${y.fail}` : `Synced ${plural(count(y.env), "secret")} to ${dest(y.c)}`); }}>Sync now</button>
                  <button type="button" className="btn sm quiet danger-text" aria-label={`Remove sync of ${y.env} to ${y.target}`} onClick={() => setRemoving(y.id)}>Remove</button>
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

export const pages: Pages = {
  "secrets/dynamic": Dynamic,
  "secrets/history": History,
  "secrets/rotation": Rotation,
  "secrets/syncs": Syncs,
};
