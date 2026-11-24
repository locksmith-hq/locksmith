// Agent Gateway pages: hosts, grants and settings. All state lives in ./gateway-data so the pages agree.
import { useState } from "react";
import {
  Crumbs,
  Empty,
  Head,
  Icon,
  NOW,
  DAY,
  Switch,
  agents,
  ago,
  inTime,
  plural,
  secrets as seedSecrets,
  type PageProps,
  type Pages,
} from "../kit";
import {
  EXPIRY,
  GRANT_MAX,
  guardrail,
  label,
  lastCall,
  until,
  useGw,
  useHosts,
  useReqs,
  useSecrets,
  type Host,
} from "./gateway-data";
import "../settings.css";
import "./gateway.css";

const NAMES = [...new Set(seedSecrets.map((s) => s.name))].sort();
const HOST_RE = /^(?=.{3,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/;
type Say = PageProps["say"];

// Allowing a host for a secret adds the secret to an existing row rather than listing the host twice.
const withAllowed = (hs: Host[], host: string, name: string): Host[] =>
  hs.some((h) => h.host === host)
    ? hs.map((h) => (h.host === host && !h.names.includes(name) ? { ...h, names: [...h.names, name] } : h))
    : [...hs, { host, names: [name], week: 0 }];
const when = (expires: number | null) =>
  expires === null ? "No expiry" : expires <= NOW ? "Expired" : inTime(expires);

function NotFound({ what, href, back }: { what: string; href: string; back: string }) {
  return (
    <section>
      <Crumbs trail={[[back, href], ["Not found"]]} />
      <Head title="Not found" sub={`There is no ${what} with that address. It may have been removed.`}>
        <a className="btn primary" href={href}>
          Back to {back.toLowerCase()}
        </a>
      </Head>
      <Empty icon="search">
        <b>Nothing here.</b> Check the address, or go back to the list.
      </Empty>
    </section>
  );
}

// ---------------------------------------------------------------- Hosts

function HostList({ say }: { say: Say }) {
  const [hosts, setHosts] = useHosts();
  const [reqs] = useReqs();
  const [adding, setAdding] = useState(false);
  const [bad, setBad] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const attempts = reqs
    .filter((r) => r.result === "Blocked" && !hosts.some((h) => h.host === r.host && h.names.includes(r.name)))
    .sort((a, b) => b.at - a.at);

  const allow = (host: string, name: string) => {
    setHosts((hs) => withAllowed(hs, host, name));
    say(`Allowed ${name} to go to ${host}`);
  };
  const submit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const host = String(f.get("host")).trim().toLowerCase();
    if (!HOST_RE.test(host)) return setBad(true);
    allow(host, String(f.get("name")));
    setAdding(false);
    setBad(false);
  };
  const remove = (h: Host) => {
    setHosts((hs) => hs.filter((x) => x.host !== h.host));
    setRemoving(null);
    say(`Removed ${h.host}`);
  };

  return (
    <section>
      <Head
        title="Allowed hosts"
        sub="A secret is only ever added to a call to a host on this list. Anywhere else, the gateway refuses the call."
      >
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Allow a host
        </button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={submit} aria-label="Allow a host">
          <h2>Allow a host</h2>
          <div className="add">
            <label className="field">
              Host name
              <input
                name="host"
                required
                autoFocus
                placeholder="api.example.com"
                autoComplete="off"
                spellCheck={false}
                aria-invalid={bad}
                onChange={() => setBad(false)}
              />
            </label>
            <label className="field">
              Secret that may go there
              <select name="name">
                {NAMES.map((n) => (
                  <option key={n}>{n}</option>
                ))}
              </select>
            </label>
            <button type="submit" className="btn primary">
              Allow host
            </button>
            <button
              type="button"
              className="btn quiet"
              onClick={() => {
                setAdding(false);
                setBad(false);
              }}
            >
              Cancel
            </button>
          </div>
          {bad && (
            <p className="gw-warn" role="alert">
              <Icon name="alert" />
              Enter a host name only, such as api.example.com. No https:// and no path.
            </p>
          )}
          <p className="hint">
            Only that secret goes to that host. Other secrets stay blocked there until you allow them too.
          </p>
        </form>
      )}
      {hosts.length === 0 ? (
        <Empty icon="http">
          <b>No hosts are allowed.</b> Agents can still run, but the gateway adds no secret to any call. Allow a host to
          start.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th>Host</th>
                <th>Secrets that may go there</th>
                <th>Last request</th>
                <th className="num">Last 7 days</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {hosts.flatMap((h) => [
                <tr key={h.host}>
                  <td className="mono">
                    <a className="strong" href={`#/access/hosts/${encodeURIComponent(h.host)}`}>
                      {h.host}
                    </a>
                  </td>
                  <td>
                    <ul className="scopes-t mono" aria-label={`Secrets allowed at ${h.host}`}>
                      {h.names.map((n) => (
                        <li key={n}>{n} </li>
                      ))}
                    </ul>
                  </td>
                  <td className="muted">
                    {lastCall(reqs, h.host) === null ? "Never used" : ago(lastCall(reqs, h.host))}
                  </td>
                  <td className="num mono">{h.week.toLocaleString("en-US")}</td>
                  <td className="num">
                    <button
                      type="button"
                      className="btn sm quiet danger-text"
                      aria-label={`Remove ${h.host}`}
                      onClick={() => (h.week > 0 ? setRemoving(h.host) : remove(h))}
                    >
                      Remove
                    </button>
                  </td>
                </tr>,
                removing === h.host && (
                  <tr key={`${h.host}-x`} className="detail">
                    <td colSpan={5}>
                      <p className="alert" role="alert" style={{ margin: 0 }}>
                        {plural(h.week, "call")} went to {h.host} in the last 7 days. After removal, the gateway refuses
                        them and agents see an error.
                        <button type="button" className="btn sm danger" onClick={() => remove(h)}>
                          Remove anyway
                        </button>
                        <button type="button" className="btn sm quiet" onClick={() => setRemoving(null)}>
                          Keep host
                        </button>
                      </p>
                    </td>
                  </tr>
                ),
              ])}
            </tbody>
          </table>
        </div>
      )}

      <div className="sec-h" style={{ marginTop: 28 }}>
        <h2>Recently blocked</h2>
        <span className="n">{plural(attempts.length, "attempt")}</span>
      </div>
      {attempts.length === 0 ? (
        <Empty icon="shield">
          <b>Nothing blocked lately.</b> When an agent tries to send a secret to a host that is not on the list, it
          shows up here.
        </Empty>
      ) : (
        <ul className="list">
          {attempts.map((a) => (
            <li key={a.id} className="row">
              <span className="ic">
                <Icon name="alert" />
              </span>
              <div>
                <a className="mono strong" href={`#/access/hosts/${encodeURIComponent(a.host)}`}>
                  {a.host}
                </a>{" "}
                <span className="badge" data-by="agent">
                  Blocked
                </span>
                <p>
                  <span className="mono">{a.agent}</span> tried to send <span className="mono">{a.name}</span> there{" "}
                  {ago(a.at)}. No credential left the gateway.
                </p>
              </div>
              <span className="meta">
                <button
                  type="button"
                  className="btn sm"
                  aria-label={`Allow ${a.name} at ${a.host}`}
                  onClick={() => allow(a.host, a.name)}
                >
                  Allow this host
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function HostDetail({ host, say }: { host: string; say: Say }) {
  const [hosts, setHosts] = useHosts();
  const [reqs] = useReqs();
  const [pick, setPick] = useState("");
  const h = hosts.find((x) => x.host === host);
  const mine = reqs.filter((r) => r.host === host).sort((a, b) => b.at - a.at);
  if (!h && mine.length === 0) return <NotFound what="host" href="#/access/hosts" back="Allowed hosts" />;

  const names = h?.names ?? [];
  const free = NAMES.filter((n) => !names.includes(n));
  const choice = free.includes(pick) ? pick : (free[0] ?? "");
  const first = mine.find((r) => r.result === "Blocked")?.name;
  const allow = (name: string) => {
    setHosts((hs) => withAllowed(hs, host, name));
    say(`Allowed ${name} to go to ${host}`);
  };
  const dropName = (name: string) => {
    setHosts((hs) =>
      hs.flatMap((x) =>
        x.host !== host ? [x] : x.names.length > 1 ? [{ ...x, names: x.names.filter((n) => n !== name) }] : [],
      ),
    );
    say(names.length > 1 ? `${name} can no longer go to ${host}` : `Removed ${host}`);
  };

  return (
    <section>
      <Crumbs trail={[["Allowed hosts", "#/access/hosts"], [host]]} />
      <Head
        title={host}
        sub={
          h
            ? "The gateway adds the secrets below to calls to this host. Agents never see them."
            : "This host is not on the allowed list, so the gateway refuses every call to it."
        }
      >
        {!h && first && (
          <button type="button" className="btn primary" onClick={() => allow(first)}>
            <Icon name="unlock" />
            Allow {first} here
          </button>
        )}
      </Head>
      <div className="sec-h">
        <h2>Secrets allowed here</h2>
        <span className="n">{names.length}</span>
      </div>
      {names.length === 0 ? (
        <Empty icon="lock">
          <b>No secret may go to this host.</b>{" "}
          {first ? `${first} was blocked here. Allow it with the button above.` : "Allow one below."}
        </Empty>
      ) : (
        <ul className="plain" aria-label={`Secrets allowed at ${host}`}>
          {names.map((n) => (
            <li key={n}>
              <span className="mono strong">{n}</span>
              <button
                type="button"
                className="btn sm quiet danger-text"
                aria-label={`Stop sending ${n} to ${host}`}
                onClick={() => dropName(n)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {h && free.length > 0 && (
        <form
          className="inline-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (choice) allow(choice);
          }}
        >
          <select aria-label="Secret to allow" value={choice} onChange={(e) => setPick(e.target.value)}>
            {free.map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
          <button type="submit" className="btn sm">
            <Icon name="plus" />
            Allow secret
          </button>
        </form>
      )}

      <div className="sec-h" style={{ marginTop: 28 }}>
        <h2>Recent requests</h2>
        <span className="n">{mine.length}</span>
      </div>
      {mine.length === 0 ? (
        <Empty icon="doc">
          <b>No requests yet.</b> Calls to this host appear here as they happen.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th>Time</th>
                <th>Agent</th>
                <th>Secret</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {mine.map((r) => (
                <tr key={r.id}>
                  <td className="muted">{ago(r.at)}</td>
                  <td className="mono">{r.agent}</td>
                  <td className="mono">{r.name}</td>
                  <td>
                    {r.result === "Allowed" ? (
                      <span className="gw-ok">Allowed</span>
                    ) : (
                      <span className="gw-bad">Blocked</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Hosts({ sub, say }: PageProps) {
  return sub ? <HostDetail key={sub} host={decodeURIComponent(sub)} say={say} /> : <HostList say={say} />;
}

// ---------------------------------------------------------------- Grants

interface GrantRow {
  key: string;
  secretId: string;
  agent: string;
  project: string;
  env: string;
  name: string;
  expires: number | null;
  last: number | null;
}

const Blocked = ({ why }: { why: string }) => (
  <p className="gw-warn" role="alert">
    <Icon name="alert" />
    Not allowed by the guardrail "{why}". You can change it in <a href="#/access/settings">Settings</a>.
  </p>
);

function Grants({ say }: PageProps) {
  const [secs, setSecs] = useSecrets();
  const [gw] = useGw();
  const [agent, setAgent] = useState("all");
  const [project, setProject] = useState("all");
  const [quick, setQuick] = useState<"all" | "none" | "soon">("all");
  const [editing, setEditing] = useState<string | null>(null);
  const [pick, setPick] = useState(0);
  const [adding, setAdding] = useState(false);
  const [addAgent, setAddAgent] = useState(agents[0]?.name ?? "");
  const [notice, setNotice] = useState<string | null>(null);

  const all: GrantRow[] = secs.flatMap((s) =>
    s.grants.map((g) => ({
      key: `${s.id}:${g.agent}`,
      secretId: s.id,
      agent: g.agent,
      project: s.project,
      env: s.env,
      name: s.name,
      expires: g.expires,
      last: s.lastUsed,
    })),
  );
  const projectIds = [...new Set(secs.map((s) => s.project))];
  const shown = all.filter(
    (r) =>
      (agent === "all" || r.agent === agent) &&
      (project === "all" || r.project === project) &&
      (quick === "all" || (quick === "none" ? r.expires === null : r.expires !== null && r.expires - NOW <= DAY)),
  );
  const count = (f: (r: GrantRow) => boolean) => all.filter(f).length;

  const patch = (
    r: GrantRow,
    f: (g: { agent: string; expires: number | null }) => { agent: string; expires: number | null } | null,
  ) =>
    setSecs((ss) =>
      ss.map((s) =>
        s.id !== r.secretId
          ? s
          : { ...s, grants: s.grants.flatMap((g) => (g.agent !== r.agent ? [g] : [f(g) ?? []].flat())) },
      ),
    );
  const revoke = (r: GrantRow) => {
    patch(r, () => null);
    setEditing(null);
    say(`Revoked ${r.agent} from ${r.name} in ${r.project}/${r.env}`);
  };
  const change = (r: GrantRow) => {
    const secsLeft = EXPIRY[pick]?.[1] ?? null;
    const s = secs.find((x) => x.id === r.secretId);
    // Making a grant shorter is never held back.
    const longer = r.expires !== null && (secsLeft === null || NOW + secsLeft > r.expires);
    const why = s && longer ? guardrail(s, secsLeft, gw) : null;
    if (why) {
      setNotice(why);
      return;
    }
    patch(r, (g) => ({ ...g, expires: until(secsLeft) }));
    setEditing(null);
    setNotice(null);
    say(
      `${r.agent} can use ${r.name} until ${secsLeft === null ? "someone revokes it" : `${EXPIRY[pick]?.[0]} from now`}`,
    );
  };
  const give = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const s = secs.find((x) => x.id === String(f.get("secret")));
    if (!s) return;
    const secsLeft = EXPIRY[Number(f.get("expiry"))]?.[1] ?? null;
    const why = guardrail(s, secsLeft, gw);
    if (why) {
      setNotice(why);
      return;
    }
    setSecs((ss) =>
      ss.map((x) =>
        x.id === s.id ? { ...x, grants: [...x.grants, { agent: addAgent, expires: until(secsLeft) }] } : x,
      ),
    );
    setAdding(false);
    setNotice(null);
    say(`${addAgent} can now use ${s.name} through the gateway`);
  };
  const defaultExpiry = Math.max(
    0,
    EXPIRY.findIndex(([l]) => l === gw.grantExpiry),
  );
  const freeSecrets = secs.filter((s) => !s.grants.some((g) => g.agent === addAgent));

  return (
    <section>
      <Head
        title="Grants"
        sub="A grant lets an agent use a secret through the gateway. It never lets the agent read the value."
      >
        <button
          type="button"
          className="btn primary"
          onClick={() => {
            setAdding(true);
            setNotice(null);
          }}
          disabled={adding}
        >
          <Icon name="plus" />
          Give an agent access
        </button>
      </Head>
      {gw.paused && (
        <p className="gw-notice" role="status">
          <Icon name="alert" />
          <span>
            Agents are paused. Grants stay in place, but no agent can use them until you resume.{" "}
            <a href="#/access/settings">Open settings</a>
          </span>
        </p>
      )}
      {adding && (
        <form className="panel form" onSubmit={give} aria-label="Give an agent access">
          <h2>Give an agent access</h2>
          <div className="add">
            <label className="field">
              Agent
              <select name="agent" value={addAgent} onChange={(e) => setAddAgent(e.target.value)}>
                {agents.map((a) => (
                  <option key={a.name}>{a.name}</option>
                ))}
              </select>
            </label>
            <label className="field">
              Secret
              <select name="secret" disabled={freeSecrets.length === 0}>
                {freeSecrets.map((s) => (
                  <option key={s.id} value={s.id}>
                    {label(s)}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              Expires after
              <select name="expiry" defaultValue={defaultExpiry}>
                {EXPIRY.map(([l], i) => (
                  <option key={l} value={i}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            <button type="submit" className="btn primary" disabled={freeSecrets.length === 0}>
              Give access
            </button>
            <button
              type="button"
              className="btn quiet"
              onClick={() => {
                setAdding(false);
                setNotice(null);
              }}
            >
              Cancel
            </button>
          </div>
          {freeSecrets.length === 0 && <p className="hint">{addAgent} already has access to every secret.</p>}
          {notice && <Blocked why={notice} />}
          <p className="hint">The agent can ask the gateway to use the secret. It is never handed the value.</p>
        </form>
      )}
      <div className="toolbar">
        <label className="field">
          Agent
          <select value={agent} onChange={(e) => setAgent(e.target.value)}>
            <option value="all">All agents</option>
            {agents.map((a) => (
              <option key={a.name}>{a.name}</option>
            ))}
          </select>
        </label>
        <label className="field">
          Project
          <select value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="all">All projects</option>
            {projectIds.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
        </label>
        <fieldset className="seg inline">
          <legend className="sr-only">Quick filter</legend>
          <label>
            <input type="radio" name="gw-quick" checked={quick === "all"} onChange={() => setQuick("all")} />
            All<span className="n">{all.length}</span>
          </label>
          <label>
            <input type="radio" name="gw-quick" checked={quick === "none"} onChange={() => setQuick("none")} />
            No expiry<span className="n">{count((r) => r.expires === null)}</span>
          </label>
          <label>
            <input type="radio" name="gw-quick" checked={quick === "soon"} onChange={() => setQuick("soon")} />
            Expiring within a day<span className="n">{count((r) => r.expires !== null && r.expires - NOW <= DAY)}</span>
          </label>
        </fieldset>
      </div>
      {shown.length === 0 ? (
        <Empty icon="key">
          <b>{all.length === 0 ? "No agent has a grant." : "No grant matches these filters."}</b>{" "}
          {all.length === 0
            ? "Give an agent access to a secret to start. Until then the gateway uses nothing for it."
            : "Clear a filter to see more."}
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th>Agent</th>
                <th>Secret</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.flatMap((r) => [
                <tr key={r.key}>
                  <td className="mono strong">{r.agent}</td>
                  <td>
                    <a className="mono strong" href={`#/secrets/${r.project}`}>
                      {r.name}
                    </a>
                    <div className="muted small">
                      {r.project} / {r.env}
                    </div>
                  </td>
                  <td className={r.expires === null ? "prod" : ""}>{when(r.expires)}</td>
                  <td className="muted">{ago(r.last)}</td>
                  <td className="num">
                    <button
                      type="button"
                      className="btn sm quiet"
                      aria-expanded={editing === r.key}
                      aria-label={`Change expiry of ${r.agent} on ${r.name} in ${r.project}/${r.env}`}
                      onClick={() => {
                        setEditing(editing === r.key ? null : r.key);
                        setPick(
                          r.expires === null
                            ? EXPIRY.length - 1
                            : Math.max(
                                0,
                                EXPIRY.findIndex(([, v]) => v !== null && v >= r.expires! - NOW),
                              ),
                        );
                        setNotice(null);
                      }}
                    >
                      Change expiry
                    </button>
                    <button
                      type="button"
                      className="btn sm quiet danger-text"
                      aria-label={`Revoke ${r.agent} on ${r.name} in ${r.project}/${r.env}`}
                      onClick={() => revoke(r)}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>,
                editing === r.key && (
                  <tr key={`${r.key}-e`} className="detail">
                    <td colSpan={5}>
                      <form
                        className="gw-edit"
                        onSubmit={(e) => {
                          e.preventDefault();
                          change(r);
                        }}
                      >
                        <label className="muted small" htmlFor={`gw-exp-${r.key}`}>
                          Expires after
                        </label>
                        <select
                          id={`gw-exp-${r.key}`}
                          value={pick}
                          onChange={(e) => {
                            setPick(Number(e.target.value));
                            setNotice(null);
                          }}
                        >
                          {EXPIRY.map(([l], i) => (
                            <option key={l} value={i}>
                              {l} from now
                            </option>
                          ))}
                        </select>
                        <button type="submit" className="btn sm primary">
                          Save
                        </button>
                        <button
                          type="button"
                          className="btn sm quiet"
                          onClick={() => {
                            setEditing(null);
                            setNotice(null);
                          }}
                        >
                          Cancel
                        </button>
                        {notice && <Blocked why={notice} />}
                      </form>
                    </td>
                  </tr>
                ),
              ])}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------- Settings

const Row = ({ title, about, children }: { title: string; about: React.ReactNode; children: React.ReactNode }) => (
  <div className="set-row">
    <div>
      <b>{title}</b>
      <p>{about}</p>
    </div>
    <div className="set-ctl">{children}</div>
  </div>
);
const Pick = ({
  name,
  value,
  options,
  onChange,
}: {
  name: string;
  value: string;
  options: readonly string[];
  onChange: (v: string) => void;
}) => (
  <select aria-label={name} value={value} onChange={(e) => onChange(e.target.value)}>
    {options.map((o) => (
      <option key={o}>{o}</option>
    ))}
  </select>
);

// Agent Gateway settings: guardrails, the default grant length, the fixed session and redaction notes, and the pause switch.
function GatewaySettings({ say }: PageProps) {
  const [saved, setSaved] = useGw();
  const { paused, ...cur } = saved; // pausing saves at once, so it is not part of the form
  const [s, setS] = useState(cur);
  const dirty = JSON.stringify(s) !== JSON.stringify(cur);
  return (
    <form
      className="settings"
      onSubmit={(e) => {
        e.preventDefault();
        setSaved((g) => ({ ...g, ...s }));
        say("Gateway settings saved");
      }}
    >
      <Head
        title="Settings"
        sub="Guardrails for grants and blocked calls, how long a new grant lasts, and the pause switch."
      />
      <section className="panel" aria-labelledby="gw-guard">
        <h2 id="gw-guard">Guardrails</h2>
        <Row
          title="Access to production needs a second person"
          about="Giving or extending a grant on a production secret is refused until another admin does it."
        >
          <Switch
            label="Access to production needs a second person"
            checked={s.needSecond}
            onChange={(on) => setS({ ...s, needSecond: on })}
          />
        </Row>
        <Row
          title="Longest a grant may last"
          about="Grants cannot be given or extended past this. Grants that already exist are not changed."
        >
          <Pick
            name="Longest a grant may last"
            value={s.maxGrant}
            options={GRANT_MAX}
            onChange={(v) => setS({ ...s, maxGrant: GRANT_MAX.find((o) => o === v) ?? s.maxGrant })}
          />
        </Row>
        <Row title="When an agent calls a host that is not allowed" about="The secret is never sent in either case.">
          <Pick
            name="When an agent calls a host that is not allowed"
            value={s.onBlocked}
            options={["Block it", "Block it and tell an admin"]}
            onChange={(v) => setS({ ...s, onBlocked: v })}
          />
        </Row>
      </section>
      <section className="panel" aria-labelledby="gw-access">
        <h2 id="gw-access">Access</h2>
        <Row
          title="A new grant expires after"
          about="The starting value on the Grants page when someone gives an agent access. They can choose another at that time."
        >
          <Pick
            name="A new grant expires after"
            value={s.grantExpiry}
            options={["1 hour", "8 hours", "7 days", "No expiry"]}
            onChange={(v) => setS({ ...s, grantExpiry: v })}
          />
        </Row>
        <Row
          title="Session length"
          about="Every agent session lasts 15 minutes. A short session limits what a stolen token can do, and the agent asks again with no extra step."
        >
          <span className="fixed">15 minutes, fixed</span>
        </Row>
        <Row
          title="Remove the credential from responses"
          about="The gateway strips the credential and its common encodings from every response before the agent sees it. If it cannot be sure, it withholds the response."
        >
          <span className="fixed">Always on</span>
        </Row>
      </section>
      <section className="panel danger-zone" aria-labelledby="gw-pause">
        <h2 id="gw-pause">Pause all agents</h2>
        <p className="muted">
          Revokes every live session and stops new ones until you resume. Use it if you think an agent is doing
          something it should not. Secrets and grants are not changed, and people can still unlock and export.
        </p>
        <p style={{ margin: "12px 0 0" }}>
          {paused ? (
            <button
              type="button"
              className="btn primary"
              onClick={() => {
                setSaved((g) => ({ ...g, paused: false }));
                say("Agents resumed");
              }}
            >
              <Icon name="unlock" />
              Resume agents
            </button>
          ) : (
            <button
              type="button"
              className="btn danger"
              onClick={() => {
                setSaved((g) => ({ ...g, paused: true }));
                say("Agents paused");
              }}
            >
              <Icon name="lock" />
              Pause all agents
            </button>
          )}
          {paused && (
            <span className="gw-warn" role="status" style={{ display: "inline-flex", marginLeft: 12 }}>
              <Icon name="alert" />
              Paused. No agent can get a token.
            </span>
          )}
        </p>
      </section>
      {dirty && (
        <div className="savebar" role="status">
          <span>You have unsaved changes.</span>
          <button type="button" className="btn quiet" onClick={() => setS(cur)}>
            Discard
          </button>
          <button type="submit" className="btn primary">
            Save changes
          </button>
        </div>
      )}
    </form>
  );
}

export const pages: Pages = { "access/hosts": Hosts, "access/grants": Grants, "access/settings": GatewaySettings };
