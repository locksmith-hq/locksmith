import { Fragment, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Icon, Logo, VaultMark, type IconName } from "@locksmith/ui";
import * as seed from "./data";
import { Billing } from "./Billing";
import { Settings } from "./Settings";
import { PAGES } from "./pages";
import { useSecrets } from "./pages/gateway-data";
import { useNotices } from "./pages/platform-store";
import "./settings.css";
import { NOW } from "@locksmith/ui";
import { type Agent, type Secret, type Session } from "./data";

const pad = (n: number) => String(n).padStart(2, "0");
const clock = (ts: number) => { const d = new Date(ts * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const plural = (n: number, w: string) => `${n} ${n === 1 ? w : `${w}s`}`;
const ago = (ts: number | null) => {
  if (ts === null) return "never";
  const s = NOW - ts;
  return s < 60 ? "just now" : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`;
};
const left = (s: number) => (s < 60 ? `${s}s` : `${Math.floor(s / 60)}m`);
const until = (ts: number | null) =>
  ts === null ? "no expiry" : ts - NOW < 86400 ? `expires in ${Math.ceil((ts - NOW) / 3600)}h` : `expires in ${Math.ceil((ts - NOW) / 86400)}d`;
const EXPIRY: [string, number | null][] = [["1 hour", 3600], ["8 hours", 8 * 3600], ["7 days", 7 * 86400], ["No expiry", null]];

function useRoute() {
  const read = () => location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  const [r, setR] = useState(read);
  useEffect(() => {
    const f = () => setR(read());
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);
  return r;
}

type Appearance = "system" | "light" | "dark";
const APPEARANCE: [Appearance, string, IconName][] = [["system", "System", "monitor"], ["light", "Light", "sun"], ["dark", "Dark", "moon"]];
function useAppearance() {
  const [pref, setPref] = useState<Appearance>("system");
  useLayoutEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => { document.documentElement.dataset.theme = pref === "system" ? (mq.matches ? "dark" : "light") : pref; };
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, [pref]);
  return [pref, setPref] as const;
}

const Chevrons = () => <svg className="i sel" viewBox="0 0 16 16" aria-hidden="true"><path d="M5 6.5l3-3 3 3M5 9.5l3 3 3-3" /></svg>;
const Check = () => <svg className="i tick" viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7" /></svg>;
/** Closes a `<details>` selector on Escape or when focus leaves it. */
const dismiss = {
  onKeyDown: (e: React.KeyboardEvent<HTMLDetailsElement>) => { if (e.key === "Escape") e.currentTarget.open = false; },
  onBlur: (e: React.FocusEvent<HTMLDetailsElement>) => { if (!e.currentTarget.contains(e.relatedTarget)) e.currentTarget.open = false; },
};

const me = seed.members[0]!;
const AppearanceSeg = ({ name, value, set }: { name: string; value: Appearance; set: (a: Appearance) => void }) => (
  <fieldset className="seg">
    <legend className="sr-only">Appearance</legend>
    {APPEARANCE.map(([v, label, icon]) => (
      <label key={v} title={`Appearance: ${label}`}>
        <input type="radio" name={name} checked={value === v} onChange={() => set(v)} />
        <Icon name={icon} />{label}
      </label>
    ))}
  </fieldset>
);

function Account({ appearance, setAppearance }: { appearance: Appearance; setAppearance: (a: Appearance) => void }) {
  return (
    <section>
      <Head title="User settings" sub="These follow you across every workspace you belong to." />
      <form className="panel form" onSubmit={(e) => e.preventDefault()}>
        <h2>Profile</h2>
        <div className="add">
          <label className="field">Name<input defaultValue={me.name} autoComplete="name" /></label>
          <label className="field">Email<input defaultValue={me.email} readOnly style={{ width: 260 }} /></label>
          <button type="submit" className="btn">Save</button><span />
        </div>
      </form>
      <div className="panel form">
        <h2>Appearance</h2>
        <p className="muted">System follows your computer's light or dark setting.</p>
        <div style={{ maxWidth: 280, marginTop: 12 }}><AppearanceSeg name="appearance-page" value={appearance} set={setAppearance} /></div>
      </div>
      <div className="panel">
        <h2>Sign out</h2>
        <p className="muted">Ends this browser's session. Agents and their grants are not affected.</p>
        <button type="button" className="btn" style={{ marginTop: 12 }}>Sign out</button>
      </div>
    </section>
  );
}

/** A product stops being "Planned" once its first page exists, either built in or in ./pages. */
const built = (p: seed.Product) => !!p.href || !!PAGES[`${p.id}/${seed.spaces[p.id]?.[0]?.[0]}`];
/** The wordmark: the product's own typeface in spaced capitals. */
const Word = () => <span className="wordmark" aria-label="Locksmith" style={{ fontWeight: 600, letterSpacing: "0.13em", textTransform: "uppercase", fontSize: "1.02em" }}>locksmith</span>;

/** Loading state: the small mark, its dial turning one notch at a time while the bolts draw in and out (all CSS). */
const Loader = () => (
  <div className="loader" role="status"><span className="logo"><VaultMark small size={42} /></span><span className="sr-only">Loading</span></div>
);

/** Picks who the console is working for: one person, or an organization with members and teams. */
function Workspace({ at, pick }: { at: number; pick: (i: number) => void }) {
  const ref = useRef<HTMLDetailsElement>(null);
  const close = () => { ref.current!.open = false; };
  const w = seed.workspaces[at]!;
  return (
    <details className="ws" ref={ref} {...dismiss}>
      <summary className="org" title="Switch workspace"><span className="av">{w.name[0]}</span><span>{w.name}<small>{w.org ? "Organization" : "Personal"}</small></span><Chevrons /></summary>
      <div className="ws-menu">
        {seed.workspaces.map((x, i) => (
          <button key={x.name} type="button" aria-current={i === at || undefined} onClick={() => { pick(i); close(); }}>
            <span className="av">{x.name[0]}</span><span>{x.name}<small>{x.sub}</small></span>{i === at && <Check />}
          </button>
        ))}
        <a href="#/welcome" onClick={close}><span className="av"><Icon name="plus" /></span>New workspace</a>
      </div>
    </details>
  );
}

interface Acl {
  viewer: (typeof seed.members)[number]; isAdmin: boolean;
  pm: typeof seed.projectMembers; setPm: React.Dispatch<React.SetStateAction<typeof seed.projectMembers>>;
  roleIn: (projectId: string) => seed.ProjectRole | undefined;
  /** Mockup only: look at the console as another member to see what they would see. */
  preview: (memberIndex: number) => void;
}

interface Db {
  sessions: Session[]; secrets: Secret[]; agents: Agent[]; paused: boolean;
  revoke: (ids: string[]) => void; pause: () => void; resume: () => void;
  setSecrets: React.Dispatch<React.SetStateAction<Secret[]>>;
  setAgents: React.Dispatch<React.SetStateAction<Agent[]>>;
  say: (note: string) => void;
}

export function Console() {
  const route = useRoute();
  const [appearance, setAppearance] = useAppearance();
  const [sessions, setSessions] = useState(seed.sessions);
  // One copy of secrets and grants for the whole console, shared with the Grants, Policies and Overview pages.
  const [secrets, setSecrets] = useSecrets();
  const [agents, setAgents] = useState(seed.agents);
  const [paused, setPaused] = useState(false);
  const [note, say] = useState("");
  const [at, setAt] = useState(1);
  const ws = seed.workspaces[at]!;
  const live = sessions.filter((s) => s.state === "active");
  const page = route[0] ?? "home";
  // Folded sidebar: an icon-only rail. Remembered per browser; the page works the same if storage is blocked.
  const [folded, setFolded] = useState(() => { try { return localStorage.getItem("locksmith.mock.folded") === "1"; } catch { return false; } });
  const fold = () => setFolded((f) => { try { localStorage.setItem("locksmith.mock.folded", f ? "0" : "1"); } catch { /* keep it for this page only */ } return !f; });
  // shortcut: the mockup has no data to wait for, so every page change waits a fixed second to show the loading state (?load=5000 tries a slow one).
  const where = route.join("/");
  const [loaded, setLoaded] = useState("");
  useEffect(() => { const t = setTimeout(() => setLoaded(where), Number(new URLSearchParams(location.search).get("load")) || 1000); return () => clearTimeout(t); }, [where]);
  const unread = useNotices()[0].filter((n) => !n.read).length;
  const HubPage = PAGES[`hub/${page}`];
  const [planOf, setPlanOf] = useState(["Free", "Team"]); // one subscription per workspace
  const [viewerAt, preview] = useState(0);
  const [pm, setPm] = useState(seed.projectMembers);
  const viewer = seed.members[viewerAt]!;
  const isAdmin = viewer.role === "Owner" || viewer.role === "Admin";
  const acl: Acl = { viewer, isAdmin, pm, setPm, preview, roleIn: (pid) => (isAdmin ? "Admin" : pm[pid]?.[viewer.email]) };
  // A project the viewer cannot open is treated exactly like one that does not exist.
  const proj = page === "secrets" ? seed.projects.find((p) => p.id === route[1] && acl.roleIn(p.id)) : undefined;
  const own = proj ? secrets.filter((x) => x.project === proj.id) : secrets;
  // A product is its own space with its own sidebar. Secrets needs a project first; planned products only have placeholders.
  const product = page === "access" ? "access" : proj ? "secrets" : page === "app" && seed.spaces[route[1] ?? ""] ? route[1]! : undefined;
  // The product's own front door (no project open yet): Projects and Secret sharing.
  const lobby = !product && (page === "secrets" || page === "sharing" || page === "sm");
  const lobbyTab = page === "secrets" ? "projects" : page === "sharing" ? "sharing" : route[1] ?? "";
  const crumbProduct = product ?? (lobby ? "secrets" : undefined);
  // Members and Settings of a project are for its admins only.
  const items = (product ? seed.spaces[product]! : []).filter(([t]) => !proj || !["members", "machines", "settings"].includes(t) || acl.roleIn(proj.id) === "Admin");
  const base = product === "access" ? "#/access" : product === "secrets" ? `#/secrets/${route[1]}` : `#/app/${product}`;
  const tab = (product === "access" ? route[1] : route[2]) ?? items[0]?.[0] ?? "";
  const link = (id: string, label: string, icon: IconName, count?: number) => (
    <a key={id} href={`#/${id}`} title={label} aria-current={route.join("/").startsWith(id) || (id === "home" && !route.length) ? "page" : undefined}>
      <Icon name={icon} />{label}{count !== undefined && <span className="count">{count}</span>}
    </a>
  );

  const revoke = (ids: string[]) => {
    setSessions((ss) => ss.map((s) => (ids.includes(s.id) ? { ...s, state: "revoked", endedAt: NOW } : s)));
    say(`Revoked ${plural(ids.length, "session")}`);
  };
  const pause = () => {
    revoke(live.map((s) => s.id));
    setPaused(true);
    say("");
  };
  const resume = () => { setPaused(false); say("Agents resumed"); };
  const db: Db = { sessions, secrets, agents, paused, revoke, pause, resume, setSecrets, setAgents, say };

  return (
    <div className="app" data-folded={folded || undefined}>
      <aside className="side">
        <a className="brand" href="#/home" aria-label="Locksmith home"><Logo size={34} /><Word /></a>
        {product ? (
          <>
            <nav className="nav" aria-label={seed.products.find((x) => x.id === product)!.name}>
              {items.map(([t, label, icon, group], i) => (
                <Fragment key={t}>
                  {group && group !== items[i - 1]?.[3] && <p className="nav-h">{group}</p>}
                  <a href={`${base}/${t}`} title={label} aria-current={tab === t ? "page" : undefined}>
                    <Icon name={icon} />{label}
                    {t === "secrets" && <span className="count">{own.length}</span>}
                    {product === "access" && t === "sessions" && <span className="count">{live.length}</span>}
                  </a>
                </Fragment>
              ))}
            </nav>
          </>
        ) : lobby ? (
          <nav className="nav" aria-label="Secret Management">
            {seed.spaces["secrets-lobby"]!.map(([t, label, icon]) => (
              <a key={t} href={t === "projects" ? "#/secrets" : t === "sharing" ? "#/sharing" : `#/sm/${t}`} title={label} aria-current={lobbyTab === t ? "page" : undefined}>
                <Icon name={icon} />{label}
                {t === "projects" && <span className="count">{seed.projects.filter((x) => acl.roleIn(x.id)).length}</span>}
              </a>
            ))}
          </nav>
        ) : (
          <>
        <nav className="nav" aria-label="Main">
          {link("home", "Home", "grid")}
          {link("notifications", "Notifications", "alert", unread || undefined)}
          {link("integrations", "Integrations", "s_code")}
          {link("mcp", "MCP", "s_terminal")}
          {isAdmin && <>
          <p className="nav-h">Administration</p>
          {ws.org && link("members", "User Management", "sessions", seed.members.length)}
          {link("billing", "Usage and billing", "clock")}
          {link("settings", "Settings", "s_window")}
          </>}
        </nav>
          </>
        )}
        <div className="side-foot">
          <details className="ws user" {...dismiss}>
            <summary className="org" title="Your account"><span className="av">{me.name[0]}</span><span>{me.name}<small>{me.email}</small></span><Chevrons /></summary>
            <div className="ws-menu">
              <a href="#/account" onClick={(e) => { e.currentTarget.closest("details")!.open = false; }}><span className="av"><Icon name="sessions" /></span>User settings</a>
              <AppearanceSeg name="appearance-menu" value={appearance} set={setAppearance} />
              <button type="button"><span className="av"><Icon name="power" /></span>Sign out</button>
            </div>
          </details>
        </div>
      </aside>

      <div className="work">
        <header className="vault" aria-label={proj ? "Project" : "Workspace"} data-paused={paused}>
          <button type="button" className="fold" aria-pressed={folded} aria-label={folded ? "Show sidebar" : "Hide sidebar"} title={folded ? "Show sidebar" : "Hide sidebar"} onClick={fold}>
            <svg className="i" viewBox="0 0 16 16" aria-hidden="true"><rect x="2" y="3" width="12" height="10" rx="1.75" /><path d="M6 3v10" /></svg>
          </button>
          <nav className="crumbbar" aria-label="Breadcrumb">
            {crumbProduct && <ProductSwitch id={crumbProduct} />}
            {proj ? <><i aria-hidden="true">/</i><ProjectSwitch id={proj.id} tab={tab} can={(pid) => !!acl.roleIn(pid)} /></> : lobby && <><i aria-hidden="true">/</i><span>{seed.spaces["secrets-lobby"]!.find(([t]) => t === lobbyTab)?.[1]}</span></>}
            {product && <><i aria-hidden="true">/</i><span>{items.find(([t]) => t === tab)?.[1]}</span></>}
          </nav>
          <div className="vault-line" aria-live="polite" aria-atomic="true">
            {paused && <b className="vault-state"><span className="dot" aria-hidden="true" />Agents paused</b>}
            {paused && <span className="vault-meta"><span>No token is issued until you resume</span></span>}
            {note && <span className="vault-note">{note}</span>}
            {viewerAt !== 0 && <span className="previewing">Previewing as {viewer.name} · {viewer.role}</span>}
          </div>
          <div className="acts">
            {viewerAt !== 0 && <button type="button" className="btn sm" onClick={() => preview(0)}>Stop preview</button>}
            {paused && <button type="button" className="btn primary" onClick={resume}><Icon name="unlock" />Resume agents</button>}
            <a className="bell" href="#/notifications" aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"} title="Notifications">
              <svg className="i" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 11V7.5a4 4 0 0 1 8 0V11l1.25 1.5H2.75z" /><path d="M6.5 14a1.6 1.6 0 0 0 3 0" /></svg>
              {unread > 0 && <span className="bell-n">{unread}</span>}
            </a>
            <Workspace at={at} pick={setAt} />
          </div>
        </header>
        <main aria-busy={loaded !== where}>
          {loaded !== where ? <Loader /> : page === "secrets" ? (route[1] ? <Project db={db} acl={acl} id={route[1]} tab={proj ? tab : undefined} env={route[3]} /> : <Projects db={db} acl={acl} />)
            : page === "access" ? (
              tab === "agents" ? <Agents db={db} />
                : tab === "activity" ? <section><Head title="Activity" sub="Every request the gateway relayed or blocked for this workspace's agents." /><Log events={seed.events} /></section>
                : tab === "sessions" ? <Overview db={db} />
                : <Soon id="access" tab={tab} sub={route[2]} say={say} />)
            : HubPage ? <HubPage sub={route[1]} say={say} />
            : page === "billing" ? <Billing ws={at} name={ws.name} plan={planOf[at]!} setPlan={(p) => { setPlanOf((x) => x.map((v, i) => (i === at ? p : v))); say(`${ws.name} is now on ${p}`); }} />
            : page === "settings" ? <Settings key={ws.name} name={ws.name} org={ws.org} say={say} />
            : page === "integrations" ? <Integrations say={say} />
            : page === "sharing" ? <Sharing say={say} />
            : page === "sm" ? <Soon id="secrets" tab={route[1]} space="secrets-lobby" sub={route[2]} say={say} />
            : page === "members" ? <Members acl={acl} tab={route[1]} />
            : page === "account" ? <Account appearance={appearance} setAppearance={setAppearance} />
            : page === "app" ? <Soon id={route[1]} tab={product ? tab : undefined} sub={route[3]} say={say} />
            : page === "welcome" ? <Welcome pick={setAt} />
            : <Hub db={db} org={ws.org} name={ws.name} />}
        </main>
      </div>
    </div>
  );
}

const Head = ({ title, sub, children }: { title: string; sub?: React.ReactNode; children?: React.ReactNode }) => (
  <div className="screen-head">
    <div><h1>{title}</h1>{sub && <p className="lede">{sub}</p>}</div>
    {children}
  </div>
);
function Hub({ db, org, name }: { db: Db; org: boolean; name: string }) {
  const live = db.sessions.filter((s) => s.state === "active").length;
  const stats: Record<string, [number | string, string][]> = {
    secrets: [[db.secrets.length, "secrets"], [new Set(db.secrets.map((s) => s.project + s.env)).size, "environments"], [seed.projects.length, "projects"]],
    access: [[db.agents.length, "agents"], [live, "live sessions"], [db.secrets.reduce((n, s) => n + s.grants.length, 0), "grants"]],
  };
  const groups = [...new Set(seed.products.map((p) => p.group))];
  return (
    <section className="hub">
      <Head title={org ? `${name} home` : "Your home"}
        sub={org ? "Every Locksmith product for your organization. Members and teams share this view." : "Every Locksmith product for your own work. Only you can see this workspace."} />
      {groups.map((g, i) => (
        <Fragment key={g}>
          {groups.length > 1 && <div className={i ? "sec-h spaced" : "sec-h"}><h2>{g}</h2></div>}
          <div className="hub-grid">
            {seed.products.filter((p) => p.group === g).map((p) => (
              <a key={p.id} className="pcard" href={p.href ?? `#/app/${p.id}`} data-planned={!built(p) || undefined}>
                <span className="pic" data-tint={p.tint}><Icon name={p.icon} /></span>
                <span className="pname">{p.name}{!built(p) && <span className="badge">Planned</span>}</span>
                <span className="pblurb">{p.blurb}</span>
                {stats[p.id] && <span className="pstats">{stats[p.id]!.map(([n, l]) => <span key={l}><b>{n}</b> {l}</span>)}</span>}
              </a>
            ))}
          </div>
        </Fragment>
      ))}
    </section>
  );
}

function Soon({ id, tab, space, project, sub, say }: { id?: string; tab?: string; space?: string; project?: string; sub?: string; say: (note: string) => void }) {
  const p = [...seed.products, ...seed.extras].find((x) => x.id === id);
  if (!p) return <p className="state">No such product. <a href="#/home">Back to home</a></p>;
  const key = space ?? p.id;
  const Page = PAGES[`${key}/${tab}`];
  if (Page) return <Page project={project} sub={sub} say={say} />;
  const item = seed.spaces[key]?.find(([t]) => t === tab);
  const what = item ? `${item[1]} in ${p.name}` : p.name;
  return (
    <section>
      <Head title={item ? item[1] : p.name} sub={seed.about[`${key}/${tab}`] ?? p.blurb} />
      <div className="state empty"><span className="state-ic"><Icon name={item ? item[2] : p.icon} /></span>
        <div><b>{what} is planned and not available yet.</b> There is nothing to set up today.</div>
      </div>
    </section>
  );
}

function Integrations({ say }: { say: (note: string) => void }) {
  const [rows, setRows] = useState(seed.connections);
  const [kind, setKind] = useState<seed.Kind | "All">("All");
  const [adding, setAdding] = useState(false);
  const [newKind, setNewKind] = useState<seed.Kind>("Source and CI");
  const [removing, setRemoving] = useState<string | null>(null);
  const shown = rows.filter((c) => kind === "All" || c.kind === kind);
  const add = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setRows((r) => [...r, { id: `c_new${r.length}`, kind: newKind, provider: String(f.get("provider")), name: String(f.get("name")), icon: "relay", uses: [], scope: String(f.get("scope")) }]);
    say(`Connected ${f.get("name")}`);
    setAdding(false);
  };
  const remove = (c: seed.Connection) => { setRows((r) => r.filter((x) => x !== c)); setRemoving(null); say(`Removed ${c.name}`); };
  return (
    <section>
      <Head title="Integrations" sub="Connections to the systems outside Locksmith. Set one up here once; each product then picks it from a list.">
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding}><Icon name="plus" />Add connection</button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add connection">
          <h2>Add a connection</h2>
          <div className="add share">
            <label className="field">Kind<select value={newKind} onChange={(e) => setNewKind(e.target.value as seed.Kind)}>{seed.kinds.map((k) => <option key={k}>{k}</option>)}</select></label>
            <label className="field">System<select name="provider" key={newKind}>{seed.providers[newKind].map((p) => <option key={p}>{p}</option>)}</select></label>
            <label className="field">Name<input name="name" required autoFocus placeholder="Staging account" autoComplete="off" /></label>
            <label className="field">Who may use it<select name="scope"><option>All projects</option>{seed.projects.map((p) => <option key={p.id}>{p.id}</option>)}</select></label>
            <button type="submit" className="btn primary">Connect</button>
            <button type="button" className="btn quiet" style={{ justifySelf: "start" }} onClick={() => setAdding(false)}>Cancel</button>
          </div>
          <p className="hint">The next step signs you in to that system. Its credential is kept as a Locksmith secret and rotated like any other; nobody sees it here.</p>
        </form>
      )}
      <div className="toolbar">
        <fieldset className="seg inline">
          <legend className="sr-only">Kind</legend>
          {(["All", ...seed.kinds] as const).map((k) => (
            <label key={k}><input type="radio" name="kind" checked={kind === k} onChange={() => setKind(k)} />{k}{k !== "All" && <span className="n">{rows.filter((c) => c.kind === k).length}</span>}</label>
          ))}
        </fieldset>
      </div>
      {shown.length === 0 ? (
        <div className="state empty"><span className="state-ic"><Icon name="relay" /></span><div><b>No {kind === "All" ? "" : `${kind.toLowerCase()} `}connections yet.</b> Add one, then pick it from inside a product.</div></div>
      ) : (
        <ul className="list conns">
          {shown.map((c) => (
            <li key={c.id} className="row">
              <span className="ic">{c.icon === "s_claude" ? <span className="src-claude"><Icon name="s_claude" /></span> : <Icon name={c.icon} />}</span>
              <div>
                <b>{c.name}</b> <span className="muted small">{c.provider} · {c.kind}</span>
                <p>{c.uses.length === 0 ? "Not used by any product yet." : c.uses.map(([p, what]) => <span key={p} className="use"><b>{p}</b> {what}</span>)}</p>
                {c.problem && <p className="warn"><Icon name="alert" />{c.problem}</p>}
                {removing === c.id && (
                  <p className="alert" role="alert" style={{ margin: "10px 0 0" }}>
                    Removing this stops {c.uses.map(([p, what]) => `${what} in ${p}`).join(", ")}.
                    <button type="button" className="btn sm danger" onClick={() => remove(c)}>Remove anyway</button>
                    <button type="button" className="btn sm quiet" onClick={() => setRemoving(null)}>Keep</button>
                  </p>
                )}
              </div>
              <span className="meta">
                <span title="Which projects may pick this connection">{c.scope}</span>
                <button type="button" className="btn sm quiet danger-text" aria-label={`Remove ${c.name}`} onClick={() => (c.uses.length ? setRemoving(c.id) : remove(c))}>Remove</button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Sharing({ say }: { say: (note: string) => void }) {
  const [rows, setRows] = useState(seed.shares);
  const [adding, setAdding] = useState(false);
  const [once, setOnce] = useState<string | null>(null);
  const create = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const id = `shr_new${rows.length}`;
    // The value field is dropped on purpose: the mockup never keeps what was typed.
    setRows((r) => [{ id, label: String(f.get("label")), by: me.name, created: NOW, expires: NOW + Number(f.get("ttl")), views: 0, maxViews: Number(f.get("views")) }, ...r]);
    setOnce(id);
    setAdding(false);
  };
  return (
    <section>
      <Head title="Secret sharing" sub="Hand one secret to a person outside this workspace through a link that expires and counts its views. Agents never get these links.">
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding}><Icon name="plus" />Share a secret</button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={create} aria-label="Share a secret">
          <h2>Share a secret</h2>
          <div className="add share">
            <label className="field">What it is<input name="label" required autoFocus placeholder="Staging DB password for Sam" autoComplete="off" style={{ width: 300 }} /></label>
            <label className="field">Value<input name="value" type="password" required autoComplete="off" placeholder="Paste the value" /></label>
            <label className="field">Expires after<select name="ttl" defaultValue={86400}><option value={3600}>1 hour</option><option value={86400}>1 day</option><option value={604800}>7 days</option></select></label>
            <label className="field">Can be opened<select name="views" defaultValue={1}><option value={1}>Once</option><option value={5}>5 times</option></select></label>
            <button type="submit" className="btn primary">Create link</button>
            <button type="button" className="btn quiet" onClick={() => setAdding(false)}>Cancel</button>
          </div>
          <p className="hint">The value is encrypted in this browser and the key travels only inside the link, so Locksmith cannot read it. After the last view or the expiry, the link shows nothing.</p>
        </form>
      )}
      {once && (
        <div className="panel once" role="status">
          <h2>Copy the link now</h2>
          <p>It is shown once. Anyone with the link can open the secret until it expires or runs out of views.</p>
          <code className="block">https://share.locksmith.example/s/{once}#sample-key-not-real</code>
          <button type="button" className="btn sm" style={{ marginTop: 12 }} onClick={() => setOnce(null)}>I have copied it</button>
        </div>
      )}
      {rows.length === 0 ? (
        <div className="state empty"><span className="state-ic"><Icon name="arrow" /></span><div><b>No active links.</b> Share a secret to send one to someone who is not in this workspace.</div></div>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Shared secret</th><th>Created by</th><th>Created</th><th>Expires</th><th>Opened</th><th /></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="strong">{r.label}</td><td>{r.by}</td><td className="muted">{ago(r.created)}</td><td>{until(r.expires).replace("expires ", "")}</td>
                  <td className="mono">{r.views} of {r.maxViews}</td>
                  <td className="num"><button type="button" className="btn sm quiet danger-text" aria-label={`Revoke link: ${r.label}`} onClick={() => { setRows((x) => x.filter((y) => y !== r)); say("Link revoked"); }}>Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function Members({ acl, tab }: { acl: Acl; tab?: string }) {
  const at = tab === "groups" || tab === "roles" ? tab : "users";
  const roles = seed.roles;
  const [users, setUsers] = useState(() => seed.members.map((m, i) => ({ ...m, i, invited: false })));
  const [inviting, setInviting] = useState(false);
  const elevated = (role: string) => roles.find((r) => r.name === role)?.can.includes("sm.all");
  const projectsOf = (u: (typeof users)[number]) =>
    elevated(u.role) ? "All projects" : seed.projects.filter((p) => acl.pm[p.id]?.[u.email]).map((p) => p.id).join(", ") || "None yet";
  const invite = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const email = String(f.get("email")).trim();
    setUsers((us) => [...us, { name: email.split("@")[0]!, email, role: String(f.get("role")), team: String(f.get("group")), seen: NOW, i: -1, invited: true }]);
    setInviting(false);
  };
  return (
    <section>
      <Head title="User Management" sub="Who is in this organization, what their role lets them do, and which projects they can open.">
        {at === "users" && <button type="button" className="btn primary" onClick={() => setInviting(true)} disabled={inviting}><Icon name="plus" />Invite user</button>}
      </Head>
      <nav className="tabs" aria-label="User Management">
        <a href="#/members" aria-current={at === "users" ? "page" : undefined}>Users <span className="n">{users.length}</span></a>
        <a href="#/members/groups" aria-current={at === "groups" ? "page" : undefined}>Groups <span className="n">{seed.groups.length}</span></a>
        <a href="#/members/roles" aria-current={at === "roles" ? "page" : undefined}>Roles</a>
      </nav>

      {at === "users" && <>
        {inviting && (
          <form className="panel form" onSubmit={invite} aria-label="Invite user">
            <h2>Invite a user</h2>
            <div className="add share">
              <label className="field">Email<input name="email" type="email" required autoFocus placeholder="name@acme.example" autoComplete="off" style={{ width: 260 }} /></label>
              <label className="field">Role<select name="role" defaultValue="Member">{roles.map((r) => <option key={r.name}>{r.name}</option>)}</select></label>
              <label className="field">Group<select name="group">{seed.groups.map((g) => <option key={g.name}>{g.name}</option>)}</select></label>
              <span />
              <button type="submit" className="btn primary">Send invite</button>
              <button type="button" className="btn quiet" style={{ justifySelf: "start" }} onClick={() => setInviting(false)}>Cancel</button>
            </div>
            <p className="hint">They get an email with a link. Until they accept, they are listed as invited and can open nothing.</p>
          </form>
        )}
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>User</th><th>Role</th><th>Group</th><th>Projects</th><th>Status</th><th /></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.email}>
                  <td><span className="strong">{u.name}</span><br /><span className="mono muted">{u.email}</span></td>
                  <td>{u.i === 0 ? "Owner" : (
                    <select aria-label={`Role of ${u.name}`} value={u.role} onChange={(e) => setUsers((us) => us.map((x) => (x === u ? { ...x, role: e.target.value } : x)))}>
                      {roles.map((r) => <option key={r.name}>{r.name}</option>)}
                    </select>
                  )}</td>
                  <td>{u.team}</td>
                  <td className={elevated(u.role) ? "muted" : undefined}>{u.invited ? <span className="muted">After they accept</span> : projectsOf(u)}</td>
                  <td>{u.invited ? <span className="badge" data-by="agent">Invited</span> : <span className="muted">Active {ago(u.seen)}</span>}</td>
                  <td className="num nowrap">
                    {u.i > 0 && <button type="button" className="btn sm" title="See the console as this person sees it" onClick={() => { acl.preview(u.i); location.hash = "#/secrets"; }}>Preview as</button>}
                    {u.i !== 0 && <button type="button" className="btn sm quiet danger-text" aria-label={`${u.invited ? "Cancel invite for" : "Remove"} ${u.name}`} onClick={() => setUsers((us) => us.filter((x) => x !== u))}>{u.invited ? "Cancel invite" : "Remove"}</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </>}

      {at === "groups" && <>
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Group</th><th>Members</th><th>Projects the group can open</th></tr></thead>
            <tbody>
              {seed.groups.map((g) => (
                <tr key={g.name}>
                  <td><span className="strong">{g.name}</span><br /><span className="muted">{g.about}</span></td>
                  <td>{users.filter((u) => u.team === g.name).map((u) => u.name).join(", ")}</td>
                  <td className="mono">{g.projects}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="hint">Add a group to a project and everyone in the group gets that access. Remove a person from the group and they lose it.</p>
      </>}

      {at === "roles" && <>
        <div className="table-wrap">
          <table className="grid matrix">
            <thead>
              <tr>
                <th>Permission</th>
                {roles.map((r) => <th key={r.name}>{r.name}</th>)}
              </tr>
            </thead>
            <tbody>
              {seed.permissions.map(([area, key, label], i) => (
                <Fragment key={key}>
                  {area !== seed.permissions[i - 1]?.[0] && <tr className="area"><th colSpan={roles.length + 1} scope="colgroup">{area}</th></tr>}
                  <tr>
                    <td>{label}</td>
                    {roles.map((r) => (
                      <td key={r.name}>{r.can.includes(key) ? <span className="yes">Yes</span> : <span className="muted">No</span>}</td>
                    ))}
                  </tr>
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        <p className="hint">These three roles are fixed. They cover the organization; what someone may do inside one project is set by their role on that project's Members page.</p>
      </>}
    </section>
  );
}

const ROLES: seed.ProjectRole[] = ["Admin", "Developer", "Viewer"];
function ProjectMembers({ acl, id }: { acl: Acl; id: string }) {
  const here = acl.pm[id] ?? {};
  const set = (email: string, role?: seed.ProjectRole) => acl.setPm((pm) => {
    const next = { ...pm[id] };
    if (role) next[email] = role; else delete next[email];
    return { ...pm, [id]: next };
  });
  const admins = seed.members.filter((m) => m.role !== "Member");
  const added = seed.members.filter((m) => here[m.email]);
  const free = seed.members.filter((m) => m.role === "Member" && !here[m.email]);
  return (
    <section>
      <Head title="Members" sub={`People who can open ${id}. Admins manage members and settings, developers change secrets and grants, viewers only read names and activity.`} />
      <div className="table-wrap">
        <table className="grid">
          <thead><tr><th>Name</th><th>Email</th><th>Role in this project</th><th /></tr></thead>
          <tbody>
            {added.map((m) => (
              <tr key={m.email}>
                <td className="strong">{m.name}</td><td className="mono">{m.email}</td>
                <td><select aria-label={`Role of ${m.name}`} value={here[m.email]} onChange={(e) => set(m.email, e.target.value as seed.ProjectRole)}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select></td>
                <td className="num"><button type="button" className="btn sm quiet danger-text" aria-label={`Remove ${m.name} from ${id}`} onClick={() => set(m.email)}>Remove</button></td>
              </tr>
            ))}
            {admins.map((m) => (
              <tr key={m.email}><td className="strong">{m.name}</td><td className="mono">{m.email}</td><td className="muted">Admin, as organization {m.role.toLowerCase()}</td><td /></tr>
            ))}
          </tbody>
        </table>
      </div>
      {free.length > 0 && (
        <form className="inline-form" style={{ marginTop: 16 }} onSubmit={(e) => { e.preventDefault(); const f = new FormData(e.currentTarget); set(String(f.get("who")), f.get("role") as seed.ProjectRole); }}>
          <select name="who" aria-label="Member">{free.map((m) => <option key={m.email} value={m.email}>{m.name}</option>)}</select>
          <select name="role" aria-label="Role" defaultValue="Developer">{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
          <button type="submit" className="btn sm">Add to project</button>
        </form>
      )}
    </section>
  );
}

const WHO = ["Just me", "My team or organization"];
function Welcome({ pick }: { pick: (i: number) => void }) {
  const [who, setWho] = useState(0);
  return (
    <form className="welcome" onSubmit={(e) => { e.preventDefault(); pick(who); location.hash = "#/home"; }}>
      <Head title="Create a workspace" sub="A workspace holds your projects, agents and people. You can add people later, so start with whichever fits today." />
      <fieldset className="seg inline">
        <legend className="sr-only">Who is this workspace for</legend>
        {WHO.map((w, i) => <label key={w}><input type="radio" name="who" checked={who === i} onChange={() => setWho(i)} />{w}</label>)}
      </fieldset>
      <div className="add" style={{ margin: "16px 0 20px", gridTemplateColumns: "auto 1fr" }}>
        <label className="field">{who === 0 ? "Workspace name" : "Organization name"}<input required autoFocus placeholder={who === 0 ? "Tomer" : "Acme"} autoComplete="off" /></label>
      </div>
      <button type="submit" className="btn primary">Create workspace</button>
    </form>
  );
}

const AgentIcon =({ a }: { a?: Agent }) =>
  a?.icon === "s_claude" ? <span className="src-claude"><Icon name="s_claude" /></span> : <Icon name={a?.icon ?? "s_unknown"} />;

function Overview({ db }: { db: Db }) {
  const [striking, setStriking] = useState<string | null>(null);
  const live = db.sessions.filter((s) => s.state === "active").sort((a, b) => a.expires - b.expires);
  const ended = db.sessions.filter((s) => s.state !== "active");
  const span = 900 * 1.06;
  const ticks = [300, 600, 900].map((t) => Math.floor(NOW / 300) * 300 + t).filter((t) => (t - NOW) / span > 0.12 && (t - NOW) / span < 0.95);
  const x = (t: number) => `${(Math.max(0, t - NOW) / span) * 100}%`;
  const grid = ticks.map((t) => <i key={t} className="tick" style={{ left: x(t) }} />);
  const agentOf = (name: string) => db.agents.find((a) => a.name === name);
  const who = (s: Session) => (
    <span className="who">
      <span className="who-1"><AgentIcon a={agentOf(s.agent)} /><span className="who-name">{s.agent}</span><span className="mono id">{s.id}</span></span>
      <span className="who-2">{s.project} / <span className={s.env === "production" ? "prod" : undefined}>{s.env}</span> · {agentOf(s.agent)?.machine ?? "removed agent"}</span>
    </span>
  );
  const names = (s: Session) => <ul className="scopes-t mono" aria-label="Secrets in use">{s.secrets.map((n) => <li key={n}>{n}</li>)}</ul>;
  const revokeOne = (id: string) => {
    setStriking(id);
    setTimeout(() => { db.revoke([id]); setStriking(null); }, 480);
  };
  return (
    <section className="overview">
      <Head title="Sessions" sub="What agents hold right now, and until when. A session is a 15-minute token; revoking it stops the agent at once.">
        <button type="button" className="btn quiet danger-text" disabled={!live.length} onClick={() => db.revoke(live.map((s) => s.id))}>Revoke all</button>
        {db.paused
          ? <button type="button" className="btn primary" onClick={db.resume}><Icon name="unlock" />Resume agents</button>
          : <button type="button" className="btn danger" title="Revokes every session and stops new tokens until you resume" onClick={db.pause}><Icon name="lock" />Pause agents</button>}
      </Head>
      <div className="sec-h"><h2>Sessions</h2><span className="n">{live.length} live{ended.length > 0 && ` · ${ended.length} ended`}</span></div>
      <div className="tl-list" role="list" aria-label="Sessions">
        {live.length > 0 && (
          <div className="tl-row tl-axis" aria-hidden="true">
            <span>Agent</span><span>Secrets in use</span>
            <span className="tl"><b className="tick-l now" style={{ left: 0 }}>now</b>{grid}{ticks.map((t) => <b key={t} className="tick-l mono" style={{ left: x(t) }}>{clock(t)}</b>)}</span>
            <span className="r">Left</span><span />
          </div>
        )}
        {live.length === 0 && (
          <div className="tl-row tl-empty" role="listitem">
            {db.paused
              ? <p><b>Agents are paused.</b> Every session was revoked and no agent can get a token until you resume.</p>
              : <p><b>No live sessions.</b> An enrolled agent opens one when it next asks for a secret it has access to.</p>}
          </div>
        )}
        {live.map((s) => (
          <div key={s.id} role="listitem" className="tl-row" data-soon={s.expires - NOW < 180 || undefined} data-striking={striking === s.id || undefined}>
            {who(s)}{names(s)}
            <span className="tl" aria-hidden="true">{grid}<span className="bar" style={{ width: x(s.expires) }} /></span>
            <span className="r mono left" title={`Token expires ${clock(s.expires)}`}>{left(s.expires - NOW)}</span>
            <button type="button" className="btn sm quiet danger-text reveal" aria-label={`Revoke ${s.agent} session ${s.id}`} disabled={striking !== null} onClick={() => revokeOne(s.id)}>Revoke</button>
          </div>
        ))}
        {ended.length > 0 && <div className="tl-div" role="presentation"><span>Recently ended</span></div>}
        {ended.map((s) => (
          <div key={s.id} role="listitem" className="tl-row ended" data-state={s.state}>
            {who(s)}{names(s)}
            <span className="tl mono end">{s.state} {s.endedAt === NOW ? "just now" : clock(s.endedAt ?? s.expires)}</span><span /><span />
          </div>
        ))}
      </div>

      <div className="sec-h spaced"><h2 id="h-events">Activity</h2><a className="link" href="#/access/activity">All activity</a></div>
      <Log events={seed.events.slice(0, 10)} />
      <p className="log-foot"><Icon name="shield" />Ledger chain verified {ago(NOW - 240)} · 18,420 entries</p>
    </section>
  );
}

const Log = ({ events }: { events: seed.Event[] }) => events.length === 0 ? <p className="quiet-state">Nothing in the ledger yet.</p> : (
  <ol className="log" aria-label="Activity">
    {events.map((e) => (
          <li key={e.seq} data-kind={e.outcome === "ok" ? (e.label.includes("revoked") ? "revoked" : "allowed") : "blocked"}>
            <time className="mono">{clock(e.at)}</time>
            <span className="mk" aria-hidden="true" />
            <span className="what">{e.label}</span>
            <span className="mono tgt" title={e.target}>{e.target}</span>
            <span className="who-s">{e.actor}</span>
          </li>
    ))}
  </ol>
);

/** Inside a project the sidebar belongs to that project; this switches to a sibling or back to the list. */
/** Inside a product space: jump to another product without going back to Home. */
function ProductSwitch({ id }: { id: string }) {
  const ref = useRef<HTMLDetailsElement>(null);
  const close = () => { ref.current!.open = false; };
  const at = seed.products.find((x) => x.id === id)!;
  return (
    <details className="ws" ref={ref} {...dismiss}>
      <summary className="org" title="Switch product"><span className="pic" data-tint={at.tint}><Icon name={at.icon} /></span><span>{at.name}<small>Product</small></span><Chevrons /></summary>
      <div className="ws-menu">
        {seed.products.map((x) => (
          <a key={x.id} href={x.href ?? `#/app/${x.id}`} aria-current={x.id === id || undefined} onClick={close}>
            <span className="pic" data-tint={x.tint}><Icon name={x.icon} /></span>{x.name}
            {x.id === id ? <Check /> : !built(x) && <span className="badge">Planned</span>}
          </a>
        ))}
      </div>
    </details>
  );
}

function ProjectSwitch({ id, tab, can }: { id: string; tab: string; can: (projectId: string) => boolean }) {
  const ref = useRef<HTMLDetailsElement>(null);
  const [q, setQ] = useState("");
  const close = () => { ref.current!.open = false; setQ(""); };
  const found = seed.projects.filter((x) => can(x.id) && x.id.includes(q.trim().toLowerCase()));
  return (
    <details className="ws" ref={ref} {...dismiss}>
      <summary className="org" title="Switch project"><span className="av">{id[0]!.toUpperCase()}</span><span>{id}<small>Project</small></span><Chevrons /></summary>
      <div className="ws-menu">
        <input type="search" aria-label="Find a project" placeholder="Find a project" value={q} onChange={(e) => setQ(e.target.value)} />
        {/* Switching keeps the page you are on, so Access stays Access in the next project. */}
        {found.map((x) => (
          <a key={x.id} href={`#/secrets/${x.id}/${tab}`} aria-current={x.id === id || undefined} onClick={close}>
            <span className="av">{x.id[0]!.toUpperCase()}</span>{x.id}{x.id === id && <Check />}
          </a>
        ))}
        {found.length === 0 && <p className="muted small">No project matches “{q}”.</p>}
        <a className="all" href="#/secrets" onClick={close}><span className="av"><Icon name="grid" /></span>All projects</a>
      </div>
    </details>
  );
}

function ProjectAccess({ db, id }: { db: Db; id: string }) {
  const rows = db.secrets.filter((s) => s.project === id).flatMap((s) => s.grants.map((g) => ({ s, g })));
  return (
    <section>
      <Head title="Access" sub={`Every agent that can use a secret in ${id}, across its environments.`} />
      {rows.length === 0 ? <p className="state">No agent has access to anything in this project.</p> : (
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Agent</th><th>Secret</th><th>Environment</th><th>Expires</th><th /></tr></thead>
            <tbody>
              {rows.map(({ s, g }) => (
                <tr key={s.id + g.agent}>
                  <td className="strong">{g.agent}</td><td className="mono">{s.name}</td>
                  <td className={s.env === "production" ? "prod" : undefined}>{s.env}</td><td className="muted">{until(g.expires)}</td>
                  <td className="num"><button type="button" className="btn sm quiet danger-text" aria-label={`Revoke ${g.agent} from ${s.name} in ${s.env}`}
                    onClick={() => db.setSecrets((ss) => ss.map((x) => (x.id === s.id ? { ...x, grants: x.grants.filter((y) => y !== g) } : x)))}>Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ProjectSettings({ p }: { p: seed.Project }) {
  const [envs, setEnvs] = useState(p.envs);
  const [gone, setGone] = useState<string | null>(null);
  const [confirm, setConfirm] = useState("");
  return (
    <section>
      <Head title="Settings" sub={`The environments of ${p.id}, its description, and deleting it.`} />
      <div className="panel form">
        <h2>Environments</h2>
        <p className="muted">Each environment holds its own set of secrets. The last one is treated as production: access to it can be made to need a second person.</p>
        <ul className="plain" style={{ margin: "12px 0" }}>
          {envs.map((e, i) => (
            <li key={e}>
              <span className="mono">{e}</span>{i === envs.length - 1 && <span className="badge">Production</span>}
              {envs.length > 1 && <button type="button" className="btn sm quiet danger-text" aria-label={`Remove environment ${e}`} onClick={() => setGone(e)}>Remove</button>}
            </li>
          ))}
        </ul>
        {gone && (
          <p className="alert" role="alert">
            Removing {gone} deletes every secret in it and the access agents have to them.
            <button type="button" className="btn sm danger" style={{ marginLeft: "auto" }} onClick={() => { setEnvs((x) => x.filter((e) => e !== gone)); setGone(null); }}>Remove {gone}</button>
            <button type="button" className="btn sm quiet" onClick={() => setGone(null)}>Keep</button>
          </p>
        )}
        <form className="inline-form" onSubmit={(e) => { e.preventDefault(); const f = e.currentTarget; const v = String(new FormData(f).get("env")).trim().toLowerCase().replace(/[^a-z0-9-]/g, "-"); if (v && !envs.includes(v)) setEnvs((x) => [...x.slice(0, -1), v, x[x.length - 1]!]); f.reset(); }}>
          <input name="env" required aria-label="New environment name" placeholder="preview" autoComplete="off" spellCheck={false} />
          <button type="submit" className="btn sm">Add environment</button>
        </form>
      </div>
      <form className="panel form" onSubmit={(e) => e.preventDefault()}>
        <h2>Description</h2>
        <div className="add" style={{ gridTemplateColumns: "minmax(0, 1fr) auto" }}>
          <label className="field">What this project is<input defaultValue={p.description} style={{ width: "100%" }} /></label>
          <button type="submit" className="btn">Save</button>
        </div>
      </form>
      <div className="panel">
        <h2>Delete project</h2>
        <p className="muted">Deletes every secret and grant in {p.id}. Agents lose access at once. This cannot be undone.</p>
        <div className="inline-form" style={{ marginTop: 12 }}>
          <input aria-label={`Type ${p.id} to confirm`} placeholder={`Type ${p.id} to confirm`} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
          <button type="button" className="btn danger" disabled={confirm !== p.id}>Delete project</button>
        </div>
      </div>
    </section>
  );
}

function Projects({ db, acl }: { db: Db; acl: Acl }) {
  const mine = seed.projects.filter((p) => acl.roleIn(p.id));
  return (
    <section>
      <Head title="Secret Management" sub={acl.isAdmin
        ? "A project groups the secrets of one codebase, split by environment. As an organization admin you see every project."
        : `A project groups the secrets of one codebase, split by environment. You see the ${plural(mine.length, "project")} you were added to.`}>
        {acl.isAdmin && <button type="button" className="btn primary"><Icon name="plus" />New project</button>}
      </Head>
      {mine.length === 0 && <div className="state empty"><span className="state-ic"><Icon name="key" /></span><div><b>You are not in any project yet.</b> Ask an organization admin to add you to one.</div></div>}
      <div className="list">
        {mine.map((p) => {
          const own = db.secrets.filter((s) => s.project === p.id);
          const withAccess = new Set(own.flatMap((s) => s.grants.map((g) => g.agent))).size;
          return (
            <a key={p.id} className="row" href={`#/secrets/${p.id}`}>
              <span className="ic"><Icon name="key" /></span>
              <span><b>{p.id}</b><p>{p.description}</p></span>
              <span className="meta"><span>{plural(p.envs.length, "environment")}</span><span>{plural(own.length, "secret")}</span><span>{plural(withAccess, "agent")}</span><Icon name="arrow" /></span>
            </a>
          );
        })}
      </div>
    </section>
  );
}

function Project({ db, acl, id, tab, env: envParam }: { db: Db; acl: Acl; id: string; tab?: string; env?: string }) {
  const p = seed.projects.find((x) => x.id === id);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const role = acl.roleIn(id);
  if (!p || !role) return <p className="state">There is no project named <b>{id}</b>, or you were not added to it. <a href="#/secrets">Back to projects</a></p>;
  if (tab === "members") return <ProjectMembers acl={acl} id={id} />;
  if (tab && !["secrets", "access", "activity", "settings"].includes(tab)) return <Soon id="secrets" tab={tab} project={id} sub={envParam} say={db.say} />;
  if (tab === "access") return <ProjectAccess db={db} id={id} />;
  if (tab === "activity") return <section><Head title="Activity" sub={`What agents and people did in ${id}.`} /><Log events={seed.events.filter((e) => e.target.startsWith(`${id}/`))} /></section>;
  if (tab === "settings") return <ProjectSettings p={p} />;
  const env = envParam && p.envs.includes(envParam) ? envParam : p.envs[p.envs.length - 1]!;
  const rows = db.secrets.filter((s) => s.project === id && s.env === env && s.name.toLowerCase().includes(q.toLowerCase()));
  const patch = (sid: string, f: (s: Secret) => Secret) => db.setSecrets((ss) => ss.map((s) => (s.id === sid ? f(s) : s)));

  const add = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const name = String(new FormData(e.currentTarget).get("name")).trim().toUpperCase().replace(/[^A-Z0-9_]/g, "_");
    // The value field is dropped on purpose: the mockup never keeps what was typed.
    db.setSecrets((ss) => [{ id: `sec_new_${ss.length}`, project: id, env, name, version: 1, updated: NOW, lastUsed: null, grants: [] }, ...ss]);
    db.say(`Saved ${name}`);
    setAdding(false);
  };

  return (
    <section>
      <Head title="Secrets" sub={p.description} />
      <div className="toolbar">
        <fieldset className="seg inline">
          <legend className="sr-only">Environment</legend>
          {p.envs.map((v) => (
            <label key={v}>
              <input type="radio" name="env" checked={v === env} onChange={() => { location.hash = `#/secrets/${id}/secrets/${v}`; setOpen(null); }} />
              <span className={v === "production" ? "prod" : undefined}>{v}</span>
            </label>
          ))}
        </fieldset>
        <label className="search push"><span className="sr-only">Find a secret</span><Icon name="search" /><input type="search" placeholder="Find a secret" value={q} onChange={(e) => setQ(e.target.value)} /></label>
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding || role === "Viewer"} title={role === "Viewer" ? "Viewers cannot add secrets" : undefined}><Icon name="plus" />Add secret</button>
      </div>

      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add secret">
          <h2>Add a secret to {env}</h2>
          <div className="add">
            <label className="field">Name<input name="name" required autoFocus placeholder="STRIPE_SECRET_KEY" autoComplete="off" spellCheck={false} /></label>
            <label className="field">Value<input name="value" type="password" required autoComplete="off" placeholder="Paste the value" /></label>
            <button type="submit" className="btn primary">Save secret</button>
            <button type="button" className="btn quiet" style={{ justifySelf: "start" }} onClick={() => setAdding(false)}>Cancel</button>
          </div>
          <p className="hint">The value is encrypted in this browser before it is sent. After you save it, nobody can read it back here: not you, not an agent. It can only be replaced by a new version.</p>
        </form>
      )}

      {rows.length === 0 ? (
        <div className="state empty"><span className="state-ic"><Icon name="key" /></span>
          <div>{q ? <><b>No secret matches “{q}”</b> in {env}.</> : <><b>No secrets in {env} yet.</b> Add one, then grant an agent access to it.</>}</div>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Name</th><th>Version</th><th>Updated</th><th>Agents with access</th><th>Last used</th></tr></thead>
            <tbody>
              {rows.map((s) => (
                <Fragment key={s.id}>
                  <tr>
                    <td><button type="button" className="cell-btn" aria-expanded={open === s.id} onClick={() => setOpen(open === s.id ? null : s.id)}><Icon name="arrow" />{s.name}</button></td>
                    <td className="mono">v{s.version}</td>
                    <td>{ago(s.updated)}</td>
                    <td>{s.grants.length ? s.grants.map((g) => g.agent).join(", ") : <span className="muted">No agent</span>}</td>
                    <td className={s.lastUsed === null ? "muted" : undefined}>{ago(s.lastUsed)}</td>
                  </tr>
                  {open === s.id && <tr className="detail"><td colSpan={5}><SecretDetail s={s} db={db} patch={(f) => patch(s.id, f)} /></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function SecretDetail({ s, db, patch }: { s: Secret; db: Db; patch: (f: (s: Secret) => Secret) => void }) {
  const [rotating, setRotating] = useState(false);
  const free = db.agents.filter((a) => !s.grants.some((g) => g.agent === a.name));
  const grant = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const secs = EXPIRY[Number(f.get("expiry"))]![1];
    patch((x) => ({ ...x, grants: [...x.grants, { agent: String(f.get("agent")), expires: secs === null ? null : NOW + secs }] }));
    db.say(`Granted ${f.get("agent")} access to ${s.name}`);
  };
  return (
    <div className="detail-cols">
      <div>
        <h3>Agents with access</h3>
        {s.grants.length === 0 && <p className="muted small" style={{ margin: "0 0 10px" }}>No agent can use this secret.</p>}
        <ul className="plain">
          {s.grants.map((g) => (
            <li key={g.agent}>
              <span className="strong">{g.agent}</span><span className="muted small">relay · {until(g.expires)}</span>
              <button type="button" className="btn sm quiet danger-text" onClick={() => { patch((x) => ({ ...x, grants: x.grants.filter((y) => y !== g) })); db.say(`Revoked ${g.agent} from ${s.name}`); }}>Revoke</button>
            </li>
          ))}
        </ul>
        {free.length > 0 && (
          <form className="inline-form" onSubmit={grant}>
            <select name="agent" aria-label="Agent">{free.map((a) => <option key={a.name}>{a.name}</option>)}</select>
            <select name="expiry" aria-label="Expiry" defaultValue={1}>{EXPIRY.map(([l], i) => <option key={l} value={i}>{l}</option>)}</select>
            <button type="submit" className="btn sm">Grant access</button>
          </form>
        )}
      </div>
      <div>
        <h3>Versions</h3>
        <ul className="plain">
          {Array.from({ length: Math.min(3, s.version) }, (_, i) => (
            <li key={i}><span className="mono">v{s.version - i}</span><span className="muted small">{i === 0 ? `current · ${ago(s.updated)}` : ago(s.updated - i * 30 * 86400)}</span></li>
          ))}
        </ul>
        {rotating ? (
          <form className="inline-form" onSubmit={(e) => { e.preventDefault(); patch((x) => ({ ...x, version: x.version + 1, updated: NOW })); db.say(`${s.name} is now v${s.version + 1}`); setRotating(false); }}>
            <input type="password" required autoFocus autoComplete="off" aria-label="New value" placeholder="Paste the new value" />
            <button type="submit" className="btn sm">Save v{s.version + 1}</button>
            <button type="button" className="btn sm quiet" onClick={() => setRotating(false)}>Cancel</button>
          </form>
        ) : <button type="button" className="btn sm" onClick={() => setRotating(true)}><Icon name="rotate" />New version</button>}
      </div>
    </div>
  );
}

function Agents({ db }: { db: Db }) {
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [once, setOnce] = useState<string | null>(null);
  const create = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const name = String(f.get("name")).trim().toLowerCase().replace(/[^a-z0-9-]/g, "-");
    db.setAgents((as) => [{ name, description: String(f.get("description")), icon: "s_terminal", machine: "not enrolled yet", enrolled: NOW, lastSeen: NOW }, ...as]);
    setOnce(name);
    setAdding(false);
  };
  const grantsOf = (name: string) => db.secrets.filter((s) => s.grants.some((g) => g.agent === name));
  return (
    <section>
      <Head title="Agents" sub="An agent is an identity you enroll on one machine. It uses secrets through the gateway and never receives a value.">
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding}><Icon name="plus" />New agent</button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={create} aria-label="New agent">
          <h2>New agent</h2>
          <div className="add">
            <label className="field">Name<input name="name" required autoFocus placeholder="claude-laptop" autoComplete="off" spellCheck={false} /></label>
            <label className="field">What it is for<input name="description" placeholder="Claude Code on my laptop" autoComplete="off" /></label>
            <button type="submit" className="btn primary">Create agent</button>
            <button type="button" className="btn quiet" style={{ justifySelf: "start" }} onClick={() => setAdding(false)}>Cancel</button>
          </div>
        </form>
      )}
      {once && (
        <div className="panel once" role="status">
          <h2>Enroll {once} now</h2>
          <p>Run this on the agent's machine. The enrollment secret is shown once and cannot be retrieved again.</p>
          <code className="block">smith agent enroll --name {once} --secret lse_sample_not_a_real_secret</code>
          <button type="button" className="btn sm" style={{ marginTop: 12 }} onClick={() => setOnce(null)}>I have copied it</button>
        </div>
      )}
      <ul className="sess-list">
        {db.agents.map((a) => {
          const gs = grantsOf(a.name);
          const live = db.sessions.some((s) => s.agent === a.name && s.state === "active");
          return (
            <li key={a.name} className="sess">
              <div className="sess-main">
                <button type="button" className="sess-toggle" aria-expanded={open === a.name} onClick={() => setOpen(open === a.name ? null : a.name)}>
                  <span className="av"><AgentIcon a={a} /></span>
                  <span className="who">
                    <span className="who-1"><span className="who-name">{a.name}</span>{live && <span className="live-dot" title="Has a live session" />}</span>
                    <span className="who-2">{a.description} · {a.machine}</span>
                  </span>
                </button>
                <span className="muted small">{plural(gs.length, "secret")}</span>
                <span className="r muted small nowrap">{ago(a.lastSeen)}</span>
                <span />
              </div>
              {open === a.name && (
                <dl className="sess-det">
                  <dt>Enrolled</dt><dd>{ago(a.enrolled)} on {a.machine}</dd>
                  <dt>Can use</dt>
                  <dd>
                    {gs.length === 0 ? <span className="muted">Nothing yet. Open a secret in Secrets and grant this agent access.</span> : (
                      <ul className="plain">
                        {gs.map((s) => (
                          <li key={s.id}>
                            <span className="mono">{s.name}</span>
                            <span className="muted small">{s.project} / {s.env} · {until(s.grants.find((g) => g.agent === a.name)!.expires)}</span>
                            <button type="button" className="btn sm quiet danger-text" onClick={() => db.setSecrets((ss) => ss.map((x) => (x.id === s.id ? { ...x, grants: x.grants.filter((g) => g.agent !== a.name) } : x)))}>Revoke</button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </dd>
                  <dt>Enrollment</dt>
                  <dd className="inline-form">
                    <button type="button" className="btn sm" onClick={() => setOnce(a.name)}><Icon name="rotate" />Rotate enrollment secret</button>
                    <button type="button" className="btn sm quiet danger-text" onClick={() => { db.setAgents((as) => as.filter((x) => x !== a)); db.say(`Removed ${a.name}`); }}>Remove agent</button>
                  </dd>
                </dl>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
