// KMS (product id "keys"): the keys Locksmith holds, who may use them, what was done with them, and the rules around them.
// Keys, clients (with their permissions), the activity log and settings live in module-level stores, so every page agrees.
import { useState } from "react";
import { Crumbs, Empty, Head, Icon, NOW, MIN, DAY, Switch, ago, createStore, inTime, plural, type IconName, type PageProps, type Pages } from "../kit";
import { connections } from "../data";
import "../settings.css";
import "./kms.css";

type Op = "encrypt" | "decrypt" | "sign" | "verify";
const OPS: Op[] = ["encrypt", "decrypt", "sign", "verify"];
const USE = { crypt: "Encrypt and decrypt", sign: "Sign and verify" } as const;
const opsOf = (use: keyof typeof USE): Op[] => (use === "crypt" ? ["encrypt", "decrypt"] : ["sign", "verify"]);
const cap = (s: string) => s[0]!.toUpperCase() + s.slice(1);
const NOT_ALLOWED = (op: Op) => `Not allowed to ${op} with this key`;
const DISABLED = "Key is disabled";

interface Version { n: number; created: number }
interface Key { id: string; name: string; use: keyof typeof USE; algo: string; versions: Version[]; every: number | null; enabled: boolean; deleteAt: number | null }
const v = (n: number, daysAgo: number): Version => ({ n, created: NOW - daysAgo * DAY });
const KEYS: Key[] = [
  { id: "key_7f3a", name: "customer-data", use: "crypt", algo: "AES 256", versions: [v(3, 21), v(2, 111), v(1, 201)], every: 90, enabled: true, deleteAt: null },
  { id: "key_2c91", name: "invoice-signing", use: "sign", algo: "Ed25519", versions: [v(2, 40), v(1, 220)], every: 180, enabled: true, deleteAt: null },
  { id: "key_b04e", name: "backup-archive", use: "crypt", algo: "AES 256", versions: [v(1, 150)], every: null, enabled: true, deleteAt: null },
  { id: "key_5d18", name: "session-tokens", use: "sign", algo: "HMAC SHA 256", versions: [v(5, 41), v(4, 71), v(3, 101)], every: 30, enabled: true, deleteAt: null },
  { id: "key_e6a2", name: "webhook-signing", use: "sign", algo: "ECDSA P-256", versions: [v(2, 75), v(1, 300)], every: null, enabled: true, deleteAt: null },
  { id: "key_91cd", name: "pii-vault", use: "crypt", algo: "AES 256", versions: [v(4, 95), v(3, 185), v(2, 275), v(1, 365)], every: 90, enabled: true, deleteAt: null },
  { id: "key_3b77", name: "legacy-export", use: "crypt", algo: "RSA 3072", versions: [v(1, 520)], every: null, enabled: false, deleteAt: null },
  { id: "key_a8f0", name: "old-license-signing", use: "sign", algo: "Ed25519", versions: [v(2, 400), v(1, 700)], every: null, enabled: false, deleteAt: NOW + 5 * DAY },
];

type Kind = "Service" | "CI job" | "AI agent";
interface Client { name: string; kind: Kind; about: string; icon: IconName; perms: Record<string, Op[]> }
const KIND_ICON: Record<Kind, IconName> = { Service: "s_window", "CI job": "run", "AI agent": "s_spark" };
const CLIENTS: Client[] = [
  { name: "billing-service", kind: "Service", about: "Issues and stores invoices", icon: "s_window", perms: { "customer-data": ["encrypt", "decrypt"], "invoice-signing": ["sign"], "pii-vault": ["decrypt"] } },
  { name: "checkout-api", kind: "Service", about: "Customer checkout and sessions", icon: "http", perms: { "customer-data": ["encrypt", "decrypt"], "session-tokens": ["sign", "verify"], "pii-vault": ["encrypt"] } },
  { name: "webhook-relay", kind: "Service", about: "Sends signed events to partners", icon: "relay", perms: { "webhook-signing": ["sign"] } },
  { name: "nightly-backup", kind: "CI job", about: "Encrypts database dumps every night", icon: "run", perms: { "backup-archive": ["encrypt"] } },
  { name: "ci-deploy", kind: "CI job", about: "GitHub Actions deploy job", icon: "s_terminal", perms: { "invoice-signing": ["verify"], "webhook-signing": ["verify"] } },
  { name: "codex-billing", kind: "AI agent", about: "Codex working on the billing service", icon: "s_code", perms: { "invoice-signing": ["verify"] } },
  { name: "review-bot", kind: "AI agent", about: "Pull request reviewer", icon: "s_spark", perms: {} },
];

/** One line of the log. `op` lines are requests from a client; `admin` lines are changes made in the console. */
interface Entry { at: number; kind: "op" | "admin"; client: string; op?: Op; key: string; ver?: number; why?: string; text?: string; about?: string }
const e = (m: number, client: string, op: Op, key: string, ver: number, why?: string): Entry => ({ at: NOW - m * MIN, kind: "op", client, op, key, ver, why });
const a = (m: number, text: string, key: string, about?: string): Entry => ({ at: NOW - m * MIN, kind: "admin", client: "You", text, key, about });
const LOG: Entry[] = [
  e(0.5, "checkout-api", "sign", "session-tokens", 5), e(1, "checkout-api", "decrypt", "customer-data", 3), e(2, "checkout-api", "encrypt", "customer-data", 3),
  e(4, "review-bot", "sign", "invoice-signing", 2, NOT_ALLOWED("sign")), e(6, "codex-billing", "verify", "invoice-signing", 2), e(9, "billing-service", "sign", "invoice-signing", 2),
  e(14, "billing-service", "decrypt", "pii-vault", 4), e(31, "checkout-api", "decrypt", "legacy-export", 1, DISABLED),
  e(95, "webhook-relay", "sign", "webhook-signing", 2), e(180, "ci-deploy", "sign", "webhook-signing", 2, NOT_ALLOWED("sign")),
  e(300, "billing-service", "encrypt", "old-license-signing", 2, DISABLED), e(610, "nightly-backup", "encrypt", "backup-archive", 1),
  a(1000, "Allowed verify on invoice-signing for codex-billing", "invoice-signing", "codex-billing"),
  e(1440, "nightly-backup", "encrypt", "backup-archive", 1), e(1500, "ci-deploy", "verify", "invoice-signing", 1),
  a(2880, "Scheduled old-license-signing for deletion in 7 days", "old-license-signing"),
  e(41 * 1440, "checkout-api", "decrypt", "legacy-export", 1), a(41 * 1440 + 5, "Disabled legacy-export", "legacy-export"),
  e(88 * 1440, "billing-service", "sign", "old-license-signing", 2),
].sort((x, y) => y.at - x.at);

interface Cfg { rotation: number; wait: number; root: string; aws: string }
const CFG: Cfg = { rotation: 90, wait: 7, root: "Locksmith-managed", aws: connections.find((c) => c.provider === "AWS")?.name ?? "" };
const ROTATIONS: [number, string][] = [[30, "Every 30 days"], [90, "Every 90 days"], [180, "Every 180 days"], [0, "Manual only"]];

const useKeys = createStore(KEYS);
const useClients = createStore(CLIENTS);
const useLog = createStore(LOG);
const useCfg = createStore(CFG);

const days = (n: number) => plural(n, "day");
const every = (n: number | null) => (n ? `Every ${days(n)}` : "Manual");
const state = (k: Key) => (k.deleteAt ? { s: "del", t: `Scheduled for deletion ${inTime(k.deleteAt)}` } : k.enabled ? { s: "on", t: "Enabled" } : { s: "off", t: "Disabled" });
/** Days past the rotation schedule (0 when on time or manual). */
const overdue = (k: Key) => (k.every ? Math.max(0, Math.floor((NOW - k.versions[0]!.created) / DAY) - k.every) : 0);
const keyHref = (n: string) => `#/app/keys/keys/${encodeURIComponent(n)}`;
const clientHref = (n: string) => `#/app/keys/clients/${encodeURIComponent(n)}`;
const cleanName = (s: string) => s.trim().toLowerCase().replace(/[^a-z0-9-]/g, "-");

/** All shared data plus every action that changes it. Each action also writes the Activity log and shows a note. */
function useKms(say: (n: string) => void) {
  const [keys, setKeys] = useKeys();
  const [clients, setClients] = useClients();
  const [log, setLog] = useLog();
  const [cfg, setCfg] = useCfg();
  const push = (x: Omit<Entry, "at">) => setLog((l) => [{ ...x, at: NOW }, ...l]);
  const admin = (text: string, key = "", about?: string) => { push({ kind: "admin", client: "You", text, key, about }); say(text); };
  const patch = (name: string, f: (k: Key) => Key) => setKeys((ks) => ks.map((k) => (k.name === name ? f(k) : k)));
  const keyBy = (n: string) => keys.find((k) => k.name === n);
  const clientBy = (n: string) => clients.find((c) => c.name === n);
  const lastUsed = (match: (x: Entry) => boolean) => log.find((x) => x.kind === "op" && !x.why && match(x))?.at ?? null;
  return {
    keys, clients, log, cfg, setCfg, keyBy, clientBy, admin,
    keyUsed: (k: Key) => lastUsed((x) => x.key === k.name),
    clientUsed: (c: Client) => lastUsed((x) => x.client === c.name),
    keyLink: (n: string) => (keyBy(n) ? <a className="mono" href={keyHref(n)}>{n}</a> : <span className="mono">{n}</span>),
    clientLink: (n: string) => (clientBy(n) ? <a className="mono" href={clientHref(n)}>{n}</a> : <span className="mono">{n}</span>),
    rotate(k: Key) { const n = k.versions[0]!.n + 1; patch(k.name, (x) => ({ ...x, versions: [{ n, created: NOW }, ...x.versions] })); admin(`Rotated ${k.name} to version ${n}`, k.name); },
    setEnabled(k: Key, on: boolean) {
      patch(k.name, (x) => ({ ...x, enabled: on, deleteAt: on ? null : x.deleteAt }));
      admin(on ? (k.deleteAt ? `Enabled ${k.name} and cancelled its deletion` : `Enabled ${k.name}`) : `Disabled ${k.name}`, k.name);
    },
    scheduleDelete(k: Key) { patch(k.name, (x) => ({ ...x, enabled: false, deleteAt: NOW + cfg.wait * DAY })); admin(`Scheduled ${k.name} for deletion in ${days(cfg.wait)}`, k.name); },
    cancelDelete(k: Key) { patch(k.name, (x) => ({ ...x, deleteAt: null })); admin(`Cancelled deletion of ${k.name}. It stays disabled until you enable it.`, k.name); },
    setEvery(k: Key, n: number | null) { patch(k.name, (x) => ({ ...x, every: n })); admin(`Changed rotation of ${k.name} to ${every(n).toLowerCase()}`, k.name); },
    createKey(name: string, use: keyof typeof USE, rot: number | null) {
      setKeys((ks) => [{ id: `key_${(0x4e00 + ks.length * 37).toString(16)}`, name, use, algo: use === "sign" ? "Ed25519" : "AES 256", versions: [{ n: 1, created: NOW }], every: rot, enabled: true, deleteAt: null }, ...ks]);
      admin(`Created ${name}`, name);
    },
    setPerm(c: string, key: string, op: Op, on: boolean) {
      setClients((rs) => rs.map((r) => (r.name !== c ? r : { ...r, perms: { ...r.perms, [key]: on ? [...(r.perms[key] ?? []).filter((o) => o !== op), op] : (r.perms[key] ?? []).filter((o) => o !== op) } })));
      admin(`${on ? "Allowed" : "Blocked"} ${op} on ${key} for ${c}`, key, c);
    },
    addClient(name: string, kind: Kind) { setClients((rs) => [...rs, { name, kind, about: "Added just now", icon: KIND_ICON[kind], perms: {} }]); admin(`Added client ${name}. It can use no keys yet.`, "", name); },
    removeClient(name: string) { setClients((rs) => rs.filter((r) => r.name !== name)); admin(`Removed client ${name}`, "", name); },
  };
}
type Kms = ReturnType<typeof useKms>;

function Sel({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return <select aria-label={label} value={value} onChange={(x) => onChange(x.target.value)}>{options.map(([val, text]) => <option key={val} value={val}>{text}</option>)}</select>;
}

function Row({ title, about, children }: { title: string; about: string; children: React.ReactNode }) {
  return <div className="set-row"><div><b>{title}</b><p>{about}</p></div><div className="set-ctl">{children}</div></div>;
}

function NotFound({ what, list, href, name }: { what: string; list: string; href: string; name: string }) {
  return (
    <section>
      <Crumbs trail={[[list, href], [name]]} />
      <Head title={`No ${what} named ${name}`} sub={`It may have been removed, or the address is mistyped.`}><a className="btn primary" href={href}>Back to {list.toLowerCase()}</a></Head>
      <Empty icon="lock">Nothing here. Pick one from the {list.toLowerCase()} list.</Empty>
    </section>
  );
}

/** Rows of the log. Key and client names open their detail pages. */
function LogTable({ rows, kms }: { rows: Entry[]; kms: Kms }) {
  return (
    <div className="table-wrap">
      <table className="grid kms-log">
        <thead><tr><th>Time</th><th>Who</th><th>Action</th><th>Key or client</th><th>Result</th></tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.at}-${i}`}>
              <td className="muted">{ago(r.at)}</td>
              <td>{r.kind === "op" ? kms.clientLink(r.client) : "You"}</td>
              <td>{r.kind === "op" ? r.op : r.text}</td>
              <td>{r.key ? <>{kms.keyLink(r.key)}{r.ver ? <span className="mono muted"> v{r.ver}</span> : null}</> : r.about ? kms.clientLink(r.about) : <span className="muted">Workspace</span>}</td>
              <td>{r.why ? <><span className="outcome" data-o="denied"><b>Denied</b></span><span className="kms-reason">{r.why}</span></> : <span className="kms-st" data-s="on">{r.kind === "admin" ? "Done" : "OK"}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Every operation on every key for one client, as checkboxes. Editing here is editing the key's own client list. */
function Matrix({ client, kms }: { client: Client; kms: Kms }) {
  const live = kms.keys.filter((k) => !k.deleteAt);
  return (
    <table className="matrix">
      <caption className="sr-only">Operations {client.name} may do, per key</caption>
      <thead><tr><th>Key</th>{OPS.map((o) => <th key={o} className="c">{cap(o)}</th>)}</tr></thead>
      <tbody>
        {live.map((k) => (
          <tr key={k.id}>
            <th scope="row">{kms.keyLink(k.name)}{!k.enabled && <span className="muted"> (disabled)</span>}</th>
            {OPS.map((o) => (
              <td key={o} className="c">{opsOf(k.use).includes(o)
                ? <input type="checkbox" aria-label={`${client.name} may ${o} with ${k.name}`} checked={!!client.perms[k.name]?.includes(o)} onChange={(x) => kms.setPerm(client.name, k.name, o, x.target.checked)} />
                : <span className="na" title={`${k.name} is for ${USE[k.use].toLowerCase()}`}>n/a</span>}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Every key Locksmith holds, with rotation, status and who may use it. Names open the key. */
function Keys({ say, sub }: PageProps) {
  const kms = useKms(say);
  const [adding, setAdding] = useState(false);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  if (sub) return <KeyDetail name={decodeURIComponent(sub)} say={say} />;
  const rows = kms.keys.filter((k) => k.name.includes(q.trim().toLowerCase()));
  const create = (ev: React.FormEvent<HTMLFormElement>) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    const name = cleanName(String(f.get("name")));
    if (!name) return setErr("Give the key a name using letters, numbers or dashes.");
    if (kms.keyBy(name)) return setErr(`A key named ${name} already exists.`);
    kms.createKey(name, f.get("use") === "sign" ? "sign" : "crypt", kms.cfg.rotation || null);
    setAdding(false); setErr("");
    location.hash = keyHref(name);
  };
  return (
    <section>
      <Head title="Keys" sub="The encryption and signing keys Locksmith holds for your apps.">
        <button type="button" className="btn primary" disabled={adding} onClick={() => setAdding(true)}><Icon name="plus" />Create key</button>
      </Head>
      <p className="kms-note"><Icon name="lock" /><span><b>Key material never leaves Locksmith and cannot be exported.</b> Apps send data in and get the result back.</span></p>
      {adding && (
        <form className="panel form" onSubmit={create} aria-label="Create key">
          <h2>Create a key</h2>
          <div className="add share">
            <label className="field">Name<input name="name" required autoFocus placeholder="order-data" autoComplete="off" spellCheck={false} /></label>
            <label className="field">Used for<select name="use"><option value="crypt">{USE.crypt} (AES 256)</option><option value="sign">{USE.sign} (Ed25519)</option></select></label>
            <button type="submit" className="btn primary">Create key</button>
            <button type="button" className="btn quiet" onClick={() => { setAdding(false); setErr(""); }}>Cancel</button>
          </div>
          {err && <p className="kms-warn" role="alert">{err}</p>}
          <p className="hint">The key is made inside Locksmith. You will never see it. Next, allow a client to use it. The default rotation comes from Settings.</p>
        </form>
      )}
      <div className="toolbar">
        <label className="search"><span className="sr-only">Find a key by name</span><Icon name="search" /><input type="search" placeholder="Find a key" value={q} onChange={(x) => setQ(x.target.value)} /></label>
      </div>
      {kms.keys.length === 0 ? <Empty icon="lock">No keys yet. Create one, then allow a client to use it.</Empty> : rows.length === 0 ? (
        <Empty icon="search">No key matches. <button type="button" className="btn sm quiet" onClick={() => setQ("")}>Clear search</button></Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Name</th><th>Used for</th><th>Algorithm</th><th>Version</th><th>Rotation</th><th>Last used</th><th>Status</th></tr></thead>
            <tbody>
              {rows.map((k) => {
                const s = state(k);
                const late = overdue(k);
                return (
                  <tr key={k.id}>
                    <td><a className="mono" href={keyHref(k.name)}>{k.name}</a></td>
                    <td>{USE[k.use]}</td><td>{k.algo}</td><td className="mono">v{k.versions[0]!.n}</td>
                    <td>{every(k.every)}{late > 0 && !k.deleteAt && (
                      <span className="kms-late"><span className="kms-warn">Rotation overdue by {days(late)}</span><button type="button" className="btn sm" disabled={!k.enabled} onClick={() => kms.rotate(k)}><Icon name="rotate" />Rotate now</button></span>
                    )}</td>
                    <td className={kms.keyUsed(k) === null ? "muted" : undefined}>{ago(kms.keyUsed(k))}</td>
                    <td><span className="kms-st" data-s={s.s}>{s.t}</span></td>
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

/** One key: facts, rotation, versions and who may use it. */
function KeyDetail({ name, say }: { name: string; say: (n: string) => void }) {
  const kms = useKms(say);
  const [asking, setAsking] = useState(false);
  const k = kms.keyBy(name);
  const back = "#/app/keys/keys";
  if (!k) return <NotFound what="key" list="Keys" href={back} name={name} />;
  const s = state(k);
  const late = overdue(k);
  const cur = k.versions[0]!;
  const ops = opsOf(k.use);
  const next = k.every ? cur.created + k.every * DAY : null;
  return (
    <section className="kms-stack">
      <div>
        <Crumbs trail={[["Keys", back], [k.name]]} />
        <Head title={k.name} sub={`${USE[k.use]} key, ${k.algo}. It is held inside Locksmith and never shown.`}>
          <button type="button" className="btn primary" disabled={!k.enabled || !!k.deleteAt} onClick={() => kms.rotate(k)}><Icon name="rotate" />Rotate now</button>
        </Head>
        {k.deleteAt && <p className="alert" role="status">This key is gone {inTime(k.deleteAt)}. Data it protects cannot be read after that. <button type="button" className="btn sm" onClick={() => kms.cancelDelete(k)}>Cancel deletion</button></p>}
      </div>

      <div className="panel">
        <h2>Details</h2>
        <dl className="kms-facts">
          <div><dt>Status</dt><dd><span className="kms-st" data-s={s.s}>{s.t}</span></dd></div>
          <div><dt>Key id</dt><dd className="mono">{k.id}</dd></div>
          <div><dt>Current version</dt><dd className="mono">v{cur.n}</dd></div>
          <div><dt>Last rotated</dt><dd>{ago(cur.created)}</dd></div>
          <div><dt>Last used</dt><dd>{ago(kms.keyUsed(k))}</dd></div>
          <div><dt>Next rotation</dt><dd>{next === null ? "Manual only" : late > 0 ? `Overdue by ${days(late)}` : inTime(next)}</dd></div>
        </dl>
        <Row title="Enabled" about={k.deleteAt ? "Turning it on also cancels the scheduled deletion." : "When off, every request for this key is denied. Nothing is lost."}>
          <Switch label={`Enable ${k.name}`} checked={k.enabled && !k.deleteAt} onChange={(on) => kms.setEnabled(k, on)} />
        </Row>
        <Row title="Rotation" about="Rotating adds a new version. Older versions still open data they protected.">
          <Sel label="Rotation schedule" value={String(k.every ?? 0)} onChange={(x) => kms.setEvery(k, Number(x) || null)} options={ROTATIONS.map(([n, t]) => [String(n), t])} />
        </Row>
        <Row title="Deletion" about={k.deleteAt ? `Scheduled ${inTime(k.deleteAt)}. You can still cancel.` : `Waits ${days(kms.cfg.wait)} (set in Settings). The key is disabled meanwhile and you can cancel.`}>
          {k.deleteAt
            ? <button type="button" className="btn sm" onClick={() => kms.cancelDelete(k)}>Cancel deletion</button>
            : asking ? (
              <span className="kms-acts">
                <button type="button" className="btn sm danger" onClick={() => { kms.scheduleDelete(k); setAsking(false); }}>Schedule deletion</button>
                <button type="button" className="btn sm quiet" onClick={() => setAsking(false)}>Keep it</button>
              </span>
            ) : <button type="button" className="btn sm quiet danger-text" onClick={() => setAsking(true)}>Schedule deletion</button>}
        </Row>
      </div>

      <div className="panel">
        <h2>Versions</h2>
        <p className="muted">New data always uses the current version. Older versions are kept only to {k.use === "crypt" ? "decrypt" : "verify"} what they already protected.</p>
        <ul className="plain">
          {k.versions.map((x, i) => (
            <li key={x.n}>
              <span className="mono">v{x.n}</span><span className="muted">created {ago(x.created)}</span>
              {i === 0 ? <span className="kms-cur">Current</span> : <span className="muted kms-old">{k.use === "crypt" ? "Decrypt only" : "Verify only"}</span>}
            </li>
          ))}
        </ul>
      </div>

      <div className="panel kms-detail">
        <h2>Clients that may use it</h2>
        <p className="muted">Tick what each client may do. This is the same setting as on the Clients page.</p>
        {kms.clients.length === 0 ? <Empty icon="s_terminal">No clients yet. <a href="#/app/keys/clients">Add a client</a> first.</Empty> : (
          <table className="matrix">
            <caption className="sr-only">Clients and what each may do with {k.name}</caption>
            <thead><tr><th>Client</th>{ops.map((o) => <th key={o} className="c">{cap(o)}</th>)}</tr></thead>
            <tbody>
              {kms.clients.map((c) => (
                <tr key={c.name}>
                  <th scope="row">{kms.clientLink(c.name)} <span className="badge">{c.kind}</span></th>
                  {ops.map((o) => <td key={o} className="c"><input type="checkbox" aria-label={`${c.name} may ${o} with ${k.name}`} checked={!!c.perms[k.name]?.includes(o)} onChange={(x) => kms.setPerm(c.name, k.name, o, x.target.checked)} /></td>)}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

    </section>
  );
}

/** One client: what it may do, what it was refused and how to fix that. */
function ClientDetail({ name, say }: { name: string; say: (n: string) => void }) {
  const kms = useKms(say);
  const [removing, setRemoving] = useState(false);
  const c = kms.clientBy(name);
  const back = "#/app/keys/clients";
  if (!c) return <NotFound what="client" list="Clients" href={back} name={name} />;
  const count = Object.values(c.perms).filter((o) => o.length).length;
  const denied = kms.log.filter((x) => x.kind === "op" && x.client === c.name && x.why).slice(0, 8);
  /** What would let this refused request through now, as a button, or a word when it already would pass. */
  const fix = (x: Entry) => {
    const k = kms.keyBy(x.key);
    if (!k || !x.op) return <span className="muted">Key no longer exists</span>;
    if (x.why === DISABLED) return k.deleteAt
      ? <button type="button" className="btn sm" onClick={() => kms.cancelDelete(k)}>Cancel deletion of {k.name}</button>
      : !k.enabled ? <button type="button" className="btn sm" onClick={() => kms.setEnabled(k, true)}>Enable {k.name}</button> : <span className="kms-st" data-s="on">Fixed: key is enabled</span>;
    return c.perms[k.name]?.includes(x.op)
      ? <span className="kms-st" data-s="on">Fixed: allowed</span>
      : <button type="button" className="btn sm" onClick={() => kms.setPerm(c.name, k.name, x.op!, true)}>Allow {x.op} on {k.name}</button>;
  };
  return (
    <section className="kms-stack">
      <div>
        <Crumbs trail={[["Clients", back], [c.name]]} />
        <Head title={c.name} sub={c.about} />
      </div>
      <div className="panel">
        <h2>About</h2>
        <dl className="kms-facts">
          <div><dt>Kind</dt><dd>{c.kind}</dd></div>
          <div><dt>Keys it may use</dt><dd>{count ? plural(count, "key") : "None"}</dd></div>
          <div><dt>Last used</dt><dd>{ago(kms.clientUsed(c))}</dd></div>
        </dl>
      </div>
      <div className="panel kms-detail">
        <h2>What it may do</h2>
        <p className="muted">Tick an operation to allow it. This is the same setting as on each key.</p>
        <Matrix client={c} kms={kms} />
      </div>
      <div>
        <h2 className="kms-h2">Refused requests</h2>
        {denied.length === 0 ? <Empty icon="shield">No requests from {c.name} have been refused.</Empty> : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>Time</th><th>Request</th><th>Reason</th><th>Fix</th></tr></thead>
              <tbody>{denied.map((x, i) => (
                <tr key={`${x.at}-${i}`}><td className="muted">{ago(x.at)}</td><td>{x.op} {kms.keyLink(x.key)}</td><td><span className="outcome" data-o="denied"><b>Denied</b></span><span className="kms-reason">{x.why}</span></td><td>{fix(x)}</td></tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </div>
      <div className="panel">
        <h2>Remove client</h2>
        <div className="kms-acts">
          {removing ? (
            <>
              <span className="alert" role="alert" style={{ margin: 0 }}>{c.name} stops working on {plural(count, "key")} right away. Its requests will be denied.</span>
              <button type="button" className="btn sm danger" onClick={() => { kms.removeClient(c.name); location.hash = back; }}>Remove {c.name}</button>
              <button type="button" className="btn sm quiet" onClick={() => setRemoving(false)}>Keep it</button>
            </>
          ) : <><button type="button" className="btn sm quiet danger-text" onClick={() => setRemoving(true)}>Remove client</button><span className="muted">Its permissions are deleted. Past activity stays in the log.</span></>}
        </div>
      </div>
    </section>
  );
}

/** Who may do what: one client at a time. Names open the client. */
function Clients({ say, sub }: PageProps) {
  const kms = useKms(say);
  const [adding, setAdding] = useState(false);
  const [err, setErr] = useState("");
  if (sub) return <ClientDetail name={decodeURIComponent(sub)} say={say} />;
  const count = (c: Client) => Object.values(c.perms).filter((o) => o.length).length;
  const add = (ev: React.FormEvent<HTMLFormElement>) => {
    ev.preventDefault();
    const f = new FormData(ev.currentTarget);
    const name = cleanName(String(f.get("name")));
    if (!name) return setErr("Give the client a name using letters, numbers or dashes.");
    if (kms.clientBy(name)) return setErr(`A client named ${name} already exists.`);
    kms.addClient(name, String(f.get("kind")) as Kind);
    setAdding(false); setErr("");
    location.hash = clientHref(name);
  };
  return (
    <section>
      <Head title="Clients" sub="The apps, jobs and agents that may use keys, and what each one may do with them.">
        <button type="button" className="btn primary" disabled={adding} onClick={() => setAdding(true)}><Icon name="plus" />Add client</button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add client">
          <h2>Add a client</h2>
          <div className="add share">
            <label className="field">Name<input name="name" required autoFocus placeholder="reports-worker" autoComplete="off" spellCheck={false} /></label>
            <label className="field">Kind<select name="kind"><option>Service</option><option>CI job</option><option>AI agent</option></select></label>
            <button type="submit" className="btn primary">Add client</button>
            <button type="button" className="btn quiet" onClick={() => { setAdding(false); setErr(""); }}>Cancel</button>
          </div>
          {err && <p className="kms-warn" role="alert">{err}</p>}
          <p className="hint">A new client can use no keys. Tick the operations it needs on its page.</p>
        </form>
      )}
      {kms.clients.length === 0 ? <Empty icon="s_terminal">No clients yet. Add one, then choose which keys it may use.</Empty> : (
        <ul className="list">
          {kms.clients.map((c) => (
            <li key={c.name} className="row kms-client">
              <div className="row-head">
                <span className="pic"><Icon name={c.icon} /></span>
                <div><a className="mono kms-name" href={clientHref(c.name)}>{c.name}</a> <span className="badge">{c.kind}</span><p>{c.about}</p></div>
                <span className="meta"><span>{count(c) ? plural(count(c), "key") : "No keys"}</span><span>{kms.clientUsed(c) === null ? "Never used" : `Used ${ago(kms.clientUsed(c))}`}</span></span>
                <a className="btn sm" href={clientHref(c.name)}>Edit access</a>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** A log of key operations and admin changes. Filter by result or search. */
function Activity({ say }: PageProps) {
  const kms = useKms(say);
  const [res, setRes] = useState("any");
  const [q, setQ] = useState("");
  const needle = q.trim().toLowerCase();
  const rows = kms.log.filter((r) => (res === "any" || (res === "denied") === !!r.why) && `${r.key} ${r.client} ${r.about ?? ""}`.includes(needle));
  return (
    <section>
      <Head title="Activity" sub="Every encrypt, decrypt, sign and verify request, and every change made in this console." />
      <div className="toolbar">
        <Sel label="Filter by result" value={res} onChange={setRes} options={[["any", "Any result"], ["ok", "OK"], ["denied", "Denied"]]} />
        <label className="search push"><span className="sr-only">Find by key or client</span><Icon name="search" /><input type="search" placeholder="Find a key or client" value={q} onChange={(x) => setQ(x.target.value)} /></label>
      </div>
      {rows.length === 0 ? (
        <Empty icon="doc">No activity matches. <button type="button" className="btn sm quiet" onClick={() => { setRes("any"); setQ(""); }}>Clear filters</button></Empty>
      ) : <LogTable rows={rows} kms={kms} />}
    </section>
  );
}

const LABELS: Record<keyof Cfg, string> = { rotation: "default rotation", wait: "deletion wait", root: "root key", aws: "AWS connection" };

/** KMS rules: rotation default, deletion wait, and where the root key lives. */
function Settings({ say }: PageProps) {
  const kms = useKms(say);
  const saved = kms.cfg;
  const [draft, setDraft] = useState<Cfg | null>(null);
  const s = draft ?? saved;
  const changed = (Object.keys(LABELS) as (keyof Cfg)[]).filter((x) => s[x] !== saved[x]);
  const awsConns = connections.filter((c) => c.provider === "AWS");
  const set = (k: keyof Cfg, val: string | number) => setDraft({ ...s, [k]: val });
  const pick = (k: "root" | "aws", label: string, options: string[]) => <Sel label={label} value={s[k]} onChange={(x) => set(k, x)} options={options.map((o): [string, string] => [o, o])} />;
  return (
    <form className="settings" onSubmit={(ev) => { ev.preventDefault(); kms.setCfg(s); kms.admin(`Changed KMS settings: ${changed.map((x) => LABELS[x]).join(", ")}`); setDraft(null); }}>
      <div className="screen-head"><div><h1>Settings</h1><p className="lede">Rules that apply to every key in this workspace.</p></div></div>
      <section className="panel" aria-labelledby="kms-keys">
        <h2 id="kms-keys">Keys</h2>
        <Row title="Default rotation" about="The rotation a new key starts with. Rotating adds a new version; older versions still open data they protected."><Sel label="Default rotation" value={String(s.rotation)} onChange={(x) => set("rotation", Number(x))} options={ROTATIONS.map(([n, t]) => [String(n), t])} /></Row>
        <Row title="Wait before a deletion takes effect" about="A deleted key is disabled for this long and can be brought back. After that, data it protects cannot be read."><Sel label="Wait before deletion" value={String(s.wait)} onChange={(x) => set("wait", Number(x))} options={[7, 14, 30].map((n): [string, string] => [String(n), days(n)])} /></Row>
      </section>
      <section className="panel" aria-labelledby="kms-root">
        <h2 id="kms-root">Root key</h2>
        <Row title="Where the root key lives" about="The root key protects all other keys. It is set when the workspace is created, so changing it re-wraps every key.">{pick("root", "Where the root key lives", ["Locksmith-managed", "Your own AWS KMS"])}</Row>
        {s.root === "Your own AWS KMS" && (
          <Row title="AWS connection" about="Locksmith asks your AWS account to unwrap keys. If you turn that off in AWS, every key stops working at once.">
            {awsConns.length ? pick("aws", "AWS connection", awsConns.map((c) => c.name)) : <span className="fixed">No AWS connection yet. Add one in Integrations.</span>}
          </Row>
        )}
      </section>
      {changed.length > 0 && (
        <div className="savebar" role="status">
          <span>You have unsaved changes.</span>
          <button type="button" className="btn quiet" onClick={() => setDraft(null)}>Discard</button>
          <button type="submit" className="btn primary">Save changes</button>
        </div>
      )}
    </form>
  );
}

export const pages: Pages = { "keys/keys": Keys, "keys/clients": Clients, "keys/activity": Activity, "keys/settings": Settings };
