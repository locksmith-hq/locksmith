// Access Broker: databases and servers reached through brokered, recorded sessions. Sample data only.
// All five pages and their detail views read one shared store, so a change on one page shows on the others.
import { useState } from "react";
import {
  Crumbs,
  Empty,
  Head,
  Icon,
  MIN,
  HOUR,
  DAY,
  NOW,
  Switch,
  agents,
  ago,
  createStore,
  members,
  plural,
  type PageProps,
  type Pages,
} from "../kit";
import "../settings.css";
import "./broker.css";

const kinds = ["Postgres", "MySQL", "SSH server", "Kubernetes"] as const;
type Kind = (typeof kinds)[number];
const ME = "Tomer Levy";
const dur = (s: number) =>
  s < MIN
    ? `${Math.max(0, s)}s`
    : s < HOUR
      ? `${Math.floor(s / MIN)}m ${s % MIN}s`
      : `${Math.floor(s / HOUR)}h ${Math.floor((s % HOUR) / MIN)}m`;
const people = [
  ...members.map((m) => m.name),
  "Group: Platform",
  "Group: Billing",
  ...agents.map((a) => `Agent: ${a.name}`),
];
const whoOptions = [...members.map((m) => m.name), ...agents.map((a) => `Agent: ${a.name}`)];
const MAXLEN: Record<string, number> = { "1 hour": HOUR, "4 hours": 4 * HOUR, "8 hours": 8 * HOUR };

const H = "#/app/broker";
const dec = (s: string) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};
const sl = (id: string) => `${H}/sessions/${encodeURIComponent(id)}`;
const cl = (id: string) => `${H}/recordings/${encodeURIComponent(id)}`;

type Level = "read" | "write" | "admin";
const LEVEL: Record<Level, string> = { read: "Read only", write: "Read and write", admin: "Administrator" };

interface Acct {
  id: string;
  name: string;
  res: string;
  level: Level;
  who: string[];
}
const A = (name: string, res: string, level: Level, who: string[]): Acct => ({
  id: `${name}@${res}`,
  name,
  res,
  level,
  who,
});
const ACCTS: Acct[] = [
  A("readonly", "billing-db", "read", ["Group: Billing", "Agent: codex-billing"]),
  A("admin", "billing-db", "admin", ["Dana Okafor", "Tomer Levy"]),
  A("readonly", "orders-db", "read", ["Group: Platform", "Agent: claude-laptop"]),
  A("migrate", "orders-db", "write", ["Agent: ci-deploy"]),
  A("report", "analytics-mysql", "read", ["Group: Billing", "Lea Fischer"]),
  A("deploy", "web-1.internal.acme.example", "write", ["Agent: ci-deploy", "Ravi Menon"]),
  A("deploy", "web-2.internal.acme.example", "write", ["Agent: ci-deploy"]),
  A("ops", "web-1.internal.acme.example", "admin", ["Tomer Levy"]),
  A("viewer", "prod-eks", "read", ["Group: Platform", "Agent: review-bot"]),
  A("readonly", "staging-db", "read", ["Group: Platform", "Agent: claude-laptop"]),
];

interface Res {
  name: string;
  kind: Kind;
  where: string;
  problem?: string;
  fix?: string;
}
const RES: Res[] = [
  { name: "billing-db", kind: "Postgres", where: "Production · eu-west-1 private network" },
  { name: "orders-db", kind: "Postgres", where: "Production · eu-west-1 private network" },
  { name: "analytics-mysql", kind: "MySQL", where: "Staging · us-east-1 private network" },
  {
    name: "staging-db",
    kind: "Postgres",
    where: "Staging · us-east-1 private network",
    problem: "Connection refused on port 5432",
    fix: "Check that the database is running and that its firewall lets the broker in, then test again.",
  },
  { name: "web-1.internal.acme.example", kind: "SSH server", where: "Production · office VPN" },
  { name: "web-2.internal.acme.example", kind: "SSH server", where: "Production · office VPN" },
  {
    name: "prod-eks",
    kind: "Kubernetes",
    where: "Production · AWS account Production",
    problem: "Certificate expired 2 days ago",
    fix: "Renew the cluster's API certificate, then test again.",
  },
];

interface Sess {
  id: string;
  who: string;
  acct: string;
  res: string;
  started: number;
  ended: number | null;
  how: string;
  reason: string;
  by: string;
}
const S = (
  id: string,
  who: string,
  acct: string,
  res: string,
  startedAgo: number,
  endedAgo: number | null,
  how: string,
  reason: string,
  by: string,
): Sess => ({
  id,
  who,
  acct,
  res,
  started: NOW - startedAgo,
  ended: endedAgo === null ? null : NOW - endedAgo,
  how,
  reason,
  by,
});
const SESS: Sess[] = [
  S(
    "ses_8f2",
    "Agent: codex-billing",
    "readonly",
    "billing-db",
    12 * MIN,
    null,
    "",
    "Count overdue invoices for the month-end report",
    "Dana Okafor",
  ),
  S(
    "ses_8f1",
    "Dana Okafor",
    "admin",
    "billing-db",
    3 * HOUR + 20 * MIN,
    null,
    "",
    "Fix a stuck payout batch",
    "Tomer Levy",
  ),
  S(
    "ses_8e9",
    "Agent: ci-deploy",
    "deploy",
    "web-1.internal.acme.example",
    6 * MIN,
    null,
    "",
    "Deploy acme-web 4.18.2",
    "Ravi Menon",
  ),
  S(
    "ses_8e4",
    "Agent: claude-laptop",
    "readonly",
    "orders-db",
    41 * MIN,
    null,
    "",
    "Find why order 5512 shows no shipping date",
    "Tomer Levy",
  ),
  S(
    "ses_8d7",
    "Ravi Menon",
    "deploy",
    "web-1.internal.acme.example",
    3 * HOUR,
    2 * HOUR + 10 * MIN,
    "Ended by Ravi Menon",
    "Roll out the login redirect fix",
    "Dana Okafor",
  ),
  S(
    "ses_8d2",
    "Agent: review-bot",
    "viewer",
    "prod-eks",
    5 * HOUR,
    4 * HOUR + 30 * MIN,
    "Ended by the agent",
    "Check the api deployment before reviewing PR 912",
    "Tomer Levy",
  ),
  S(
    "ses_8c8",
    "Tomer Levy",
    "ops",
    "web-1.internal.acme.example",
    4 * DAY,
    4 * DAY - 70 * MIN,
    "Time limit reached",
    "Disk is filling up on web-1",
    "Dana Okafor",
  ),
  S(
    "ses_8c1",
    "Lea Fischer",
    "report",
    "analytics-mysql",
    5 * HOUR + 20 * MIN,
    5 * HOUR,
    "Ended by Lea Fischer",
    "Weekly plan breakdown",
    "Not needed",
  ),
  S(
    "ses_8b6",
    "Agent: ci-deploy",
    "migrate",
    "orders-db",
    3 * DAY,
    3 * DAY - 90,
    "Ended by the agent",
    "Add shipped_at to orders",
    "Tomer Levy",
  ),
  S(
    "ses_8b2",
    "Agent: codex-billing",
    "readonly",
    "billing-db",
    26 * HOUR,
    26 * HOUR - 8 * MIN,
    "Terminated by Dana Okafor",
    "Look at failed payouts",
    "Dana Okafor",
  ),
];

type Line = [at: number, text: string, flag?: string, end?: boolean];
const DROP = "Flagged: DROP deletes a whole table and everything in it.";
const RM = "Flagged: rm -rf deletes files and folders without asking.";
const CONNECTED: Line = [0, "Connected through the broker. The password was typed in for you and is not shown."];
/** What a live session has run so far (lines are shown up to the time the session has been open). */
const LIVE: Record<string, Line[]> = {
  ses_8f2: [
    [2, "SELECT count(*) FROM invoices WHERE status = 'overdue';"],
    [31, "SELECT id, total FROM invoices WHERE customer_email = '[redacted]' LIMIT 20;"],
    [95, "\\d payouts"],
    [240, "SELECT date_trunc('day', paid_at) AS day, sum(total) FROM payouts GROUP BY 1 ORDER BY 1 DESC LIMIT 30;"],
    [
      412,
      "UPDATE invoices SET status = 'void' WHERE id = 4411;",
      "Flagged: this account is read-only, so the database refused the change.",
    ],
    [640, "SELECT * FROM refunds ORDER BY created_at DESC LIMIT 10;"],
  ],
  ses_8f1: [
    [6, "\\dt"],
    [40, "SELECT id, status, attempts FROM payout_batches WHERE status = 'stuck';"],
    [300, "UPDATE payout_batches SET status = 'retry' WHERE id = 3318;"],
    [900, "SELECT count(*) FROM payouts WHERE batch_id = 3318;"],
    [4200, "TRUNCATE payouts_staging;"],
    [9000, "SELECT status, count(*) FROM payout_batches GROUP BY 1;"],
  ],
  ses_8e9: [
    [4, "cd /srv/acme-web && git pull --ff-only"],
    [30, "npm ci --omit=dev"],
    [120, "sudo systemctl restart acme-web"],
    [200, "sudo shutdown -h now"],
    [240, "journalctl -u acme-web -n 20 --no-pager"],
  ],
  ses_8e4: [
    [5, "\\d orders"],
    [60, "SELECT id, status, shipped_at FROM orders WHERE id = 5512;"],
    [420, "SELECT count(*) FROM orders WHERE shipped_at IS NULL AND status = 'shipped';"],
    [1500, "SELECT id FROM orders WHERE shipped_at IS NULL AND status = 'shipped' LIMIT 20;"],
  ],
};
const ENDED: Record<string, Line[]> = {
  ses_8d7: [
    [3, "cd /srv/acme-web && git pull --ff-only"],
    [20, "npm ci --omit=dev"],
    [88, "sudo systemctl restart acme-web"],
    [96, "journalctl -u acme-web -n 50 --no-pager"],
    [610, "export API_TOKEN=[redacted]"],
    [1200, "rm -rf .cache", RM],
    [2400, "systemctl status acme-web"],
  ],
  ses_8c8: [
    [5, "df -h"],
    [40, "du -sh /var/log/*"],
    [300, "sudo logrotate -f /etc/logrotate.conf"],
    [1800, "tail -n 200 /var/log/nginx/error.log"],
    [3600, "uptime"],
  ],
  ses_8b6: [
    [1, "BEGIN;"],
    [3, "ALTER TABLE orders ADD COLUMN shipped_at timestamptz;"],
    [8, "CREATE INDEX CONCURRENTLY orders_shipped_idx ON orders (shipped_at);"],
    [30, "TRUNCATE orders_scratch;"],
    [40, "DROP TABLE orders_backup_2024;", DROP],
    [44, "COMMIT;"],
  ],
  ses_8c1: [
    [4, "SHOW TABLES;"],
    [30, "SELECT plan, count(*) FROM subscriptions GROUP BY plan;"],
    [210, "SELECT email FROM users WHERE id = 8812; -- email shown as [redacted]"],
    [900, "SELECT avg(duration_ms) FROM api_calls WHERE day = CURDATE();"],
  ],
  ses_8d2: [
    [2, "kubectl get pods -n acme-api"],
    [25, "kubectl describe deployment acme-api -n acme-api"],
    [140, "kubectl logs deploy/acme-api --tail=100"],
    [700, "kubectl get events --sort-by=.lastTimestamp"],
  ],
  ses_8b2: [
    [3, "SELECT sum(total) FROM refunds WHERE created_at > now() - interval '7 days';"],
    [120, "SELECT * FROM payouts WHERE status = 'failed';"],
    [300, "SELECT customer_email FROM invoices LIMIT 5; -- emails shown as [redacted]"],
  ],
};
/** "Terminated by Dana Okafor" reads "Session terminated by Dana Okafor"; "Time limit reached" reads "Session ended: time limit reached". */
const finalText = (how: string) =>
  /^(Terminated|Ended) by/.test(how)
    ? `Session ${how[0]!.toLowerCase()}${how.slice(1)}`
    : `Session ended: ${how.toLowerCase()}`;
const SEED_RECS: Record<string, Line[]> = Object.fromEntries(
  Object.entries(ENDED).map(([id, lines]) => {
    const s = SESS.find((x) => x.id === id)!;
    return [id, [...lines, [s.ended! - s.started, finalText(s.how), undefined, true] as Line]];
  }),
);

interface Req {
  id: string;
  who: string;
  acct: string;
  reason: string;
  asked: number;
  status: "waiting" | "denied";
  by?: string;
}
const REQS: Req[] = [
  {
    id: "req_1",
    who: "Ravi Menon",
    acct: "deploy@web-1.internal.acme.example",
    reason: "Hotfix for the login redirect loop",
    asked: NOW - 4 * MIN,
    status: "waiting",
  },
  {
    id: "req_2",
    who: "Lea Fischer",
    acct: "readonly@billing-db",
    reason: "Check overdue invoices for month-end",
    asked: NOW - 11 * MIN,
    status: "waiting",
  },
];
interface Cfg {
  maxLen: string;
  approval: string;
  keep: string;
  blocked: string[];
}
const CFG: Cfg = {
  maxLen: "4 hours",
  approval: "Production only",
  keep: "1 year",
  blocked: ["rm -rf /", "DROP DATABASE", "TRUNCATE", "shutdown"],
};

interface World {
  res: Res[];
  accts: Acct[];
  sess: Sess[];
  recs: Record<string, Line[]>;
  reqs: Req[];
  cfg: Cfg;
  seq: number;
}
const useBroker = createStore<World>({
  res: RES,
  accts: ACCTS,
  sess: SESS,
  recs: SEED_RECS,
  reqs: REQS,
  cfg: CFG,
  seq: 10,
});
type SetWorld = (f: (w: World) => World) => void;

// ---- rules, written as plain functions of the shared data ----
const teamOf = (n: string) => members.find((m) => m.name === n)?.team;
const allowed = (a: Acct, who: string) => a.who.includes(who) || a.who.includes(`Group: ${teamOf(who)}`);
const needsApproval = (c: Cfg, r: Res) =>
  c.approval === "Always" || (c.approval === "Production only" && r.where.startsWith("Production"));
const maxSecs = (c: Cfg) => MAXLEN[c.maxLen] ?? 4 * HOUR;
const left = (w: World, s: Sess) => Math.max(0, s.started + maxSecs(w.cfg) - NOW);
const live = (w: World) => w.sess.filter((s) => s.ended === null);
const liveLines = (s: Sess): Line[] => (LIVE[s.id] ?? [CONNECTED]).filter((l) => l[0] <= NOW - s.started);
const idOf = (s: { acct: string; res: string }) => `${s.acct}@${s.res}`;
const cmdOf = (s: { acct: string; res: string }) => `smith connect ${s.res} --as ${s.acct}`;
const lastUsed = (w: World, a: Acct) => {
  const ss = w.sess.filter((s) => idOf(s) === a.id);
  return ss.some((s) => s.ended === null)
    ? "In use now"
    : ss.length
      ? ago(Math.max(...ss.map((s) => s.ended!)))
      : "never";
};
/** A line is blocked when it contains a blocked command; otherwise it may carry its own flag. */
const flagOf = (l: Line, blocked: string[]): { text: string; hard: boolean } | null => {
  if (l[3]) return null;
  const b = blocked.find((x) => l[1].toLowerCase().includes(x.toLowerCase()));
  return b
    ? { text: `Blocked: never ran. It contains “${b}”, which is on the blocked list.`, hard: true }
    : l[2]
      ? { text: l[2], hard: false }
      : null;
};

/** Ends live sessions and records why. The broker rotates the account password after every session. */
function endSessions(w: World, pick: (s: Sess) => boolean, how: string): World {
  const hit = w.sess.filter((s) => s.ended === null && pick(s));
  if (!hit.length) return w;
  const ids = new Set(hit.map((s) => s.id));
  const recs = { ...w.recs };
  for (const s of hit) recs[s.id] = [...liveLines(s), [NOW - s.started, finalText(how), undefined, true]];
  return { ...w, recs, sess: w.sess.map((s) => (ids.has(s.id) ? { ...s, ended: NOW, how } : s)) };
}
const openSession = (w: World, who: string, acct: string, reason: string, by: string): World => {
  const a = w.accts.find((x) => x.id === acct);
  if (!a) return w;
  const s: Sess = {
    id: `ses_9${String(w.seq).padStart(2, "0")}`,
    who,
    acct: a.name,
    res: a.res,
    started: NOW,
    ended: null,
    how: "",
    reason,
    by,
  };
  return { ...w, seq: w.seq + 1, sess: [s, ...w.sess] };
};
const setWho = (w: World, id: string, who: string[]): World => {
  const accts = w.accts.map((a) => (a.id === id ? { ...a, who } : a));
  const a = accts.find((x) => x.id === id);
  return a ? endSessions({ ...w, accts }, (s) => idOf(s) === id && !allowed(a, s.who), "Access removed") : w;
};
const removeAcct = (w: World, id: string): World => {
  const n = endSessions(w, (s) => idOf(s) === id, "Account removed");
  return { ...n, accts: n.accts.filter((a) => a.id !== id), reqs: n.reqs.filter((r) => r.acct !== id) };
};
const removeRes = (w: World, name: string): World => {
  const n = endSessions(w, (s) => s.res === name, "Resource removed");
  return {
    ...n,
    res: n.res.filter((r) => r.name !== name),
    accts: n.accts.filter((a) => a.res !== name),
    reqs: n.reqs.filter((r) => !r.acct.endsWith(`@${name}`)),
  };
};
const terminate = (set: SetWorld, s: Sess, say: PageProps["say"]) => {
  set((w) => endSessions(w, (x) => x.id === s.id, `Terminated by ${ME}`));
  say(`Ended ${s.who}'s session on ${s.res}`);
};

async function copyText(text: string, what: string, say: PageProps["say"]) {
  try {
    await navigator.clipboard.writeText(text);
    say(`${what} copied`);
  } catch {
    say(`Could not copy the ${what.toLowerCase()}: the browser blocked clipboard access. Select it and copy by hand.`);
  }
}
function saveText(name: string, text: string, say: PageProps["say"]) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  say(`Downloaded ${name}`);
}

// ---- small shared pieces ----
const Health = ({ r }: { r: Res }) =>
  r.problem ? (
    <span className="br-health" data-ok="false">
      <Icon name="alert" />
      Cannot connect: {r.problem}
    </span>
  ) : (
    <span className="br-health" data-ok="true">
      Reachable
    </span>
  );

const NotFound = ({ what, id, back }: { what: string; id: string; back: [string, string] }) => (
  <section>
    <Crumbs trail={[[back[0], back[1]], [id]]} />
    <Empty icon="search">
      <b>
        No {what} called “{id}”.
      </b>{" "}
      It may have been removed.{" "}
      <a className="link" href={back[1]}>
        Back to {back[0].toLowerCase()}
      </a>
    </Empty>
  </section>
);

const Facts = ({ rows }: { rows: [string, React.ReactNode][] }) => (
  <dl className="br-facts">
    {rows.map(([k, v]) => (
      <div key={k}>
        <dt>{k}</dt>
        <dd>{v}</dd>
      </div>
    ))}
  </dl>
);

const CommandBox = ({ cmd, say }: { cmd: string; say: PageProps["say"] }) => (
  <div className="br-cmd">
    <code>{cmd}</code>
    <button type="button" className="btn sm" onClick={() => void copyText(cmd, "Command", say)}>
      Copy command
    </button>
  </div>
);

const Tx = ({ lines, blocked, q = "" }: { lines: Line[]; blocked: string[]; q?: string }) => {
  const shown = lines.filter((l) => l[1].toLowerCase().includes(q.trim().toLowerCase()));
  if (!shown.length)
    return <p className="muted">{q.trim() ? `No line matches “${q}”.` : "Nothing has been run yet."}</p>;
  return (
    <ol className="br-tx">
      {shown.map((l) => {
        const f = flagOf(l, blocked);
        return (
          <li key={`${l[0]}-${l[1]}`} data-flag={!!f} data-blocked={f?.hard ?? false} data-end={!!l[3]}>
            <time className="mono muted">{dur(l[0])}</time>
            <code>{l[1]}</code>
            {f && (
              <p className="flag">
                <Icon name={f.hard ? "block" : "alert"} /> {f.text}
              </p>
            )}
          </li>
        );
      })}
    </ol>
  );
};

const WhoEditor = ({
  label,
  draft,
  setDraft,
}: {
  label: string;
  draft: string[];
  setDraft: (f: (d: string[]) => string[]) => void;
}) => (
  <fieldset className="br-fs">
    <legend className="strong">{label}</legend>
    <div className="br-edit">
      {people.map((p) => (
        <label key={p}>
          <input
            type="checkbox"
            checked={draft.includes(p)}
            onChange={(e) => setDraft((d) => (e.target.checked ? [...d, p] : d.filter((x) => x !== p)))}
          />
          {p}
        </label>
      ))}
    </div>
    {draft.length === 0 && <p className="hint">With nobody selected, no one can open a session with this account.</p>}
  </fieldset>
);

// ---- Start a session: pick who, resource, an allowed account and a reason ----
function StartPanel({ onClose, say }: { onClose: () => void; say: PageProps["say"] }) {
  const [w, set] = useBroker();
  const [who, setWho] = useState(ME);
  const [res, setRes] = useState(w.res[0]?.name ?? "");
  const [pick, setPick] = useState("");
  const [reason, setReason] = useState("");
  const [done, setDone] = useState<{ kind: "open"; id: string; cmd: string } | { kind: "ask" } | null>(null);
  const r = w.res.find((x) => x.name === res);
  const options = w.accts.filter((a) => a.res === res && allowed(a, who));
  const chosen = options.find((a) => a.id === pick) ?? options[0];
  const ask = r ? needsApproval(w.cfg, r) : false;
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!chosen || !r || r.problem) return;
    if (ask) {
      set((x) => ({
        ...x,
        seq: x.seq + 1,
        reqs: [
          ...x.reqs,
          { id: `req_${x.seq}`, who, acct: chosen.id, reason: reason.trim(), asked: NOW, status: "waiting" },
        ],
      }));
      setDone({ kind: "ask" });
      say(`Asked for approval to use ${chosen.id}`);
    } else {
      setDone({
        kind: "open",
        id: `ses_9${String(w.seq).padStart(2, "0")}`,
        cmd: cmdOf({ acct: chosen.name, res: chosen.res }),
      });
      set((x) => openSession(x, who, chosen.id, reason.trim(), "Not needed"));
      say(`Session opened on ${chosen.res}`);
    }
  };
  if (done) {
    return (
      <div className="panel form" role="status">
        {done.kind === "open" ? (
          <>
            <h2>Session {done.id} is open</h2>
            <p className="muted small">
              Run this in a terminal to connect. The password is never shown: the broker types it in for you.
            </p>
            <CommandBox cmd={done.cmd} say={say} />
            <div className="inline-form">
              <a className="btn sm primary" href={sl(done.id)}>
                Open session
              </a>
              <button type="button" className="btn sm quiet" onClick={onClose}>
                Close
              </button>
            </div>
          </>
        ) : (
          <>
            <h2>Waiting for approval</h2>
            <p className="muted small">
              Your request is in the “Waiting for approval” list on Sessions. A second person approves it, and then the
              session opens.
            </p>
            <div className="inline-form">
              <a className="btn sm primary" href={`${H}/sessions`}>
                See requests
              </a>
              <button type="button" className="btn sm quiet" onClick={onClose}>
                Close
              </button>
            </div>
          </>
        )}
      </div>
    );
  }
  return (
    <form className="panel form" onSubmit={submit} aria-label="Start a session">
      <h2>Start a session</h2>
      <div className="br-start">
        <label className="field">
          Who
          <select value={who} onChange={(e) => setWho(e.target.value)}>
            {whoOptions.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
        </label>
        <label className="field">
          Resource
          <select value={res} onChange={(e) => setRes(e.target.value)}>
            {w.res.map((x) => (
              <option key={x.name}>{x.name}</option>
            ))}
          </select>
        </label>
        <label className="field">
          Account
          <select value={chosen?.id ?? ""} disabled={options.length === 0} onChange={(e) => setPick(e.target.value)}>
            {options.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({LEVEL[a.level].toLowerCase()})
              </option>
            ))}
          </select>
        </label>
        <label className="field br-reason">
          Reason
          <input
            value={reason}
            required
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why this session is needed"
            autoComplete="off"
          />
        </label>
      </div>
      {!r && <p className="hint">Add a resource first, so there is something to connect to.</p>}
      {r && options.length === 0 && (
        <p className="hint">
          {who} has no account on {res}. Ask an admin to add {who} to one of its accounts under{" "}
          <a className="link" href={`${H}/accounts`}>
            Accounts
          </a>
          , or pick another resource.
        </p>
      )}
      {r?.problem && (
        <p className="hint prod">
          {res} cannot be reached right now ({r.problem}), so a session cannot open. Fix the connection first.
        </p>
      )}
      {chosen && !r?.problem && (
        <p className="hint">
          {ask
            ? `${res} needs approval (${w.cfg.approval.toLowerCase()}). This sends a request and nothing connects until a second person approves.`
            : "No approval is needed. The session opens at once and is recorded."}
        </p>
      )}
      <div className="inline-form" style={{ marginTop: 12 }}>
        <button type="submit" className="btn primary" disabled={!chosen || !r || !!r.problem}>
          {ask ? "Ask for approval" : "Start session"}
        </button>
        <button type="button" className="btn quiet" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}

// ---- Resources ----
function Resources({ say }: PageProps) {
  const [w, set] = useBroker();
  const [kind, setKind] = useState<Kind | "All">("All");
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const shown = w.res.filter((r) => kind === "All" || r.kind === kind);
  const add = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const name = String(f.get("name")).trim().toLowerCase();
    if (w.res.some((r) => r.name === name)) {
      setErr(`There is already a resource called ${name}.`);
      return;
    }
    set((x) => ({
      ...x,
      res: [...x.res, { name, kind: String(f.get("kind")) as Kind, where: String(f.get("where")).trim() }],
    }));
    say(`Added ${name}`);
    setAdding(false);
    setErr("");
  };
  return (
    <section>
      <Head
        title="Resources"
        sub="The databases and servers people and agents can reach through the broker, without ever holding a password."
      >
        <button type="button" className="btn primary" disabled={adding} onClick={() => setAdding(true)}>
          <Icon name="plus" />
          Add resource
        </button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add resource">
          <h2>Add a resource</h2>
          <div className="add share">
            <label className="field">
              Name
              <input
                name="name"
                required
                autoFocus
                placeholder="reports-db"
                autoComplete="off"
                onChange={() => setErr("")}
              />
            </label>
            <label className="field">
              Kind
              <select name="kind">
                {kinds.map((k) => (
                  <option key={k}>{k}</option>
                ))}
              </select>
            </label>
            <label className="field">
              Where it is
              <input name="where" required placeholder="Production · eu-west-1" autoComplete="off" />
            </label>
            <button type="submit" className="btn primary">
              Add resource
            </button>
            <button
              type="button"
              className="btn quiet"
              onClick={() => {
                setAdding(false);
                setErr("");
              }}
            >
              Cancel
            </button>
          </div>
          {err && (
            <p className="hint prod" role="alert">
              {err}
            </p>
          )}
          <p className="hint">
            The broker connects from inside your network, so the resource needs no public address. Start the place with
            “Production” or “Staging” so approval rules apply. Add an account next, so someone can connect.
          </p>
        </form>
      )}
      <div className="toolbar">
        <fieldset className="seg inline">
          <legend className="sr-only">Kind</legend>
          {(["All", ...kinds] as const).map((k) => (
            <label key={k}>
              <input type="radio" name="res-kind" checked={kind === k} onChange={() => setKind(k)} />
              {k}
              <span className="n">{k === "All" ? w.res.length : w.res.filter((r) => r.kind === k).length}</span>
            </label>
          ))}
        </fieldset>
      </div>
      {shown.length === 0 ? (
        <Empty icon="db">
          <b>{kind === "All" ? "No resources yet." : `No ${kind} resources.`}</b> Add a database or server so the broker
          can open sessions to it.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th>Resource</th>
                <th>Kind</th>
                <th>Where</th>
                <th>Accounts</th>
                <th>Live now</th>
                <th>Health</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.flatMap((r) => {
                const accts = w.accts.filter((a) => a.res === r.name).length;
                const n = live(w).filter((s) => s.res === r.name).length;
                return [
                  <tr key={r.name}>
                    <td className="strong">{r.name}</td>
                    <td>{r.kind}</td>
                    <td className="muted">{r.where}</td>
                    <td>{accts}</td>
                    <td>
                      {n > 0 ? (
                        <span className="br-live">
                          <i />
                          {n}
                        </span>
                      ) : (
                        <span className="muted">0</span>
                      )}
                    </td>
                    <td>
                      <Health r={r} />
                      {r.fix && (
                        <p className="muted small" style={{ margin: "2px 0 0" }}>
                          {r.fix}
                        </p>
                      )}
                    </td>
                    <td className="num">
                      <button
                        type="button"
                        className="btn sm quiet danger-text"
                        aria-label={`Remove ${r.name}`}
                        onClick={() => setRemoving(r.name)}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>,
                  removing === r.name && (
                    <tr key={`${r.name}-x`} className="detail">
                      <td colSpan={7}>
                        <p className="alert" role="alert" style={{ margin: 0 }}>
                          Removing {r.name} deletes {plural(accts, "account")} from the broker and ends{" "}
                          {plural(n, "live session")} at once. Past recordings are kept.
                          <button
                            type="button"
                            className="btn sm danger"
                            onClick={() => {
                              set((x) => removeRes(x, r.name));
                              setRemoving(null);
                              say(`Removed ${r.name}`);
                            }}
                          >
                            Remove anyway
                          </button>
                          <button type="button" className="btn sm quiet" onClick={() => setRemoving(null)}>
                            Keep
                          </button>
                        </p>
                      </td>
                    </tr>
                  ),
                ];
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

// ---- Accounts ----
function Accounts({ say }: PageProps) {
  const [w, set] = useBroker();
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState<string[]>([]);
  const [err, setErr] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [who, setWhoDraft] = useState<string[]>([]);
  const [removing, setRemoving] = useState(false);
  const add = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const res = String(f.get("res"));
    const name = String(f.get("name")).trim().toLowerCase();
    if (w.accts.some((a) => a.id === `${name}@${res}`)) {
      setErr(`${res} already has an account called ${name}.`);
      return;
    }
    set((x) => ({
      ...x,
      accts: [...x.accts, { id: `${name}@${res}`, name, res, level: String(f.get("level")) as Level, who: draft }],
    }));
    say(`Added ${name} on ${res}`);
    setAdding(false);
    setDraft([]);
    setErr("");
  };
  const open = (a: Acct) => {
    setEditing(a.id);
    setWhoDraft(a.who);
    setRemoving(false);
  };
  const edited = w.accts.find((a) => a.id === editing);
  const dropped = edited ? live(w).filter((s) => idOf(s) === editing && !allowed({ ...edited, who }, s.who)) : [];
  return (
    <section>
      <Head
        title="Accounts"
        sub="The privileged logins the broker holds on each resource. People and agents borrow them for a session; nobody is ever shown the password."
      >
        <button
          type="button"
          className="btn primary"
          disabled={adding || w.res.length === 0}
          onClick={() => setAdding(true)}
        >
          <Icon name="plus" />
          Add account
        </button>
      </Head>
      {adding && (
        <form className="panel form" onSubmit={add} aria-label="Add account">
          <h2>Add an account</h2>
          <div className="br-start">
            <label className="field">
              Resource
              <select name="res">
                {w.res.map((r) => (
                  <option key={r.name}>{r.name}</option>
                ))}
              </select>
            </label>
            <label className="field">
              Name
              <input
                name="name"
                required
                autoFocus
                placeholder="readonly"
                autoComplete="off"
                onChange={() => setErr("")}
              />
            </label>
            <label className="field">
              What it can do
              <select name="level" defaultValue="read">
                {(Object.keys(LEVEL) as Level[]).map((l) => (
                  <option key={l} value={l}>
                    {LEVEL[l]}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <WhoEditor label="Who may use it" draft={draft} setDraft={setDraft} />
          {err && (
            <p className="hint prod" role="alert">
              {err}
            </p>
          )}
          <div className="inline-form">
            <button type="submit" className="btn primary">
              Add account
            </button>
            <button
              type="button"
              className="btn quiet"
              onClick={() => {
                setAdding(false);
                setErr("");
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      {w.accts.length === 0 ? (
        <Empty icon="sessions">
          <b>No accounts.</b> Add an account to a resource so someone can connect to it.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th>Account</th>
                <th>Can do</th>
                <th>Who may use it</th>
                <th>Last used</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {w.accts.flatMap((a) => [
                <tr key={a.id}>
                  <td>
                    <span className="strong mono">{a.name}</span>
                    <br />
                    <span className="muted small">on {a.res}</span>
                  </td>
                  <td>{LEVEL[a.level]}</td>
                  <td>
                    <ul className="br-who" aria-label={`Who may use ${a.id}`}>
                      {a.who.length ? a.who.map((p) => <li key={p}>{p}</li>) : <li>Nobody</li>}
                    </ul>
                  </td>
                  <td className="muted">{lastUsed(w, a)}</td>
                  <td className="num">
                    <button
                      type="button"
                      className="btn sm quiet"
                      aria-expanded={editing === a.id}
                      aria-label={`Change access for ${a.id}`}
                      onClick={() => (editing === a.id ? setEditing(null) : open(a))}
                    >
                      Change access
                    </button>
                  </td>
                </tr>,
                editing === a.id && (
                  <tr key={`${a.id}-x`} className="detail">
                    <td colSpan={5}>
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          set((x) => setWho(x, a.id, who));
                          say(
                            dropped.length
                              ? `Saved. Ended ${plural(dropped.length, "session")} for people who lost access.`
                              : `Updated ${a.id}`,
                          );
                          setEditing(null);
                        }}
                      >
                        <WhoEditor label="People, groups and agents" draft={who} setDraft={setWhoDraft} />
                        {dropped.length > 0 && (
                          <p className="hint prod" role="status">
                            Saving ends {plural(dropped.length, "live session")}: {dropped.map((s) => s.who).join(", ")}
                            .
                          </p>
                        )}
                        <div className="inline-form" style={{ marginTop: 12 }}>
                          <button type="submit" className="btn sm primary">
                            Save
                          </button>
                          <button type="button" className="btn sm quiet" onClick={() => setEditing(null)}>
                            Cancel
                          </button>
                          {removing ? (
                            <span className="alert" role="alert">
                              Ends {plural(live(w).filter((s) => idOf(s) === a.id).length, "live session")} and nobody
                              can use {a.id} again. Recordings stay.
                              <button
                                type="button"
                                className="btn sm danger"
                                onClick={() => {
                                  set((x) => removeAcct(x, a.id));
                                  say(`Removed ${a.id}`);
                                  setEditing(null);
                                }}
                              >
                                Remove anyway
                              </button>
                              <button type="button" className="btn sm quiet" onClick={() => setRemoving(false)}>
                                Keep
                              </button>
                            </span>
                          ) : (
                            <button
                              type="button"
                              className="btn sm quiet danger-text"
                              onClick={() => setRemoving(true)}
                            >
                              Remove account
                            </button>
                          )}
                        </div>
                      </form>
                    </td>
                  </tr>
                ),
              ])}
            </tbody>
          </table>
        </div>
      )}
      <p className="hint">
        <Icon name="lock" /> Passwords are generated by the broker, stored encrypted and changed after every session.
        They are typed into the connection for you and never appear on screen, in recordings or in logs.
      </p>
    </section>
  );
}

// ---- Sessions ----
function SessionList({ say }: { say: PageProps["say"] }) {
  const [w, set] = useBroker();
  const [view, setView] = useState<"live" | "ended" | "all">("all");
  const [striking, setStriking] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const now = live(w);
  const ended = w.sess.filter((s) => s.ended !== null).sort((a, b) => b.ended! - a.ended!);
  const list = view === "live" ? now : view === "ended" ? ended : [...now, ...ended];
  const stop = (s: Sess) => {
    setStriking(s.id);
    setTimeout(() => {
      terminate(set, s, say);
      setStriking(null);
    }, 480);
  };
  const approve = (r: Req) => {
    const a = w.accts.find((x) => x.id === r.acct);
    const res = w.res.find((x) => x.name === a?.res);
    if (!a || !res || res.problem || !allowed(a, r.who)) {
      set((x) => ({ ...x, reqs: x.reqs.filter((q) => q.id !== r.id) }));
      say(`Dropped the request: ${r.who} can no longer use ${r.acct}, or the resource cannot be reached.`);
      return;
    }
    const by = r.who === ME ? "Dana Okafor" : ME;
    set((x) => ({ ...openSession(x, r.who, r.acct, r.reason, by), reqs: x.reqs.filter((q) => q.id !== r.id) }));
    say(`Approved. ${r.who} can now connect to ${a.res}.`);
  };
  const deny = (r: Req) => {
    set((x) => ({ ...x, reqs: x.reqs.map((q) => (q.id === r.id ? { ...q, status: "denied", by: ME } : q)) }));
    say(`Denied ${r.who}'s request`);
  };
  return (
    <section>
      <Head
        title="Sessions"
        sub="Who is connected through the broker right now, and the sessions that have ended. Terminate cuts a connection at once."
      >
        <button
          type="button"
          className="btn primary"
          aria-expanded={starting}
          disabled={starting}
          onClick={() => setStarting(true)}
        >
          <Icon name="plus" />
          Start a session
        </button>
      </Head>
      {starting && <StartPanel onClose={() => setStarting(false)} say={say} />}
      {w.reqs.length > 0 && (
        <div className="br-sec">
          <div className="sec-h">
            <h2>Waiting for approval</h2>
            <span className="n">{w.reqs.filter((r) => r.status === "waiting").length}</span>
          </div>
          <div className="table-wrap">
            <table className="grid">
              <thead>
                <tr>
                  <th>Who</th>
                  <th>Wants to use</th>
                  <th>Reason</th>
                  <th>Asked</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {w.reqs.map((r) => (
                  <tr key={r.id}>
                    <td className="strong">{r.who}</td>
                    <td>
                      <span className="mono">{r.acct.split("@")[0]}</span>{" "}
                      <span className="muted">on {r.acct.split("@")[1]}</span>
                    </td>
                    <td>{r.reason}</td>
                    <td className="muted">{ago(r.asked)}</td>
                    <td className="num">
                      {r.status === "denied" ? (
                        <>
                          <span className="muted">Denied by {r.by}</span>{" "}
                          <button
                            type="button"
                            className="btn sm quiet"
                            aria-label={`Clear ${r.who}'s denied request`}
                            onClick={() => set((x) => ({ ...x, reqs: x.reqs.filter((q) => q.id !== r.id) }))}
                          >
                            Clear
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            type="button"
                            className="btn sm primary"
                            title={
                              r.who === ME
                                ? "Your own request needs a second person. This stands in for Dana Okafor approving it."
                                : undefined
                            }
                            aria-label={`Approve ${r.who}'s request`}
                            onClick={() => approve(r)}
                          >
                            {r.who === ME ? "Approve as Dana Okafor" : "Approve"}
                          </button>
                          <button
                            type="button"
                            className="btn sm quiet danger-text"
                            aria-label={`Deny ${r.who}'s request`}
                            onClick={() => deny(r)}
                          >
                            Deny
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <div className="toolbar">
        <fieldset className="seg inline">
          <legend className="sr-only">Show</legend>
          {(
            [
              ["all", "All", w.sess.length],
              ["live", "Live", now.length],
              ["ended", "Ended", ended.length],
            ] as const
          ).map(([k, l, n]) => (
            <label key={k}>
              <input type="radio" name="sess-view" checked={view === k} onChange={() => setView(k)} />
              {l}
              <span className="n">{n}</span>
            </label>
          ))}
        </fieldset>
      </div>
      {list.length === 0 ? (
        <Empty icon="clock">
          <b>{view === "live" ? "Nobody is connected." : "No sessions yet."}</b> Sessions appear here as soon as a
          person or agent opens a connection to a resource. Use “Start a session” to open one.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th>Who</th>
                <th>Account on resource</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Status</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.map((s) => (
                <tr key={s.id} className={striking === s.id ? "br-strike" : undefined}>
                  <td>
                    <a className="strong" href={sl(s.id)}>
                      {s.who}
                    </a>
                  </td>
                  <td>
                    <span className="mono">{s.acct}</span> <span className="muted">on {s.res}</span>
                  </td>
                  <td className="muted">{ago(s.started)}</td>
                  <td className="mono">{dur((s.ended ?? NOW) - s.started)}</td>
                  <td>
                    {s.ended === null ? (
                      <span className="br-live">
                        <i />
                        Live<span className="muted small"> · ends in {dur(left(w, s))}</span>
                      </span>
                    ) : (
                      <span className="muted">{s.how}</span>
                    )}
                  </td>
                  <td className="num">
                    {s.ended === null ? (
                      <button
                        type="button"
                        className="btn sm quiet danger-text"
                        disabled={striking !== null}
                        aria-label={`Terminate ${s.who} on ${s.res}`}
                        onClick={() => stop(s)}
                      >
                        Terminate
                      </button>
                    ) : (
                      <a className="link" href={cl(s.id)} aria-label={`Open recording of ${s.id}`}>
                        Recording
                      </a>
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

function SessionDetail({ id, say }: { id: string; say: PageProps["say"] }) {
  const [w, set] = useBroker();
  const s = w.sess.find((x) => x.id === id);
  if (!s) return <NotFound what="session" id={id} back={["Sessions", `${H}/sessions`]} />;
  const isLive = s.ended === null;
  const lines = isLive ? liveLines(s) : (w.recs[s.id] ?? []);
  return (
    <section>
      <Crumbs trail={[["Sessions", `${H}/sessions`], [s.id]]} />
      <Head
        title={`${s.who} on ${s.res}`}
        sub={
          isLive
            ? `Connected now. It ends in ${dur(left(w, s))}, or sooner if someone terminates it.`
            : `${s.how}. The recording is kept.`
        }
      >
        {isLive && (
          <button type="button" className="btn danger" onClick={() => terminate(set, s, say)}>
            Terminate session
          </button>
        )}
      </Head>
      <div className="panel br-sec">
        <h2>Details</h2>
        <Facts
          rows={[
            ["Who", s.who],
            ["Account", `${s.acct} on ${s.res}`],
            ["Reason given", s.reason || "None given"],
            ["Approved by", s.by],
            ["Started", ago(s.started)],
            [isLive ? "Open for" : "Lasted", dur((s.ended ?? NOW) - s.started)],
            ["How it ended", isLive ? `Still live. Cut off automatically after ${w.cfg.maxLen}.` : s.how],
          ]}
        />
      </div>
      {isLive && (
        <div className="panel br-sec">
          <h2>Connect</h2>
          <p className="muted small">
            Run this in a terminal. The password is never shown: the broker types it in for you.
          </p>
          <CommandBox cmd={cmdOf(s)} say={say} />
        </div>
      )}
      <div className="panel br-sec">
        <div className="sec-h">
          <h2>{isLive ? "Transcript so far" : "Transcript"}</h2>
          <span className="n">{plural(lines.length, "line")}</span>
        </div>
        <Tx lines={lines} blocked={w.cfg.blocked} />
      </div>
    </section>
  );
}

function Sessions({ sub, say }: PageProps) {
  return sub ? <SessionDetail key={sub} id={dec(sub)} say={say} /> : <SessionList say={say} />;
}

// ---- Recordings ----
const useRecUi = createStore({ flagged: false, q: "" });

const transcriptText = (s: Sess, lines: Line[], blocked: string[]) =>
  [
    `Recording ${s.id}: ${s.who} as ${s.acct} on ${s.res}`,
    `Reason: ${s.reason || "none given"}`,
    `Ended: ${s.how}`,
    "",
    ...lines.flatMap((l) => {
      const f = flagOf(l, blocked);
      return [`${dur(l[0]).padEnd(8)}${l[1]}`, ...(f ? [`        ! ${f.text}`] : [])];
    }),
  ].join("\n");

function Recordings({ sub, say }: PageProps) {
  const [w] = useBroker();
  const [ui, setUi] = useRecUi();
  const setUiState = (p: Partial<typeof ui>) => setUi({ ...ui, ...p });
  const { blocked } = w.cfg;
  const all = w.sess.filter((s) => s.ended !== null && w.recs[s.id]).sort((a, b) => b.ended! - a.ended!);
  const flagged = (s: Sess) => (w.recs[s.id] ?? []).some((l) => flagOf(l, blocked));
  const list = all.filter((s) => !ui.flagged || flagged(s));
  const sel = sub ? all.find((s) => s.id === dec(sub)) : undefined;
  const lines = sel ? (w.recs[sel.id] ?? []) : [];
  const flags = lines.filter((l) => flagOf(l, blocked)).length;
  const shown = lines.filter((l) => l[1].toLowerCase().includes(ui.q.trim().toLowerCase())).length;
  return (
    <section>
      <Head
        title="Recordings"
        sub="Every session is recorded as the commands and queries that were run. Open one to read exactly what happened."
      />
      {all.length === 0 ? (
        <Empty icon="s_window">
          <b>No recordings yet.</b> They appear here after the first session ends.
        </Empty>
      ) : (
        <>
          <div className="toolbar">
            <label className="br-check">
              <input type="checkbox" checked={ui.flagged} onChange={(e) => setUiState({ flagged: e.target.checked })} />
              Flagged only
            </label>
          </div>
          <div className="br-split">
            {list.length === 0 ? (
              <Empty icon="search">
                <b>No flagged recording.</b> Turn off “Flagged only” to see them all.
              </Empty>
            ) : (
              <ul className="list br-list" aria-label="Recordings">
                {list.map((s) => (
                  <li key={s.id}>
                    <a className="row" href={cl(s.id)} aria-current={sel?.id === s.id ? "true" : undefined}>
                      <div>
                        <b>{s.who}</b> <span className="muted small">{ago(s.ended)}</span>
                        <p>
                          <span className="mono">
                            {s.acct}@{s.res}
                          </span>
                        </p>
                        <p>
                          {dur(s.ended! - s.started)} · {plural((w.recs[s.id] ?? []).length - 1, "command")}
                          {flagged(s) && (
                            <>
                              {" "}
                              · <span className="prod">flagged</span>
                            </>
                          )}
                        </p>
                      </div>
                    </a>
                  </li>
                ))}
              </ul>
            )}
            {sel ? (
              <div className="panel" aria-label="Transcript">
                <h2>
                  {sel.who} on {sel.res}
                </h2>
                <p className="muted small">
                  {sel.acct}@{sel.res} · {ago(sel.started)} · {dur(sel.ended! - sel.started)} ·{" "}
                  {plural(flags, "flagged line")}. Sensitive values are replaced with [redacted] before the recording is
                  stored.{" "}
                  <a className="link" style={{ margin: 0 }} href={sl(sel.id)}>
                    View session
                  </a>
                </p>
                <div className="inline-form" style={{ margin: "10px 0" }}>
                  <label className="field" style={{ flexDirection: "row", alignItems: "center" }}>
                    Search this transcript
                    <input
                      type="search"
                      value={ui.q}
                      onChange={(e) => setUiState({ q: e.target.value })}
                      placeholder="DROP, invoices…"
                    />
                  </label>
                  <span className="muted small">
                    {shown} of {lines.length} lines
                  </span>
                </div>
                <Tx lines={lines} blocked={blocked} q={ui.q} />
                <div className="inline-form" style={{ marginTop: 12 }}>
                  <button
                    type="button"
                    className="btn sm"
                    onClick={() => saveText(`${sel.id}-${sel.res}.txt`, transcriptText(sel, lines, blocked), say)}
                  >
                    Download transcript
                  </button>
                </div>
              </div>
            ) : sub ? (
              <Empty icon="search">
                <b>No recording called “{dec(sub)}”.</b> It may still be live, or the id is wrong.{" "}
                <a className="link" href={`${H}/recordings`}>
                  Back to recordings
                </a>
              </Empty>
            ) : (
              <Empty icon="s_window">
                <b>Pick a recording.</b> Its commands appear here, with risky lines marked.
              </Empty>
            )}
          </div>
        </>
      )}
    </section>
  );
}

// ---- Settings ----
const Row = ({ title, about, children }: { title: string; about: string; children: React.ReactNode }) => (
  <div className="set-row">
    <div>
      <b>{title}</b>
      <p>{about}</p>
    </div>
    <div className="set-ctl">{children}</div>
  </div>
);

// Settings are real: they decide who needs approval, when live sessions are cut off, and which transcript lines are blocked.
function BrokerSettings({ say }: PageProps) {
  const [w, set] = useBroker();
  const saved = w.cfg;
  const [s, setS] = useState(saved);
  const [cmd, setCmd] = useState("");
  const dirty = JSON.stringify(s) !== JSON.stringify(saved);
  const cut = live(w).filter((x) => x.started + (MAXLEN[s.maxLen] ?? 4 * HOUR) <= NOW);
  const pick = (k: "maxLen" | "approval" | "keep", label: string, options: string[]) => (
    <select aria-label={label} value={s[k]} onChange={(e) => setS((x) => ({ ...x, [k]: e.target.value }))}>
      {options.map((o) => (
        <option key={o}>{o}</option>
      ))}
    </select>
  );
  const addCmd = () => {
    const c = cmd.trim();
    if (c && !s.blocked.includes(c)) setS((x) => ({ ...x, blocked: [...x.blocked, c] }));
    setCmd("");
  };
  const save = (e: React.FormEvent) => {
    e.preventDefault();
    set((x) => {
      const n = { ...x, cfg: s };
      return endSessions(n, (y) => y.started + maxSecs(s) <= NOW, "Time limit reached");
    });
    say(
      cut.length
        ? `Settings saved. Ended ${plural(cut.length, "session")} past the new limit.`
        : "Access Broker settings saved",
    );
  };
  return (
    <form className="settings" onSubmit={save}>
      <Head title="Settings" sub="Limits and rules that apply to every session opened through the broker." />
      <section className="panel" aria-labelledby="br-limits">
        <h2 id="br-limits">Session limits</h2>
        <Row
          title="Longest session"
          about="A session ends on its own after this long, even if it is busy. People can open a new one."
        >
          {pick("maxLen", "Longest session", ["1 hour", "4 hours", "8 hours"])}
        </Row>
        {cut.length > 0 && (
          <p className="hint prod" role="status">
            Saving this ends {plural(cut.length, "live session")} that already ran longer:{" "}
            {cut.map((x) => `${x.who} on ${x.res}`).join(", ")}.
          </p>
        )}
        <Row
          title="A session needs approval"
          about="A second person must approve before the connection opens. Agents wait until someone does."
        >
          {pick("approval", "A session needs approval", ["Never", "Production only", "Always"])}
        </Row>
      </section>
      <section className="panel" aria-labelledby="br-rec">
        <h2 id="br-rec">Recording</h2>
        <Row
          title="Record every session"
          about="Always on. A session nobody can look back on cannot be audited, so this cannot be turned off."
        >
          <span className="fixed">
            <Switch label="Record every session (always on)" checked onChange={() => {}} />
          </span>
        </Row>
        <Row
          title="Keep recordings for"
          about="After this, a recording is deleted for good. Deleting early is not possible."
        >
          {pick("keep", "Keep recordings for", ["30 days", "90 days", "1 year", "7 years"])}
        </Row>
      </section>
      <section className="panel" aria-labelledby="br-block">
        <h2 id="br-block">Blocked commands</h2>
        <p className="muted small">
          A command that contains one of these is stopped before it runs, for everyone including admins. Transcript
          lines that match are marked “Blocked: never ran”.
        </p>
        <ul className="br-block" aria-label="Blocked commands" style={{ margin: "12px 0" }}>
          {s.blocked.map((b) => (
            <li key={b}>
              <code>{b}</code>
              <button
                type="button"
                className="btn sm quiet danger-text"
                aria-label={`Stop blocking ${b}`}
                onClick={() => setS((x) => ({ ...x, blocked: x.blocked.filter((y) => y !== b) }))}
              >
                <Icon name="x" />
              </button>
            </li>
          ))}
          {s.blocked.length === 0 && (
            <li className="muted">Nothing is blocked. Every command is allowed and recorded.</li>
          )}
        </ul>
        <div className="inline-form">
          <input
            aria-label="Command to block"
            placeholder="DROP TABLE"
            value={cmd}
            onChange={(e) => setCmd(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addCmd();
              }
            }}
            autoComplete="off"
          />
          <button type="button" className="btn sm" onClick={addCmd} disabled={!cmd.trim()}>
            Block command
          </button>
        </div>
      </section>
      {dirty && (
        <div className="savebar" role="status">
          <span>You have unsaved changes.</span>
          <button type="button" className="btn quiet" onClick={() => setS(saved)}>
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

export const pages: Pages = {
  "broker/resources": Resources,
  "broker/accounts": Accounts,
  "broker/sessions": Sessions,
  "broker/recordings": Recordings,
  "broker/settings": BrokerSettings,
};
