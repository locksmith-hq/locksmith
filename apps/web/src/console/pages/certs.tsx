// Certificates product: issue, renew and revoke X.509 certificates from your own authorities (sample data only).
// All data lives in module-level stores, so every page and detail view sees the same certificates, authorities and settings.
import { Checkbox } from "@locksmith-hq/ui/checkbox";
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Label } from "@locksmith-hq/ui/label";
import { Card } from "@locksmith-hq/ui/card";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/ui/toggle-group";
import { Button } from "@locksmith-hq/ui/button";
import { Input } from "@locksmith-hq/ui/input";
import { Dropdown, Option } from "../../Dropdown";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
import { Fragment, useState } from "react";
import {
  createStore,
  Crumbs,
  DAY,
  Empty,
  Head,
  HOUR,
  Icon,
  NOW,
  Switch,
  ago,
  inTime,
  plural,
  type IconName,
  type PageProps,
  type Pages,
} from "../kit";
import "../settings.css";
import "./certs.css";

type Use = "TLS server" | "mTLS client" | "Code signing";
type Status = "Valid" | "Expiring soon" | "Expired" | "Revoked";
type Say = PageProps["say"];
interface Ev {
  icon: IconName;
  text: string;
  at: number;
}
interface Cert {
  id: string;
  name: string;
  names: string[];
  ca: string;
  use: Use;
  profile: string;
  issued: number;
  expires: number;
  revoked?: string;
  serial: string;
  fp: string;
  auto: boolean;
  log: Ev[];
}
interface Profile {
  id: string;
  name: string;
  pattern: string;
  maxDays: number;
  key: string;
  use: Use;
  approval: boolean;
}
interface Authority {
  id: string;
  name: string;
  kind: "Root" | "Intermediate";
  parent: string | null;
  key: string;
  until: number;
  status: "Offline" | "Active" | "Disabled";
}
interface Pending {
  id: string;
  name: string;
  ca: string;
  profile: string;
  by: string;
  at: number;
  days: number;
}
interface Settings {
  profile: string;
  lifetime: number;
  window: number;
  warn: number;
  acme: boolean;
}

const USES: Use[] = ["TLS server", "mTLS client", "Code signing"];
const KEYS = ["ECDSA P-256", "ECDSA P-384", "RSA 3072", "Ed25519"];
const REASONS = ["Key compromised", "Replaced by a new certificate", "No longer needed", "Name changed"];
const LIFETIMES: [number, string][] = [
  [7, "7 days"],
  [30, "30 days"],
  [90, "90 days"],
  [365, "1 year"],
];
const ME = "Tomer Levy";

const days = (ts: number) => Math.ceil((ts - NOW) / DAY);
const date = (ts: number) =>
  new Date(ts * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
const status = (c: Cert, win: number): Status =>
  c.revoked ? "Revoked" : c.expires <= NOW ? "Expired" : c.expires - NOW < win * DAY ? "Expiring soon" : "Valid";
const hex = (seed: number, bytes: number, sep = "") =>
  Array.from({ length: bytes }, (_, i) =>
    (((seed * 2654435761 + i * 40503 + i * i * 977) >>> 3) & 255).toString(16).padStart(2, "0"),
  ).join(sep);
const matches = (pattern: string, name: string) =>
  new RegExp(
    `^${pattern
      .split("*")
      .map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*")}$`,
  ).test(name);
const href = (tab: string, id?: string) => `#/app/certs/${tab}${id ? `/${encodeURIComponent(id)}` : ""}`;
let seq = 100;

// What happened to a seed certificate, built from its dates.
const seedLog = (c: { issued: number; expires: number; revoked?: string; auto: boolean }): Ev[] => {
  const l: Ev[] = [{ icon: "key", text: "Issued", at: c.issued }];
  if (c.auto && c.issued < NOW - 90 * DAY)
    l.push({ icon: "rotate", text: "Renewed automatically", at: c.issued + 45 * DAY });
  if (c.revoked) l.push({ icon: "block", text: `Revoked: ${c.revoked}`, at: NOW - 2 * DAY });
  return l;
};
const cert = (
  n: number,
  name: string,
  ca: string,
  use: Use,
  profile: string,
  left: number,
  auto: boolean,
  names: string[] = [],
  revoked?: string,
): Cert => {
  const issued = NOW - (60 + n * 9) * DAY,
    expires = NOW + left * DAY;
  return {
    id: `crt_${n}`,
    name,
    names,
    ca,
    use,
    profile,
    issued,
    expires,
    revoked,
    serial: hex(n, 8),
    fp: hex(n + 40, 10, ":").toUpperCase(),
    auto,
    log: seedLog({ issued, expires, revoked, auto }),
  };
};

const useCerts = createStore<Cert[]>([
  cert(1, "api.acme.example", "i2", "TLS server", "p1", 9, true, ["api-v2.acme.example"]),
  cert(2, "*.internal.acme.example", "i1", "TLS server", "p2", 24, true, ["internal.acme.example"]),
  cert(3, "billing.acme.example", "i2", "TLS server", "p1", 62, true, ["pay.acme.example"]),
  cert(4, "ci-deploy.agents.acme.example", "i1", "mTLS client", "p3", 3, true),
  cert(5, "claude-laptop.agents.acme.example", "i1", "mTLS client", "p3", 11, true),
  cert(6, "codex-billing.agents.acme.example", "i1", "mTLS client", "p3", 22, true),
  cert(7, "Acme release signing", "i3", "Code signing", "p4", 140, false),
  cert(8, "Acme installer signing", "i3", "Code signing", "p4", -5, false),
  cert(9, "staging.acme.example", "i1", "TLS server", "p1", 30, true, [], "Key compromised"),
  cert(10, "review-bot.agents.acme.example", "i1", "mTLS client", "p3", 85, true),
]);
const useProfiles = createStore<Profile[]>([
  {
    id: "p1",
    name: "TLS server",
    pattern: "*.acme.example",
    maxDays: 90,
    key: "ECDSA P-256",
    use: "TLS server",
    approval: false,
  },
  {
    id: "p2",
    name: "Wildcard internal",
    pattern: "*.internal.acme.example",
    maxDays: 60,
    key: "ECDSA P-256",
    use: "TLS server",
    approval: true,
  },
  {
    id: "p3",
    name: "Agent client",
    pattern: "*.agents.acme.example",
    maxDays: 30,
    key: "ECDSA P-256",
    use: "mTLS client",
    approval: false,
  },
  {
    id: "p4",
    name: "Code signing",
    pattern: "Acme *",
    maxDays: 365,
    key: "RSA 3072",
    use: "Code signing",
    approval: true,
  },
  {
    id: "p5",
    name: "Short-lived test",
    pattern: "*.dev.acme.example",
    maxDays: 7,
    key: "Ed25519",
    use: "TLS server",
    approval: false,
  },
]);
const au = (
  id: string,
  name: string,
  kind: Authority["kind"],
  parent: string | null,
  key: string,
  untilDays: number,
  st: Authority["status"],
): Authority => ({ id, name, kind, parent, key, until: NOW + untilDays * DAY, status: st });
const useAuths = createStore<Authority[]>([
  au("r1", "Acme Root CA 2024", "Root", null, "ECDSA P-384", 3350, "Offline"),
  au("i1", "Acme Internal CA", "Intermediate", "r1", "ECDSA P-384", 1800, "Active"),
  au("i2", "Acme Public Services CA", "Intermediate", "r1", "ECDSA P-384", 1800, "Active"),
  au("i3", "Acme Code Signing CA", "Intermediate", "r1", "RSA 3072", 1400, "Active"),
  au("i5", "Acme Staging CA", "Intermediate", "r1", "ECDSA P-256", 700, "Disabled"),
  au("r2", "Acme Root CA 2019", "Root", null, "RSA 3072", 380, "Offline"),
  au("i6", "Acme Legacy Issuing CA", "Intermediate", "r2", "RSA 3072", 300, "Active"),
]);
const usePending = createStore<Pending[]>([
  {
    id: "req_1",
    name: "build.internal.acme.example",
    ca: "i1",
    profile: "p2",
    by: "Dana Okafor",
    at: NOW - 3 * HOUR,
    days: 60,
  },
]);
const useSettings = createStore<Settings>({ profile: "p1", lifetime: 90, window: 21, warn: 30, acme: true });

// Shared helpers over the stores' contents.
const chainOf = (auths: Authority[], id: string | null): Authority[] => {
  const a = auths.find((x) => x.id === id);
  return a ? [...chainOf(auths, a.parent), a] : [];
};
const below = (auths: Authority[], id: string): string[] => [
  id,
  ...auths.filter((a) => a.parent === id).flatMap((a) => below(auths, a.id)),
];
const stuck = (c: Cert, auths: Authority[]) => chainOf(auths, c.ca).some((a) => a.status === "Disabled");
const lifetimeOf = (p: Profile | undefined, cfg: Settings) => Math.min(p?.maxDays ?? 90, cfg.lifetime);
const mint = (name: string, ca: string, p: Profile, d: number, note: string): Cert => {
  const n = ++seq;
  return {
    id: `crt_${n}`,
    name,
    names: [],
    ca,
    use: p.use,
    profile: p.id,
    issued: NOW,
    expires: NOW + d * DAY,
    serial: hex(n, 8),
    fp: hex(n + 40, 10, ":").toUpperCase(),
    auto: true,
    log: [{ icon: "key", text: note, at: NOW }],
  };
};
const pem = (c: Cert) => {
  const body =
    btoa(`SAMPLE ONLY, NOT A REAL CERTIFICATE. ${c.name}. Serial ${c.serial}.`)
      .match(/.{1,64}/g)
      ?.join("\n") ?? "";
  return `# Sample file from the Locksmith console. This is not a real certificate.\n# Subject: ${c.name}\n-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
};
const download = (c: Cert) => {
  const url = URL.createObjectURL(new Blob([pem(c)], { type: "application/x-pem-file" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `${c.name.replace(/[^a-z0-9.-]/gi, "_")}.pem`;
  a.click();
  URL.revokeObjectURL(url);
};
const addEv = (c: Cert, icon: IconName, text: string): Cert => ({ ...c, log: [...c.log, { icon, text, at: NOW }] });

const Stat = ({ s }: { s: string }) => (
  <span className="cstat" data-s={s}>
    {s}
  </span>
);
const A = ({ tab, id, children }: { tab: string; id: string; children: React.ReactNode }) => (
  <a href={href(tab, id)}>{children}</a>
);

function NotFound({ trail, what, tab, list }: { trail: string; what: string; tab: string; list: string }) {
  return (
    <section>
      <Crumbs trail={[[list, href(tab)], ["Not found"]]} />
      <Head
        title={`${trail} not found`}
        sub={`There is no ${what} at this address. It may have been removed, or the link is mistyped.`}
      >
        <Button asChild>
          <a href={href(tab)}>Back to {list.toLowerCase()}</a>
        </Button>
      </Head>
      <Empty icon="doc">
        <b>Nothing to show.</b> Go back to the list and pick another one.
      </Empty>
    </section>
  );
}

// Renew a certificate: new expiry from the profile and default lifetime, and a note in its timeline.
function renewWith(set: ReturnType<typeof useCerts>[1], c: Cert, profiles: Profile[], cfg: Settings) {
  const d = lifetimeOf(
    profiles.find((p) => p.id === c.profile),
    cfg,
  );
  set((r) =>
    r.map((x) =>
      x.id === c.id ? { ...addEv(x, "rotate", `Renewed for ${plural(d, "day")}`), expires: NOW + d * DAY } : x,
    ),
  );
  return d;
}

/* ---------------------------------------------------------------- Certificates */

function IssueForm({ onDone, say }: { onDone: () => void; say: Say }) {
  const [auths] = useAuths(),
    [profiles] = useProfiles(),
    [cfg] = useSettings();
  const [, setCerts] = useCerts(),
    [, setPending] = usePending();
  const issuers = auths.filter((a) => a.kind === "Intermediate");
  const live = (a: Authority) => chainOf(auths, a.id).every((x) => x.status !== "Disabled");
  const [caId, setCaId] = useState(issuers.find(live)?.id ?? issuers[0]?.id ?? "");
  const [profileId, setProfileId] = useState(cfg.profile);
  const [dayText, setDayText] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const ca = issuers.find((a) => a.id === caId);
  const caOk = !!ca && live(ca);
  const profile = profiles.find((p) => p.id === profileId) ?? profiles[0];
  const dayValue = dayText ?? String(profile ? lifetimeOf(profile, cfg) : "");

  const submit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const name = String(new FormData(e.currentTarget).get("name")).trim();
    const d = Number(dayValue);
    if (!ca || !caOk || !profile) return;
    if (!matches(profile.pattern, name))
      return setErr(`The ${profile.name} profile only allows names like ${profile.pattern}.`);
    if (!(d >= 1) || d > profile.maxDays)
      return setErr(`The ${profile.name} profile allows 1 to ${plural(profile.maxDays, "day")}.`);
    if (profile.approval) {
      setPending((r) => [...r, { id: `req_${++seq}`, name, ca: ca.id, profile: profile.id, by: ME, at: NOW, days: d }]);
      say(`Sent ${name} for approval`);
    } else {
      setCerts((r) => [...r, mint(name, ca.id, profile, d, `Issued under the ${profile.name} profile`)]);
      say(`Issued ${name}`);
    }
    onDone();
  };
  return (
    <Card className="panel form">
      <form className="contents" onSubmit={submit} aria-label="Issue certificate">
        <h2>Issue a certificate</h2>
        <div className="add certs">
          <Label className="field">
            Authority
            <Dropdown
              value={caId}
              onChange={(e) => {
                setCaId(e);
                setErr("");
              }}
            >
              {issuers.map((a) => (
                <Option key={a.id} value={a.id} disabled={!live(a)}>
                  {a.name}
                  {live(a) ? "" : " (disabled)"}
                </Option>
              ))}
            </Dropdown>
          </Label>
          <Label className="field">
            Profile
            <Dropdown
              value={profile?.id ?? ""}
              onChange={(e) => {
                setProfileId(e);
                setDayText(null);
                setErr("");
              }}
            >
              {profiles.map((p) => (
                <Option key={p.id} value={p.id}>
                  {p.name}
                </Option>
              ))}
            </Dropdown>
          </Label>
          <Label className="field">
            Name
            <Input
              name="name"
              required
              autoFocus
              autoComplete="off"
              placeholder={profile?.pattern.replace("*", "app")}
              onChange={() => setErr("")}
            />
          </Label>
          <Label className="field">
            Valid for (days)
            <Input
              className="num-in"
              type="number"
              min={1}
              value={dayValue}
              onChange={(e) => {
                setDayText(e.target.value);
                setErr("");
              }}
            />
          </Label>
          <Button type="submit" disabled={!caOk || !profile}>
            Issue certificate
          </Button>
          <Button variant="ghost" type="button" onClick={onDone}>
            Cancel
          </Button>
        </div>
        {err && (
          <p className="field-err" role="alert">
            {err}
          </p>
        )}
        {ca && !caOk && (
          <Alert variant="destructive">
            <AlertDescription>
              {ca.name} is disabled, so it cannot issue certificates.{" "}
              <A tab="authorities" id={ca.id}>
                Open it to enable it
              </A>
              .
            </AlertDescription>
          </Alert>
        )}
        {profile && caOk && (
          <p className="hint">
            {profile.name} allows {profile.pattern}, up to {plural(profile.maxDays, "day")}.{" "}
            {profile.approval ? "A second person must approve it before it is issued." : "It is issued straight away."}
          </p>
        )}
      </form>
    </Card>
  );
}

function CertList({ say }: { say: Say }) {
  const [certs, setCerts] = useCerts(),
    [auths] = useAuths(),
    [profiles] = useProfiles(),
    [cfg] = useSettings(),
    [pending, setPending] = usePending();
  const [filter, setFilter] = useState<Status | "All">("All");
  const [q, setQ] = useState("");
  const [dir, setDir] = useState<1 | -1>(1);
  const [adding, setAdding] = useState(false);
  const needle = q.trim().toLowerCase();
  const base = certs.filter((c) => !needle || [c.name, ...c.names].some((n) => n.toLowerCase().includes(needle)));
  const shown = base
    .filter((c) => filter === "All" || status(c, cfg.window) === filter)
    .sort((a, b) => (a.revoked ? 1 : 0) - (b.revoked ? 1 : 0) || (a.expires - b.expires) * dir);
  const clear = () => {
    setFilter("All");
    setQ("");
  };
  const filtered = filter !== "All" || needle !== "";

  const approve = (r: Pending) => {
    const p = profiles.find((x) => x.id === r.profile);
    if (!p) return;
    setCerts((c) => [...c, mint(r.name, r.ca, p, r.days, `Issued under the ${p.name} profile`)]);
    setPending((x) => x.filter((y) => y.id !== r.id));
    say(`Approved and issued ${r.name}`);
  };

  return (
    <section>
      <Head
        title="Certificates"
        sub="Every certificate your authorities have issued, with the ones closest to expiry first."
      >
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Issue certificate
        </Button>
      </Head>
      {adding && <IssueForm onDone={() => setAdding(false)} say={say} />}
      <h2 className="ct-h">Waiting for approval</h2>
      {pending.length === 0 ? (
        <p className="muted small ct-none">Nothing is waiting for approval.</p>
      ) : (
        <ul className="list ct-pending">
          {pending.map((r) => {
            const p = profiles.find((x) => x.id === r.profile),
              a = auths.find((x) => x.id === r.ca);
            const off = !a || chainOf(auths, a.id).some((x) => x.status === "Disabled");
            return (
              <li key={r.id} className="row">
                <span className="ic">
                  <Icon name="clock" />
                </span>
                <div>
                  <b>{r.name}</b>
                  <p>
                    {r.by} asked {ago(r.at)} for {plural(r.days, "day")} under{" "}
                    {p ? (
                      <A tab="templates" id={p.id}>
                        {p.name}
                      </A>
                    ) : (
                      "a removed profile"
                    )}{" "}
                    from {a?.name ?? "a removed authority"}.
                    {off && " Its authority is disabled, so it cannot be approved yet."}
                  </p>
                </div>
                <span className="meta">
                  <Button
                    variant="outline"
                    size="sm"
                    type="button"
                    disabled={off || !p}
                    aria-label={`Approve ${r.name}`}
                    onClick={() => approve(r)}
                  >
                    Approve
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-(--destructive-text)"
                    type="button"
                    aria-label={`Decline ${r.name}`}
                    onClick={() => {
                      setPending((x) => x.filter((y) => y.id !== r.id));
                      say(`Declined ${r.name}`);
                    }}
                  >
                    Decline
                  </Button>
                </span>
              </li>
            );
          })}
        </ul>
      )}
      <h2 className="ct-h">All certificates</h2>
      <div className="toolbar">
        <label className="search">
          <span className="sr-only">Search by name</span>
          <Icon name="search" />
          <Input type="search" placeholder="Search by name" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <ToggleGroup type="single" value={String(filter)} aria-label="Status">
          {(["All", "Valid", "Expiring soon", "Expired", "Revoked"] as const).map((s) => (
            <ToggleGroupItem key={s} size="sm" value={String(s)} onClick={() => setFilter(s)}>
              {s}
              <span className="n">
                {s === "All" ? base.length : base.filter((c) => status(c, cfg.window) === s).length}
              </span>
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
      </div>
      <p className="sr-only" role="status">
        {plural(shown.length, "certificate")} shown, sorted by expiry, {dir === 1 ? "soonest first" : "latest first"}.
      </p>
      {shown.length === 0 ? (
        <Empty icon="doc">
          {filtered ? (
            <>
              <b>No certificates match.</b>{" "}
              <Button variant="outline" size="sm" type="button" onClick={clear}>
                Clear search and filters
              </Button>
            </>
          ) : (
            <>
              <b>No certificates yet.</b> Issue one to get started.
            </>
          )}
        </Empty>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Issued for</TableHead>
                <TableHead>Authority</TableHead>
                <TableHead>Used for</TableHead>
                <TableHead aria-sort={dir === 1 ? "ascending" : "descending"}>
                  <Button
                    variant="ghost"
                    type="button"
                    className="ct-sort"
                    data-dir={dir}
                    onClick={() => setDir(dir === 1 ? -1 : 1)}
                  >
                    Expires
                    <Icon name="arrow" />
                  </Button>
                </TableHead>
                <TableHead>Status</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((c) => {
                const st = status(c, cfg.window),
                  cs = chainOf(auths, c.ca).at(-1),
                  blocked = stuck(c, auths);
                return (
                  <TableRow key={c.id} data-bad={st === "Expiring soon" || st === "Expired"}>
                    <TableCell>
                      <a className="ct-link mono" href={href("certificates", c.id)}>
                        {c.name}
                      </a>
                    </TableCell>
                    <TableCell>
                      {cs ? (
                        <A tab="authorities" id={cs.id}>
                          {cs.name}
                        </A>
                      ) : (
                        "Removed authority"
                      )}
                    </TableCell>
                    <TableCell>{c.use}</TableCell>
                    <TableCell className={st === "Revoked" ? "muted" : undefined}>
                      {st === "Revoked"
                        ? "Not applicable"
                        : c.expires <= NOW
                          ? ago(c.expires)
                          : `${inTime(c.expires)} (${date(c.expires)})`}
                    </TableCell>
                    <TableCell>
                      <Stat s={st} />
                      {blocked && st !== "Revoked" && (
                        <>
                          {" "}
                          <Stat s="Cannot renew" />
                        </>
                      )}
                    </TableCell>
                    <TableCell className="num">
                      {st !== "Revoked" && !blocked && (
                        <Button
                          variant="outline"
                          size="sm"
                          type="button"
                          aria-label={`Renew ${c.name}`}
                          onClick={() => {
                            const d = renewWith(setCerts, c, profiles, cfg);
                            say(`Renewed ${c.name} for ${plural(d, "day")}`);
                          }}
                        >
                          <Icon name="rotate" />
                          Renew
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}

function CertDetail({ id, say }: { id: string; say: Say }) {
  const [certs, setCerts] = useCerts(),
    [auths] = useAuths(),
    [profiles] = useProfiles(),
    [cfg] = useSettings();
  const [revoking, setRevoking] = useState(false),
    [reason, setReason] = useState(REASONS[0] ?? "");
  const c = certs.find((x) => x.id === id);
  if (!c) return <NotFound trail="Certificate" what="certificate" tab="certificates" list="Certificates" />;
  const st = status(c, cfg.window),
    blocked = stuck(c, auths),
    chain = chainOf(auths, c.ca),
    p = profiles.find((x) => x.id === c.profile),
    ca = chain.at(-1);
  const left = days(c.expires),
    canRenew = st !== "Revoked" && !blocked;
  const patch = (f: (x: Cert) => Cert) => setCerts((r) => r.map((x) => (x.id === id ? f(x) : x)));
  const renew = () => {
    const d = renewWith(setCerts, c, profiles, cfg);
    say(`Renewed ${c.name} for ${plural(d, "day")}`);
  };
  const renewNote = c.revoked
    ? "Not applicable. Revoked certificates are not renewed."
    : blocked
      ? "Paused, because its authority is disabled."
      : !c.auto
        ? "Off. Renew it by hand before it expires."
        : left <= cfg.window
          ? `Due now. Locksmith renews it when ${plural(cfg.window, "day")} remain.`
          : `In ${plural(left - cfg.window, "day")}, when ${plural(cfg.window, "day")} remain.`;

  return (
    <section>
      <Crumbs trail={[["Certificates", href("certificates")], [c.name]]} />
      <Head
        title={c.name}
        sub={`${c.use} certificate from ${ca?.name ?? "a removed authority"}. ${st === "Revoked" ? `Revoked: ${c.revoked}.` : st === "Expired" ? `It expired ${ago(c.expires)}.` : `It expires ${inTime(c.expires)}.`}`}
      >
        {canRenew && (
          <Button type="button" onClick={renew}>
            <Icon name="rotate" />
            Renew certificate
          </Button>
        )}
      </Head>
      {blocked && st !== "Revoked" && (
        <Alert role="status">
          <AlertDescription>
            Cannot renew: an authority in its chain is disabled. Enable it to renew this certificate. It keeps working
            until it expires.
          </AlertDescription>
        </Alert>
      )}
      <div className="ct-cols">
        <div className="ct-col">
          <Card className="panel" role="region" aria-labelledby="cd-facts">
            <h2 id="cd-facts">Details</h2>
            <dl className="kv ct-kv">
              <dt>Status</dt>
              <dd>
                <Stat s={st} />
                {blocked && st !== "Revoked" && (
                  <>
                    {" "}
                    <Stat s="Cannot renew" />
                  </>
                )}
              </dd>
              <dt>Used for</dt>
              <dd>{c.use}</dd>
              <dt>Profile</dt>
              <dd>
                {p ? (
                  <A tab="templates" id={p.id}>
                    {p.name}
                  </A>
                ) : (
                  "Removed profile"
                )}
              </dd>
              <dt>Authority</dt>
              <dd>
                {ca ? (
                  <A tab="authorities" id={ca.id}>
                    {ca.name}
                  </A>
                ) : (
                  "Removed authority"
                )}
              </dd>
              <dt>Serial</dt>
              <dd className="mono">{c.serial}</dd>
              <dt>Fingerprint</dt>
              <dd className="mono">{c.fp}</dd>
              <dt>Issued</dt>
              <dd>{date(c.issued)}</dd>
              <dt>Expires</dt>
              <dd>
                {date(c.expires)}, {c.expires <= NOW ? ago(c.expires) : inTime(c.expires)}
              </dd>
              <dt>Automatic renewal</dt>
              <dd>
                {c.revoked ? (
                  <span>Off</span>
                ) : (
                  <span className="inline-form">
                    <Switch
                      label={`Renew ${c.name} automatically`}
                      checked={c.auto}
                      onChange={(on) => {
                        patch((x) => ({ ...x, auto: on }));
                        say(`Automatic renewal ${on ? "on" : "off"} for ${c.name}`);
                      }}
                    />{" "}
                    {c.auto ? "On" : "Off"}
                  </span>
                )}
                <p className="muted small ct-note">{renewNote}</p>
              </dd>
            </dl>
          </Card>
          <Card className="panel" role="region" aria-labelledby="cd-names">
            <h2 id="cd-names">Names it covers</h2>
            <ul className="plain">
              {[c.name, ...c.names].map((n, i) => (
                <li key={n}>
                  <span className="mono">{n}</span>
                  <span className="muted small">{i === 0 ? "Main name" : "Also covered"}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Card className="panel" role="region" aria-labelledby="cd-revoke">
            <h2 id="cd-revoke">Revoke</h2>
            {c.revoked ? (
              <p className="small">
                Revoked because: {c.revoked}. A revoked certificate cannot be renewed. Issue a new one to replace it.
              </p>
            ) : (
              <>
                <p className="muted small">Revoking stops systems trusting it within minutes.</p>
                <Button
                  variant="ghost"
                  size="sm"
                  className="ct-gap text-(--destructive-text)"
                  type="button"
                  aria-expanded={revoking}
                  onClick={() => setRevoking(!revoking)}
                >
                  Revoke this certificate
                </Button>
                {revoking && (
                  <div className="stack ct-gap">
                    <Label className="field">
                      Reason
                      <Dropdown value={reason} onChange={(e) => setReason(e)}>
                        {REASONS.map((r) => (
                          <Option key={r}>{r}</Option>
                        ))}
                      </Dropdown>
                    </Label>
                    <Alert variant="destructive" style={{ margin: 0 }}>
                      <AlertDescription>This cannot be undone.</AlertDescription>
                    </Alert>
                    <span className="inline-form">
                      <Button
                        variant="destructive"
                        type="button"
                        onClick={() => {
                          patch((x) => addEv({ ...x, revoked: reason }, "block", `Revoked: ${reason}`));
                          setRevoking(false);
                          say(`Revoked ${c.name}`);
                        }}
                      >
                        Revoke certificate
                      </Button>
                      <Button variant="ghost" type="button" onClick={() => setRevoking(false)}>
                        Keep it
                      </Button>
                    </span>
                  </div>
                )}
              </>
            )}
          </Card>
        </div>
        <div className="ct-col">
          <Card className="panel" role="region" aria-labelledby="cd-chain">
            <h2 id="cd-chain">Chain of trust</h2>
            <ol className="ct-chain">
              {chain.map((a) => (
                <li key={a.id}>
                  <span className="ct-dot">
                    <Icon name={a.kind === "Root" ? "lock" : "shield"} />
                  </span>
                  <A tab="authorities" id={a.id}>
                    {a.name}
                  </A>
                  <span className="muted small">
                    {a.kind === "Root" ? "Root, kept offline" : "Intermediate"} · {a.status.toLowerCase()}
                  </span>
                </li>
              ))}
              <li>
                <span className="ct-dot">
                  <Icon name="key" />
                </span>
                <b>{c.name}</b>
                <span className="muted small">This certificate</span>
              </li>
            </ol>
          </Card>
          <Card className="panel" role="region" aria-labelledby="cd-dl">
            <h2 id="cd-dl">Download</h2>
            <p className="muted small">
              You get the public certificate only. The private key never leaves the machine that asked for the
              certificate, so it cannot be downloaded. The file here is fake sample text.
            </p>
            <Button
              variant="outline"
              className="ct-gap"
              type="button"
              onClick={() => {
                download(c);
                say(`Downloaded the certificate for ${c.name}`);
              }}
            >
              <Icon name="doc" />
              Download certificate
            </Button>
          </Card>
          <Card className="panel" role="region" aria-labelledby="cd-tl">
            <h2 id="cd-tl">What happened</h2>
            <ul className="plain ct-time">
              {[...c.log]
                .reverse()
                .sort((a, b) => b.at - a.at)
                .map((e, i) => (
                  <li key={`${e.at}${i}`}>
                    <span className="ct-ico">
                      <Icon name={e.icon} />
                    </span>
                    <span>{e.text}</span>
                    <span className="muted small">{ago(e.at)}</span>
                  </li>
                ))}
            </ul>
          </Card>
        </div>
      </div>
    </section>
  );
}

function Certificates({ sub, say }: PageProps) {
  return sub ? <CertDetail id={decodeURIComponent(sub)} say={say} /> : <CertList say={say} />;
}

/* ---------------------------------------------------------------- Authorities */

function AuthList({ say }: { say: Say }) {
  const [auths, setAuths] = useAuths(),
    [certs] = useCerts();
  const [adding, setAdding] = useState(false),
    [disabling, setDisabling] = useState<string | null>(null);
  const issued = (a: Authority) =>
    a.kind === "Root"
      ? plural(auths.filter((x) => x.parent === a.id).length, "intermediate")
      : plural(certs.filter((c) => c.ca === a.id).length, "certificate");
  const setStatus = (a: Authority, st: Authority["status"]) => {
    setAuths((r) => r.map((x) => (x.id === a.id ? { ...x, status: st } : x)));
    setDisabling(null);
    say(`${st === "Disabled" ? "Disabled" : "Enabled"} ${a.name}`);
  };
  const create = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const parent = auths.find((a) => a.id === f.get("parent"));
    if (!parent) return;
    const nid = `i_${++seq}`,
      name = String(f.get("name")).trim();
    setAuths((r) => [
      ...r,
      {
        id: nid,
        name,
        kind: "Intermediate",
        parent: parent.id,
        key: String(f.get("key")),
        until: Math.min(parent.until, NOW + Number(f.get("years")) * 365 * DAY),
        status: "Active",
      },
    ]);
    say(`Created ${name}`);
    setAdding(false);
  };
  const walk = (parent: string | null, depth: number): React.ReactNode =>
    auths
      .filter((a) => a.parent === parent)
      .map((a) => {
        const hit = certs.filter((c) => below(auths, a.id).includes(c.ca)).length;
        return (
          <Fragment key={a.id}>
            <TableRow>
              <TableCell>
                <span className="tree-name" style={{ paddingLeft: depth * 24 }}>
                  {depth > 0 && <span className="elbow" aria-hidden="true" />}
                  <Icon name={a.kind === "Root" ? "lock" : "shield"} />
                  <a className="ct-link" href={href("authorities", a.id)}>
                    <b>{a.name}</b>
                  </a>
                </span>
              </TableCell>
              <TableCell>{a.kind === "Root" ? "Root, kept offline" : "Intermediate"}</TableCell>
              <TableCell className="mono">{a.key}</TableCell>
              <TableCell>{date(a.until)}</TableCell>
              <TableCell>{issued(a)}</TableCell>
              <TableCell>
                <Stat s={a.status} />
              </TableCell>
              <TableCell className="num">
                {a.kind === "Intermediate" &&
                  (a.status === "Disabled" ? (
                    <Button
                      variant="outline"
                      size="sm"
                      type="button"
                      aria-label={`Enable ${a.name}`}
                      onClick={() => setStatus(a, "Active")}
                    >
                      Enable
                    </Button>
                  ) : (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      type="button"
                      aria-expanded={disabling === a.id}
                      aria-label={`Disable ${a.name}`}
                      onClick={() => setDisabling(disabling === a.id ? null : a.id)}
                    >
                      Disable
                    </Button>
                  ))}
              </TableCell>
            </TableRow>
            {disabling === a.id && (
              <TableRow className="detail">
                <TableCell colSpan={7}>
                  <Alert variant="destructive" style={{ margin: 0 }}>
                    <AlertDescription>
                      Disabling {a.name} stops it issuing, and stops{" "}
                      {hit === 0 ? "no certificates" : plural(hit, "certificate")} from being renewed, including any
                      under its own intermediates. They keep working until they expire.
                      <Button variant="destructive" size="sm" type="button" onClick={() => setStatus(a, "Disabled")}>
                        Disable authority
                      </Button>
                      <Button variant="ghost" size="sm" type="button" onClick={() => setDisabling(null)}>
                        Keep it
                      </Button>
                    </AlertDescription>
                  </Alert>
                </TableCell>
              </TableRow>
            )}
            {walk(a.id, depth + 1)}
          </Fragment>
        );
      });
  return (
    <section>
      <Head
        title="Authorities"
        sub="The certificate authorities you run: offline roots, and the intermediates beneath them that do the day-to-day signing."
      >
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Create intermediate
        </Button>
      </Head>
      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={create} aria-label="Create intermediate authority">
            <h2>Create an intermediate authority</h2>
            <div className="add certs">
              <Label className="field">
                Name
                <Input name="name" required autoFocus autoComplete="off" placeholder="Acme Edge CA" />
              </Label>
              <Label className="field">
                Signed by
                <Dropdown name="parent">
                  {auths
                    .filter((a) => a.status !== "Disabled")
                    .map((a) => (
                      <Option key={a.id} value={a.id}>
                        {a.name}
                      </Option>
                    ))}
                </Dropdown>
              </Label>
              <Label className="field">
                Key type
                <Dropdown name="key">
                  {KEYS.map((k) => (
                    <Option key={k}>{k}</Option>
                  ))}
                </Dropdown>
              </Label>
              <Label className="field">
                Valid for
                <Dropdown name="years" defaultValue={3}>
                  <Option value={1}>1 year</Option>
                  <Option value={3}>3 years</Option>
                  <Option value={5}>5 years</Option>
                </Dropdown>
              </Label>
              <Button type="submit">Create authority</Button>
              <Button variant="ghost" type="button" onClick={() => setAdding(false)}>
                Cancel
              </Button>
            </div>
            <p className="hint">
              An intermediate cannot outlive the authority that signs it, so a long choice is cut short. Signing with an
              offline root needs the root key ceremony; the console skips it.
            </p>
          </form>
        </Card>
      )}
      {auths.length === 0 ? (
        <Empty icon="shield">
          <b>No authorities yet.</b> Create a root first, then an intermediate to issue from.
        </Empty>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Authority</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Key</TableHead>
                <TableHead>Valid until</TableHead>
                <TableHead>Issued</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>{walk(null, 0)}</TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}

function AuthDetail({ id, say }: { id: string; say: Say }) {
  const [auths, setAuths] = useAuths(),
    [certs] = useCerts();
  const [disabling, setDisabling] = useState(false);
  const a = auths.find((x) => x.id === id);
  if (!a) return <NotFound trail="Authority" what="authority" tab="authorities" list="Authorities" />;
  const parent = auths.find((x) => x.id === a.parent);
  const mine = certs.filter((c) => c.ca === a.id),
    kids = auths.filter((x) => x.parent === a.id);
  const hit = certs.filter((c) => below(auths, a.id).includes(c.ca)).length;
  const isInt = a.kind === "Intermediate";
  const setStatus = (st: Authority["status"]) => {
    setAuths((r) => r.map((x) => (x.id === a.id ? { ...x, status: st } : x)));
    setDisabling(false);
    say(`${st === "Disabled" ? "Disabled" : "Enabled"} ${a.name}`);
  };

  return (
    <section>
      <Crumbs trail={[["Authorities", href("authorities")], [a.name]]} />
      <Head
        title={a.name}
        sub={
          isInt
            ? `An intermediate authority signed by ${parent?.name ?? "a removed authority"}; it issues the certificates below.`
            : "A root authority, kept offline. It only signs intermediates."
        }
      />
      <div className="ct-col ct-one">
        <Card className="panel" role="region" aria-labelledby="ad-facts">
          <h2 id="ad-facts">Details</h2>
          <dl className="kv ct-kv">
            <dt>Type</dt>
            <dd>{a.kind === "Root" ? "Root, kept offline" : "Intermediate"}</dd>
            <dt>Status</dt>
            <dd>
              <Stat s={a.status} />
            </dd>
            <dt>Key type</dt>
            <dd className="mono">{a.key}</dd>
            <dt>Valid until</dt>
            <dd>
              {date(a.until)}, {inTime(a.until)}
            </dd>
            <dt>Signed by</dt>
            <dd>
              {parent ? (
                <A tab="authorities" id={parent.id}>
                  {parent.name}
                </A>
              ) : (
                "Nothing. It is a root."
              )}
            </dd>
            <dt>{isInt ? "Issued" : "Signed"}</dt>
            <dd>{isInt ? plural(mine.length, "certificate") : plural(kids.length, "intermediate")}</dd>
          </dl>
        </Card>
        <Card className="panel" role="region" aria-labelledby="ad-issued">
          <h2 id="ad-issued">Certificates it issued</h2>
          {!isInt ? (
            <p className="muted small">Roots sign intermediates only. Open an intermediate to see its certificates.</p>
          ) : mine.length === 0 ? (
            <p className="muted small">It has not issued anything yet.</p>
          ) : (
            <ul className="plain">
              {mine.map((c) => (
                <li key={c.id}>
                  <A tab="certificates" id={c.id}>
                    {c.name}
                  </A>
                  <span className="muted small">{c.use}</span>
                  <Stat s={c.revoked ? "Revoked" : c.expires <= NOW ? "Expired" : "Valid"} />
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="panel" role="region" aria-labelledby="ad-status">
          <h2 id="ad-status">{a.status === "Disabled" ? "Enable this authority" : "Disable this authority"}</h2>
          {!isInt ? (
            <p className="muted small">Roots stay offline and are not disabled here.</p>
          ) : a.status === "Disabled" ? (
            <>
              <p className="muted small">
                It cannot issue, and its {plural(hit, "certificate")} cannot be renewed. Enabling it lets both happen
                again.
              </p>
              <Button variant="outline" className="ct-gap" type="button" onClick={() => setStatus("Active")}>
                Enable authority
              </Button>
            </>
          ) : (
            <>
              <p className="muted small">
                Disabling stops it issuing and stops {hit === 0 ? "no certificates" : plural(hit, "certificate")} from
                being renewed, including any under its intermediates. They keep working until they expire.
              </p>
              <Button
                variant="ghost"
                size="sm"
                className="ct-gap text-(--destructive-text)"
                type="button"
                aria-expanded={disabling}
                onClick={() => setDisabling(!disabling)}
              >
                Disable authority
              </Button>
              {disabling && (
                <span className="inline-form ct-gap">
                  <Button variant="destructive" type="button" onClick={() => setStatus("Disabled")}>
                    Yes, disable {a.name}
                  </Button>
                  <Button variant="ghost" type="button" onClick={() => setDisabling(false)}>
                    Keep it
                  </Button>
                </span>
              )}
            </>
          )}
        </Card>
      </div>
    </section>
  );
}

function Authorities({ sub, say }: PageProps) {
  return sub ? <AuthDetail id={decodeURIComponent(sub)} say={say} /> : <AuthList say={say} />;
}

/* ---------------------------------------------------------------- Profiles */

// The draft of one profile's rules. Its own component so typing is kept until you save.
function ProfileForm({ p, say }: { p: Profile; say: Say }) {
  const [, setProfiles] = useProfiles();
  const [d, setD] = useState({
    name: p.name,
    pattern: p.pattern,
    days: String(p.maxDays),
    key: p.key,
    use: p.use,
    approval: p.approval,
  });
  const set = <K extends keyof typeof d>(k: K, v: (typeof d)[K]) => setD((x) => ({ ...x, [k]: v }));
  const n = Number(d.days),
    bad = !d.name.trim() || !d.pattern.trim() || !(n >= 1 && n <= 825);
  const dirty =
    d.name !== p.name ||
    d.pattern !== p.pattern ||
    n !== p.maxDays ||
    d.key !== p.key ||
    d.use !== p.use ||
    d.approval !== p.approval;
  const save = (e: React.FormEvent) => {
    e.preventDefault();
    if (bad) return;
    setProfiles((r) =>
      r.map((x) =>
        x.id === p.id
          ? {
              ...x,
              name: d.name.trim(),
              pattern: d.pattern.trim(),
              maxDays: n,
              key: d.key,
              use: d.use,
              approval: d.approval,
            }
          : x,
      ),
    );
    say(`Saved ${d.name.trim()}`);
  };
  return (
    <Card className="panel">
      <form className="contents" onSubmit={save} aria-label={`Rules for ${p.name}`}>
        <h2>Rules</h2>
        <div className="ct-form">
          <Label className="field">
            Name
            <Input value={d.name} required autoComplete="off" onChange={(e) => set("name", e.target.value)} />
          </Label>
          <Label className="field">
            Allowed names
            <Input value={d.pattern} required autoComplete="off" onChange={(e) => set("pattern", e.target.value)} />
          </Label>
          <Label className="field">
            Longest lifetime (days)
            <Input
              className="num-in"
              type="number"
              min={1}
              max={825}
              value={d.days}
              onChange={(e) => set("days", e.target.value)}
            />
          </Label>
          <Label className="field">
            Key type
            <Dropdown value={d.key} onChange={(e) => set("key", e)}>
              {KEYS.map((k) => (
                <Option key={k}>{k}</Option>
              ))}
            </Dropdown>
          </Label>
          <Label className="field">
            Used for
            <Dropdown value={d.use} onChange={(e) => set("use", e as Use)}>
              {USES.map((u) => (
                <Option key={u}>{u}</Option>
              ))}
            </Dropdown>
          </Label>
          <span className="inline-form">
            <Switch label={`${d.name} needs approval`} checked={d.approval} onChange={(on) => set("approval", on)} />{" "}
            Needs approval before issuing
          </span>
        </div>
        <p className="hint">
          Changes apply to new certificates and renewals. Existing certificates keep their dates until renewed.
        </p>
        <span className="inline-form ct-gap">
          <Button type="submit" disabled={bad || !dirty}>
            Save profile
          </Button>
          <Button
            variant="ghost"
            type="button"
            disabled={!dirty}
            onClick={() =>
              setD({
                name: p.name,
                pattern: p.pattern,
                days: String(p.maxDays),
                key: p.key,
                use: p.use,
                approval: p.approval,
              })
            }
          >
            Discard changes
          </Button>
        </span>
      </form>
    </Card>
  );
}

function ProfileDetail({ id, say }: { id: string; say: Say }) {
  const [profiles] = useProfiles();
  const p = profiles.find((x) => x.id === id);
  if (!p) return <NotFound trail="Profile" what="profile" tab="templates" list="Profiles" />;
  return (
    <section>
      <Crumbs trail={[["Profiles", href("templates")], [p.name]]} />
      <Head
        title={p.name}
        sub={`The rules for ${p.use.toLowerCase()} certificates: ${p.approval ? "someone must approve each one" : "issued straight away"}, up to ${plural(p.maxDays, "day")}.`}
      />
      <div className="ct-col ct-one">
        <ProfileForm key={`${p.id}${p.name}${p.pattern}${p.maxDays}${p.key}${p.use}${p.approval}`} p={p} say={say} />
      </div>
    </section>
  );
}

function ProfileList({ say }: { say: Say }) {
  const [profiles, setProfiles] = useProfiles(),
    [certs] = useCerts();
  const [adding, setAdding] = useState(false);
  const add = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setProfiles((r) => [
      ...r,
      {
        id: `p_${++seq}`,
        name: String(f.get("name")).trim(),
        pattern: String(f.get("pattern")).trim(),
        maxDays: Number(f.get("days")),
        key: String(f.get("key")),
        use: String(f.get("use")) as Use,
        approval: f.get("approval") === "on",
      },
    ]);
    say(`Added profile ${f.get("name")}`);
    setAdding(false);
  };
  return (
    <section>
      <Head
        title="Profiles"
        sub="A profile is the rule set a certificate is issued under: which names it may carry, how long it lasts and whether someone must approve it."
      >
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Add profile
        </Button>
      </Head>
      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={add} aria-label="Add profile">
            <h2>Add a profile</h2>
            <div className="add certs">
              <Label className="field">
                Name
                <Input name="name" required autoFocus autoComplete="off" placeholder="Edge TLS" />
              </Label>
              <Label className="field">
                Allowed names
                <Input name="pattern" required autoComplete="off" placeholder="*.edge.acme.example" />
              </Label>
              <Label className="field">
                Longest lifetime (days)
                <Input name="days" type="number" min={1} max={825} defaultValue={90} required />
              </Label>
              <Label className="field">
                Key type
                <Dropdown name="key">
                  {KEYS.map((k) => (
                    <Option key={k}>{k}</Option>
                  ))}
                </Dropdown>
              </Label>
              <Label className="field">
                Used for
                <Dropdown name="use">
                  {USES.map((u) => (
                    <Option key={u}>{u}</Option>
                  ))}
                </Dropdown>
              </Label>
              <label className="inline-form">
                <Checkbox name="approval" /> Needs approval
              </label>
              <Button type="submit">Add profile</Button>
              <Button variant="ghost" type="button" onClick={() => setAdding(false)}>
                Cancel
              </Button>
            </div>
            <p className="hint">Use * for any part of a name. A request for a name outside the pattern is refused.</p>
          </form>
        </Card>
      )}
      {profiles.length === 0 ? (
        <Empty icon="grid">
          <b>No profiles yet.</b> Add one, or nobody can be issued a certificate.
        </Empty>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Profile</TableHead>
                <TableHead>Allowed names</TableHead>
                <TableHead>Longest lifetime</TableHead>
                <TableHead>Key type</TableHead>
                <TableHead>Used for</TableHead>
                <TableHead>Issuance</TableHead>
                <TableHead>Certificates</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {profiles.map((p) => (
                <TableRow key={p.id}>
                  <TableCell>
                    <a className="ct-link" href={href("templates", p.id)}>
                      <b>{p.name}</b>
                    </a>
                  </TableCell>
                  <TableCell className="mono">{p.pattern}</TableCell>
                  <TableCell>{plural(p.maxDays, "day")}</TableCell>
                  <TableCell className="mono">{p.key}</TableCell>
                  <TableCell>{p.use}</TableCell>
                  <TableCell>{p.approval ? "Needs approval" : "Automatic"}</TableCell>
                  <TableCell>{certs.filter((c) => c.profile === p.id).length}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}

function Templates({ sub, say }: PageProps) {
  return sub ? <ProfileDetail id={decodeURIComponent(sub)} say={say} /> : <ProfileList say={say} />;
}

/* ---------------------------------------------------------------- Settings */

const Row = ({ title, about, children }: { title: string; about?: React.ReactNode; children: React.ReactNode }) => (
  <div className="set-row">
    <div>
      <b>{title}</b>
      {about && <p>{about}</p>}
    </div>
    <div className="set-ctl">{children}</div>
  </div>
);

function CertSettings({ say }: PageProps) {
  const [saved, setSaved] = useSettings(),
    [profiles] = useProfiles();
  const [s, setS] = useState(saved);
  const dirty = JSON.stringify(s) !== JSON.stringify(saved);
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setS((x) => ({ ...x, [k]: v }));
  return (
    <form
      className="settings"
      onSubmit={(e) => {
        e.preventDefault();
        setSaved(s);
        say("Certificate settings saved");
      }}
    >
      <div className="screen-head">
        <div>
          <h1>Certificate settings</h1>
          <p className="lede">Defaults and rules that apply to every certificate your authorities issue.</p>
        </div>
      </div>
      <Card className="panel" role="region" aria-labelledby="cs-issue">
        <h2 id="cs-issue">Issuing</h2>
        <Row title="Default profile" about="Chosen first in the issue form.">
          <Dropdown aria-label="Default profile" value={s.profile} onChange={(e) => set("profile", e)}>
            {profiles.map((p) => (
              <Option key={p.id} value={p.id}>
                {p.name}
              </Option>
            ))}
          </Dropdown>
        </Row>
        <Row title="Default lifetime" about="A profile's longest lifetime still wins if it is shorter.">
          <Dropdown aria-label="Default lifetime" value={s.lifetime} onChange={(e) => set("lifetime", Number(e))}>
            {LIFETIMES.map(([v, l]) => (
              <Option key={v} value={v}>
                {l}
              </Option>
            ))}
          </Dropdown>
        </Row>
        <Row
          title="Renew when this many days remain"
          about="Marks certificates as expiring soon, and renews automatic ones."
        >
          <span className="inline-form">
            <Input
              className="num-in"
              type="number"
              min={1}
              max={60}
              aria-label="Renew when this many days remain"
              value={s.window}
              onChange={(e) => set("window", Number(e.target.value))}
            />{" "}
            days
          </span>
        </Row>
        <Row
          title="Warn this many days before a certificate expires"
          about={
            <>
              Warnings are sent by a rule in the <a href="#/notifications/rules">notification center</a>.
            </>
          }
        >
          <span className="inline-form">
            <Input
              className="num-in"
              type="number"
              min={1}
              max={90}
              aria-label="Warn this many days before a certificate expires"
              value={s.warn}
              onChange={(e) => set("warn", Number(e.target.value))}
            />{" "}
            days
          </span>
        </Row>
      </Card>
      <Card className="panel" role="region" aria-labelledby="cs-enroll">
        <h2 id="cs-enroll">Enrollment</h2>
        <Row title="ACME" about="Lets servers and tools such as certbot request and renew certificates themselves.">
          <Switch label="Allow ACME" checked={s.acme} onChange={(on) => set("acme", on)} />
        </Row>
        {s.acme && (
          <Row title="ACME directory address" about="Point your ACME client at this address.">
            <code>https://ca.acme.example/acme/directory</code>
          </Row>
        )}
      </Card>
      {dirty && (
        <div className="savebar" role="status">
          <span>You have unsaved changes.</span>
          <Button variant="ghost" type="button" onClick={() => setS(saved)}>
            Discard
          </Button>
          <Button type="submit">Save changes</Button>
        </div>
      )}
    </form>
  );
}

export const pages: Pages = {
  "certs/certificates": Certificates,
  "certs/authorities": Authorities,
  "certs/templates": Templates,
  "certs/settings": CertSettings,
};
