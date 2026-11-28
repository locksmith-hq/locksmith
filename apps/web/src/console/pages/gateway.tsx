// Agent Gateway pages: hosts, grants and settings. All state lives in ./gateway-data so the pages agree.
import { Badge } from "@locksmith-hq/ui/badge";
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Label } from "@locksmith-hq/ui/label";
import { Card } from "@locksmith-hq/ui/card";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/ui/toggle-group";
import { Button } from "@locksmith-hq/ui/button";
import { Input } from "@locksmith-hq/ui/input";
import { Dropdown, Option } from "../../Dropdown";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
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
  SectionHead,
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
        <Button asChild>
          <a href={href}>Back to {back.toLowerCase()}</a>
        </Button>
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
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Allow a host
        </Button>
      </Head>
      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={submit} aria-label="Allow a host">
            <h2>Allow a host</h2>
            <div className="add">
              <Label className="field">
                Host name
                <Input
                  name="host"
                  required
                  autoFocus
                  placeholder="api.example.com"
                  autoComplete="off"
                  spellCheck={false}
                  aria-invalid={bad}
                  onChange={() => setBad(false)}
                />
              </Label>
              <Label className="field">
                Secret that may go there
                <Dropdown name="name">
                  {NAMES.map((n) => (
                    <Option key={n}>{n}</Option>
                  ))}
                </Dropdown>
              </Label>
              <Button type="submit">Allow host</Button>
              <Button
                variant="ghost"
                type="button"
                onClick={() => {
                  setAdding(false);
                  setBad(false);
                }}
              >
                Cancel
              </Button>
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
        </Card>
      )}
      {hosts.length === 0 ? (
        <Empty icon="http">
          <b>No hosts are allowed.</b> Agents can still run, but the gateway adds no secret to any call. Allow a host to
          start.
        </Empty>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead>Secrets that may go there</TableHead>
                <TableHead>Last request</TableHead>
                <TableHead className="num">Last 7 days</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {hosts.flatMap((h) => [
                <TableRow key={h.host}>
                  <TableCell className="mono">
                    <a className="strong" href={`#/access/hosts/${encodeURIComponent(h.host)}`}>
                      {h.host}
                    </a>
                  </TableCell>
                  <TableCell>
                    <ul className="scopes-t mono" aria-label={`Secrets allowed at ${h.host}`}>
                      {h.names.map((n) => (
                        <li key={n}>{n} </li>
                      ))}
                    </ul>
                  </TableCell>
                  <TableCell className="muted">
                    {lastCall(reqs, h.host) === null ? "Never used" : ago(lastCall(reqs, h.host))}
                  </TableCell>
                  <TableCell className="num mono">{h.week.toLocaleString("en-US")}</TableCell>
                  <TableCell className="num">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      type="button"
                      aria-label={`Remove ${h.host}`}
                      onClick={() => (h.week > 0 ? setRemoving(h.host) : remove(h))}
                    >
                      Remove
                    </Button>
                  </TableCell>
                </TableRow>,
                removing === h.host && (
                  <TableRow key={`${h.host}-x`} className="detail">
                    <TableCell colSpan={5}>
                      <Alert variant="destructive" style={{ margin: 0 }}>
                        <AlertDescription>
                          {plural(h.week, "call")} went to {h.host} in the last 7 days. After removal, the gateway
                          refuses them and agents see an error.
                          <Button variant="destructive" size="sm" type="button" onClick={() => remove(h)}>
                            Remove anyway
                          </Button>
                          <Button variant="ghost" size="sm" type="button" onClick={() => setRemoving(null)}>
                            Keep host
                          </Button>
                        </AlertDescription>
                      </Alert>
                    </TableCell>
                  </TableRow>
                ),
              ])}
            </TableBody>
          </Table>
        </div>
      )}

      <SectionHead top={28}>
        <h2>Recently blocked</h2>
        <span className="n">{plural(attempts.length, "attempt")}</span>
      </SectionHead>
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
                <Badge variant="secondary" data-by="agent">
                  Blocked
                </Badge>
                <p>
                  <span className="mono">{a.agent}</span> tried to send <span className="mono">{a.name}</span> there{" "}
                  {ago(a.at)}. No credential left the gateway.
                </p>
              </div>
              <span className="meta">
                <Button
                  variant="outline"
                  size="sm"
                  type="button"
                  aria-label={`Allow ${a.name} at ${a.host}`}
                  onClick={() => allow(a.host, a.name)}
                >
                  Allow this host
                </Button>
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
          <Button type="button" onClick={() => allow(first)}>
            <Icon name="unlock" />
            Allow {first} here
          </Button>
        )}
      </Head>
      <SectionHead>
        <h2>Secrets allowed here</h2>
        <span className="n">{names.length}</span>
      </SectionHead>
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
              <Button
                variant="ghost"
                size="sm"
                className="text-(--destructive-text)"
                type="button"
                aria-label={`Stop sending ${n} to ${host}`}
                onClick={() => dropName(n)}
              >
                Remove
              </Button>
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
          <Dropdown aria-label="Secret to allow" value={choice} onChange={(e) => setPick(e)}>
            {free.map((n) => (
              <Option key={n}>{n}</Option>
            ))}
          </Dropdown>
          <Button variant="outline" size="sm" type="submit">
            <Icon name="plus" />
            Allow secret
          </Button>
        </form>
      )}

      <SectionHead top={28}>
        <h2>Recent requests</h2>
        <span className="n">{mine.length}</span>
      </SectionHead>
      {mine.length === 0 ? (
        <Empty icon="doc">
          <b>No requests yet.</b> Calls to this host appear here as they happen.
        </Empty>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Secret</TableHead>
                <TableHead>Result</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mine.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="muted">{ago(r.at)}</TableCell>
                  <TableCell className="mono">{r.agent}</TableCell>
                  <TableCell className="mono">{r.name}</TableCell>
                  <TableCell>
                    {r.result === "Allowed" ? (
                      <span className="gw-ok">Allowed</span>
                    ) : (
                      <span className="gw-bad">Blocked</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
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
        <Button
          type="button"
          onClick={() => {
            setAdding(true);
            setNotice(null);
          }}
          disabled={adding}
        >
          <Icon name="plus" />
          Give an agent access
        </Button>
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
        <Card className="panel form">
          <form className="contents" onSubmit={give} aria-label="Give an agent access">
            <h2>Give an agent access</h2>
            <div className="add">
              <Label className="field">
                Agent
                <Dropdown name="agent" value={addAgent} onChange={(e) => setAddAgent(e)}>
                  {agents.map((a) => (
                    <Option key={a.name}>{a.name}</Option>
                  ))}
                </Dropdown>
              </Label>
              <Label className="field">
                Secret
                <Dropdown name="secret" disabled={freeSecrets.length === 0}>
                  {freeSecrets.map((s) => (
                    <Option key={s.id} value={s.id}>
                      {label(s)}
                    </Option>
                  ))}
                </Dropdown>
              </Label>
              <Label className="field">
                Expires after
                <Dropdown name="expiry" defaultValue={defaultExpiry}>
                  {EXPIRY.map(([l], i) => (
                    <Option key={l} value={i}>
                      {l}
                    </Option>
                  ))}
                </Dropdown>
              </Label>
              <Button type="submit" disabled={freeSecrets.length === 0}>
                Give access
              </Button>
              <Button
                variant="ghost"
                type="button"
                onClick={() => {
                  setAdding(false);
                  setNotice(null);
                }}
              >
                Cancel
              </Button>
            </div>
            {freeSecrets.length === 0 && <p className="hint">{addAgent} already has access to every secret.</p>}
            {notice && <Blocked why={notice} />}
            <p className="hint">The agent can ask the gateway to use the secret. It is never handed the value.</p>
          </form>
        </Card>
      )}
      <div className="mb-4 flex flex-wrap items-center gap-4 [&_.push]:ml-auto">
        <Label className="field">
          Agent
          <Dropdown value={agent} onChange={(e) => setAgent(e)}>
            <Option value="all">All agents</Option>
            {agents.map((a) => (
              <Option key={a.name}>{a.name}</Option>
            ))}
          </Dropdown>
        </Label>
        <Label className="field">
          Project
          <Dropdown value={project} onChange={(e) => setProject(e)}>
            <Option value="all">All projects</Option>
            {projectIds.map((p) => (
              <Option key={p}>{p}</Option>
            ))}
          </Dropdown>
        </Label>
        <ToggleGroup type="single" value={String(quick)} aria-label="Quick filter">
          <ToggleGroupItem size="sm" value="all" onClick={() => setQuick("all")}>
            All<span className="n">{all.length}</span>
          </ToggleGroupItem>
          <ToggleGroupItem size="sm" value="none" onClick={() => setQuick("none")}>
            No expiry<span className="n">{count((r) => r.expires === null)}</span>
          </ToggleGroupItem>
          <ToggleGroupItem size="sm" value="soon" onClick={() => setQuick("soon")}>
            Expiring within a day<span className="n">{count((r) => r.expires !== null && r.expires - NOW <= DAY)}</span>
          </ToggleGroupItem>
        </ToggleGroup>
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
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Agent</TableHead>
                <TableHead>Secret</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.flatMap((r) => [
                <TableRow key={r.key}>
                  <TableCell className="mono strong">{r.agent}</TableCell>
                  <TableCell>
                    <a className="mono strong" href={`#/secrets/${r.project}`}>
                      {r.name}
                    </a>
                    <div className="muted small">
                      {r.project} / {r.env}
                    </div>
                  </TableCell>
                  <TableCell className={r.expires === null ? "text-(--warning-text)" : ""}>{when(r.expires)}</TableCell>
                  <TableCell className="muted">{ago(r.last)}</TableCell>
                  <TableCell className="num">
                    <Button
                      variant="ghost"
                      size="sm"
                      type="button"
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
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      type="button"
                      aria-label={`Revoke ${r.agent} on ${r.name} in ${r.project}/${r.env}`}
                      onClick={() => revoke(r)}
                    >
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>,
                editing === r.key && (
                  <TableRow key={`${r.key}-e`} className="detail">
                    <TableCell colSpan={5}>
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
                        <Dropdown
                          id={`gw-exp-${r.key}`}
                          value={pick}
                          onChange={(e) => {
                            setPick(Number(e));
                            setNotice(null);
                          }}
                        >
                          {EXPIRY.map(([l], i) => (
                            <Option key={l} value={i}>
                              {l} from now
                            </Option>
                          ))}
                        </Dropdown>
                        <Button size="sm" type="submit">
                          Save
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          type="button"
                          onClick={() => {
                            setEditing(null);
                            setNotice(null);
                          }}
                        >
                          Cancel
                        </Button>
                        {notice && <Blocked why={notice} />}
                      </form>
                    </TableCell>
                  </TableRow>
                ),
              ])}
            </TableBody>
          </Table>
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
  <Dropdown aria-label={name} value={value} onChange={(e) => onChange(e)}>
    {options.map((o) => (
      <Option key={o}>{o}</Option>
    ))}
  </Dropdown>
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
      <Card className="panel" role="region" aria-labelledby="gw-guard">
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
      </Card>
      <Card className="panel" role="region" aria-labelledby="gw-access">
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
          <span className="set-fixed">15 minutes, fixed</span>
        </Row>
        <Row
          title="Remove the credential from responses"
          about="The gateway strips the credential and its common encodings from every response before the agent sees it. If it cannot be sure, it withholds the response."
        >
          <span className="set-fixed">Always on</span>
        </Row>
      </Card>
      <Card className="panel danger-zone" role="region" aria-labelledby="gw-pause">
        <h2 id="gw-pause">Pause all agents</h2>
        <p className="muted">
          Revokes every live session and stops new ones until you resume. Use it if you think an agent is doing
          something it should not. Secrets and grants are not changed, and people can still unlock and export.
        </p>
        <p style={{ margin: "12px 0 0" }}>
          {paused ? (
            <Button
              type="button"
              onClick={() => {
                setSaved((g) => ({ ...g, paused: false }));
                say("Agents resumed");
              }}
            >
              <Icon name="unlock" />
              Resume agents
            </Button>
          ) : (
            <Button
              variant="destructive"
              type="button"
              onClick={() => {
                setSaved((g) => ({ ...g, paused: true }));
                say("Agents paused");
              }}
            >
              <Icon name="lock" />
              Pause all agents
            </Button>
          )}
          {paused && (
            <span className="gw-warn" role="status" style={{ display: "inline-flex", marginLeft: 12 }}>
              <Icon name="alert" />
              Paused. No agent can get a token.
            </span>
          )}
        </p>
      </Card>
      {dirty && (
        <div className="savebar" role="status">
          <span>You have unsaved changes.</span>
          <Button variant="ghost" type="button" onClick={() => setS(cur)}>
            Discard
          </Button>
          <Button type="submit">Save changes</Button>
        </div>
      )}
    </form>
  );
}

export const pages: Pages = { "access/hosts": Hosts, "access/grants": Grants, "access/settings": GatewaySettings };
