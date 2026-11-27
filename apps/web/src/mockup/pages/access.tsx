// Access pages inside one Secret Management project: machines and approvals.
// Sample data; the per-project stores are in access-store.ts.
import { Tabs, TabsList, TabsTrigger } from "@locksmith-hq/tabs";
import { Checkbox } from "@locksmith-hq/checkbox";
import { Badge } from "@locksmith-hq/badge";
import { Label } from "@locksmith-hq/label";
import { Card } from "@locksmith-hq/card";
import { Button } from "@locksmith-hq/button";
import { Input } from "@locksmith-hq/input";
import { Dropdown, Option } from "../../Dropdown";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/table";
import { useState } from "react";
import { Empty, Head, Icon, ago, type PageProps, type Pages } from "../kit";
import { hours, reqLine, useAccess, type Kind, type Req } from "./access-store";
import "./access.css";

const pid = (project?: string) => project ?? "acme-api";
const HOW: Record<Kind, string> = {
  "GitHub Actions": "Short-lived identity from GitHub; nothing stored",
  Kubernetes: "Short-lived identity from the cluster; nothing stored",
  Token: "Long-lived token that can leak (weakest)",
};

// ---------------------------------------------------------------- Machines
// CI jobs and workloads that are not AI agents, and the environments each may read.
function Machines({ project, say }: PageProps) {
  const id = pid(project),
    a = useAccess(id);
  const [adding, setAdding] = useState(false);
  const [kind, setKind] = useState<Kind>("GitHub Actions");
  const [once, setOnce] = useState<string | null>(null);
  const [ask, setAsk] = useState<string | null>(null);
  const create = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget),
      name = String(f.get("name"))
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, "-");
    const envs = f.getAll("env").map(String),
      d = String(f.get("detail") ?? "").trim();
    if (a.machines.some((m) => m.name === name)) return say(`A machine called ${name} already exists`);
    if (envs.length === 0) return say("Pick at least one environment");
    const cond: [string, string][] =
      kind === "Token"
        ? []
        : kind === "GitHub Actions"
          ? [
              ["Repository", d],
              ["Branch", String(f.get("branch") ?? "").trim() || "main"],
            ]
          : [["Service account", d]];
    a.addMachine({ name, kind, cond, envs, last: null, tail: kind === "Token" ? "new1" : "" });
    setOnce(kind === "Token" ? name : null);
    setAdding(false);
    say(`Added machine ${name}`);
  };
  return (
    <section>
      <Head
        title="Machines"
        sub={`CI jobs and workloads in ${id} that are not AI agents, and the environments each may read.`}
      >
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Add machine
        </Button>
      </Head>
      <div className="alert ac-warn" role="note">
        <Icon name="alert" />
        <span>
          Unlike an agent, a machine does receive secret values. That is why machines are listed apart from agents. Give
          each one the fewest environments it needs.
        </span>
      </div>
      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={create} aria-label="Add machine">
            <h2>Add a machine</h2>
            <div className="add share">
              <Label className="field">
                Name
                <Input name="name" required autoFocus autoComplete="off" spellCheck={false} placeholder="release-job" />
              </Label>
              <Label className="field">
                Proves who it is with
                <Dropdown value={kind} onChange={(e) => setKind(e as Kind)}>
                  <Option>GitHub Actions</Option>
                  <Option>Kubernetes</Option>
                  <Option>Token</Option>
                </Dropdown>
              </Label>
              {kind !== "Token" && (
                <Label className="field">
                  {kind === "Kubernetes" ? "Service account" : "Repository"}
                  <Input
                    key={kind}
                    name="detail"
                    required
                    autoComplete="off"
                    placeholder={kind === "Kubernetes" ? "prod/release" : `acme/${id}`}
                  />
                </Label>
              )}
              {kind === "GitHub Actions" && (
                <Label className="field">
                  Branch
                  <Input name="branch" autoComplete="off" placeholder="main" />
                </Label>
              )}
              <fieldset className="ac-fs">
                <legend className="field ac-leg">May read</legend>
                <div className="inline-form">
                  {a.envs.map((e) => (
                    <label key={e} className="inline-form ac-chk">
                      <Checkbox name="env" value={e} defaultChecked={e !== a.prod} />
                      {e}
                    </label>
                  ))}
                </div>
              </fieldset>
              <Button type="submit">Add machine</Button>
              <Button variant="ghost" type="button" onClick={() => setAdding(false)}>
                Cancel
              </Button>
            </div>
            <p className="hint">
              {kind === "Token"
                ? "A token is the weakest choice: anyone who copies it can read these environments until you revoke it. Use GitHub Actions or Kubernetes when you can."
                : "No secret is stored for this machine. It proves who it is each time it asks."}
            </p>
          </form>
        </Card>
      )}
      {once && (
        <Card className="panel once" role="status">
          <h2>Copy the token for {once} now</h2>
          <p>It is shown once and cannot be retrieved again. Store it only in the machine's own secret store.</p>
          <code className="block">lsm_sample_not_real</code>
          <Button variant="outline" size="sm" className="ac-top" type="button" onClick={() => setOnce(null)}>
            I have copied it
          </Button>
        </Card>
      )}
      {a.machines.length === 0 ? (
        <Empty icon="run">
          <b>No machines yet.</b> Add a CI job or workload that needs to read secrets from {id}.
        </Empty>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Machine</TableHead>
                <TableHead>Proves who it is with</TableHead>
                <TableHead>May read</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {a.machines.map((m) => (
                <TableRow key={m.name}>
                  <TableCell className="strong">{m.name}</TableCell>
                  <TableCell>
                    {m.kind}
                    {m.kind === "Token" && (
                      <Badge variant="secondary" data-by="agent">
                        Weakest
                      </Badge>
                    )}
                    <br />
                    <span className="muted small">
                      {m.cond.map(([k, v]) => `${k} ${v}`).join(", ") || `Token ending ${m.tail}`}. {HOW[m.kind]}.
                    </span>
                  </TableCell>
                  <TableCell className="mono">{m.envs.join(", ")}</TableCell>
                  <TableCell className={m.last === null ? "muted" : undefined}>
                    {m.last === null ? "Not yet" : ago(m.last)}
                  </TableCell>
                  <TableCell className="num nowrap">
                    {ask === m.name ? (
                      <>
                        <span className="muted small">Its next request fails.</span>{" "}
                        <Button
                          variant="destructive"
                          size="sm"
                          type="button"
                          onClick={() => {
                            a.revokeMachine(m.name);
                            setAsk(null);
                            say(`Revoked ${m.name}`);
                          }}
                        >
                          Revoke {m.name}
                        </Button>
                        <Button variant="ghost" size="sm" type="button" onClick={() => setAsk(null)}>
                          Keep
                        </Button>
                      </>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-(--destructive-text)"
                        type="button"
                        aria-label={`Revoke ${m.name}`}
                        onClick={() => setAsk(m.name)}
                      >
                        Revoke
                      </Button>
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

// ---------------------------------------------------------------- Approvals
// One waiting request, with an optional comment and a duration no longer than the one asked for.
function Waiting({
  r,
  why,
  decide,
}: {
  r: Req;
  why: string;
  decide: (r: Req, v: "Approved" | "Denied", comment: string, h: number) => void;
}) {
  const [comment, setComment] = useState("");
  const [hrs, setHrs] = useState(r.hours);
  const opts = [...new Set([1, 2, 4, 8, 24, 72, 168, r.hours].filter((h) => h <= r.hours))].sort((x, y) => x - y);
  const line = reqLine(r);
  return (
    <li className="row">
      <div className="ac-grow">
        <b>{r.who}</b>
        <p className="ac-text">{line}</p>
        <p className="why">“{r.reason}”</p>
        <p>
          {ago(r.at)}.{why && <span className="warn-t"> Cannot decide: {why}</span>}
        </p>
      </div>
      <div className="ctl">
        <Input
          type="text"
          aria-label={`Comment on ${line}`}
          placeholder="Comment (optional)"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
        <Dropdown aria-label={`Give access for, ${line}`} value={hrs} onChange={(e) => setHrs(Number(e))}>
          {opts.map((h) => (
            <Option key={h} value={h}>
              {hours(h)}
              {h === r.hours ? " (as asked)" : ""}
            </Option>
          ))}
        </Dropdown>
        <Button
          variant="outline"
          size="sm"
          type="button"
          disabled={!!why}
          aria-label={`Approve: ${line}`}
          onClick={() => decide(r, "Approved", comment, hrs)}
        >
          <Icon name="unlock" />
          Approve
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="text-(--destructive-text)"
          type="button"
          disabled={!!why}
          aria-label={`Deny: ${line}`}
          onClick={() => decide(r, "Denied", comment, hrs)}
        >
          Deny
        </Button>
      </div>
    </li>
  );
}

// Requests waiting for a yes, and what was decided.
function Approvals({ project, say }: PageProps) {
  const id = pid(project),
    a = useAccess(id);
  const [tab, setTab] = useState<"wait" | "done">("wait");
  const wait = a.reqs.filter((r) => !r.verdict),
    done = a.reqs.filter((r) => r.verdict).sort((x, y) => y.decided! - x.decided!);
  const decide = (r: Req, v: "Approved" | "Denied", comment: string, h: number) => {
    a.decide(r, v, comment, h);
    say(v === "Approved" ? `Approved: ${reqLine(r)}` : `Denied ${r.who}`);
  };
  return (
    <section>
      <Head
        title="Approvals"
        sub={`Requests in ${id} that wait for a yes. Organization owners and admins and project admins can approve, never their own request.`}
      />
      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)} className="mb-5">
        <TabsList variant="line" aria-label="Approvals">
          <TabsTrigger value="wait">
            Waiting <span className="n">{wait.length}</span>
          </TabsTrigger>
          <TabsTrigger value="done">
            Decided <span className="n">{done.length}</span>
          </TabsTrigger>
        </TabsList>
      </Tabs>
      {tab === "wait" &&
        (wait.length === 0 ? (
          <Empty icon="token">
            <b>Nothing is waiting.</b> Requests from agents and people show up here.
          </Empty>
        ) : (
          <ul className="list req">
            {wait.map((r) => (
              <Waiting key={r.id} r={r} why={a.blocked(r)} decide={decide} />
            ))}
          </ul>
        ))}
      {tab === "done" &&
        (done.length === 0 ? (
          <Empty icon="clock">
            <b>No decisions yet.</b> Approve or deny a waiting request and it lands here.
          </Empty>
        ) : (
          <div className="table-wrap">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Request</TableHead>
                  <TableHead>Asked</TableHead>
                  <TableHead>Answer</TableHead>
                  <TableHead>Decided by</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {done.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      <span className="strong">{reqLine(r)}</span>
                      <br />
                      <span className="muted small">{r.comment ? `“${r.comment}”` : `“${r.reason}”`}</span>
                    </TableCell>
                    <TableCell className="muted">{ago(r.at)}</TableCell>
                    <TableCell className={r.verdict === "Approved" ? "ok-t" : "no-t"}>
                      {r.verdict}
                      {r.granted !== undefined && (
                        <>
                          <br />
                          <span className="muted small">for {hours(r.granted)}</span>
                        </>
                      )}
                    </TableCell>
                    <TableCell>
                      {r.by}
                      <br />
                      <span className="muted small">{ago(r.decided ?? null)}</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ))}
    </section>
  );
}

export const pages: Pages = { "secrets/machines": Machines, "secrets/approvals": Approvals };
