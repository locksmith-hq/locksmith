// Access pages inside one Secret Management project: machines and approvals.
// Sample data; the per-project stores are in access-store.ts.
import { Checkbox } from "@locksmith-hq/ui/checkbox";
import { Badge } from "@locksmith-hq/ui/badge";
import { Label } from "@locksmith-hq/ui/label";
import { Card } from "@locksmith-hq/ui/card";
import { Button } from "@locksmith-hq/ui/button";
import { Input } from "@locksmith-hq/ui/input";
import { Dropdown, Option } from "../../Dropdown";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
import { useState } from "react";
import { Empty, Head, Icon, ago, type PageProps, type Pages } from "../kit";
import { useAccess, type Kind } from "./access-store";
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
                <div className="flex flex-wrap items-center gap-2">
                  {a.envs.map((e) => (
                    <label key={e} className="flex flex-wrap items-center gap-2 ac-chk">
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

export const pages: Pages = { "secrets/machines": Machines };
