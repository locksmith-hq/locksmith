// Access pages inside one Secret Management project: machines and approvals.
// Sample data; the per-project stores are in access-store.ts.
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
        <button type="button" className="btn primary" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Add machine
        </button>
      </Head>
      <div className="alert ac-warn" role="note">
        <Icon name="alert" />
        <span>
          Unlike an agent, a machine does receive secret values. That is why machines are listed apart from agents. Give
          each one the fewest environments it needs.
        </span>
      </div>
      {adding && (
        <form className="panel form" onSubmit={create} aria-label="Add machine">
          <h2>Add a machine</h2>
          <div className="add share">
            <label className="field">
              Name
              <input name="name" required autoFocus autoComplete="off" spellCheck={false} placeholder="release-job" />
            </label>
            <label className="field">
              Proves who it is with
              <select value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
                <option>GitHub Actions</option>
                <option>Kubernetes</option>
                <option>Token</option>
              </select>
            </label>
            {kind !== "Token" && (
              <label className="field">
                {kind === "Kubernetes" ? "Service account" : "Repository"}
                <input
                  key={kind}
                  name="detail"
                  required
                  autoComplete="off"
                  placeholder={kind === "Kubernetes" ? "prod/release" : `acme/${id}`}
                />
              </label>
            )}
            {kind === "GitHub Actions" && (
              <label className="field">
                Branch
                <input name="branch" autoComplete="off" placeholder="main" />
              </label>
            )}
            <fieldset className="ac-fs">
              <legend className="field ac-leg">May read</legend>
              <div className="inline-form">
                {a.envs.map((e) => (
                  <label key={e} className="inline-form ac-chk">
                    <input type="checkbox" name="env" value={e} defaultChecked={e !== a.prod} />
                    {e}
                  </label>
                ))}
              </div>
            </fieldset>
            <button type="submit" className="btn primary">
              Add machine
            </button>
            <button type="button" className="btn quiet" onClick={() => setAdding(false)}>
              Cancel
            </button>
          </div>
          <p className="hint">
            {kind === "Token"
              ? "A token is the weakest choice: anyone who copies it can read these environments until you revoke it. Use GitHub Actions or Kubernetes when you can."
              : "No secret is stored for this machine. It proves who it is each time it asks."}
          </p>
        </form>
      )}
      {once && (
        <div className="panel once" role="status">
          <h2>Copy the token for {once} now</h2>
          <p>It is shown once and cannot be retrieved again. Store it only in the machine's own secret store.</p>
          <code className="block">lsm_sample_not_real</code>
          <button type="button" className="btn sm ac-top" onClick={() => setOnce(null)}>
            I have copied it
          </button>
        </div>
      )}
      {a.machines.length === 0 ? (
        <Empty icon="run">
          <b>No machines yet.</b> Add a CI job or workload that needs to read secrets from {id}.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th>Machine</th>
                <th>Proves who it is with</th>
                <th>May read</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {a.machines.map((m) => (
                <tr key={m.name}>
                  <td className="strong">{m.name}</td>
                  <td>
                    {m.kind}
                    {m.kind === "Token" && (
                      <span className="badge" data-by="agent">
                        Weakest
                      </span>
                    )}
                    <br />
                    <span className="muted small">
                      {m.cond.map(([k, v]) => `${k} ${v}`).join(", ") || `Token ending ${m.tail}`}. {HOW[m.kind]}.
                    </span>
                  </td>
                  <td className="mono">{m.envs.join(", ")}</td>
                  <td className={m.last === null ? "muted" : undefined}>{m.last === null ? "Not yet" : ago(m.last)}</td>
                  <td className="num nowrap">
                    {ask === m.name ? (
                      <>
                        <span className="muted small">Its next request fails.</span>{" "}
                        <button
                          type="button"
                          className="btn sm danger"
                          onClick={() => {
                            a.revokeMachine(m.name);
                            setAsk(null);
                            say(`Revoked ${m.name}`);
                          }}
                        >
                          Revoke {m.name}
                        </button>
                        <button type="button" className="btn sm quiet" onClick={() => setAsk(null)}>
                          Keep
                        </button>
                      </>
                    ) : (
                      <button
                        type="button"
                        className="btn sm quiet danger-text"
                        aria-label={`Revoke ${m.name}`}
                        onClick={() => setAsk(m.name)}
                      >
                        Revoke
                      </button>
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
        <input
          type="text"
          aria-label={`Comment on ${line}`}
          placeholder="Comment (optional)"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
        <select aria-label={`Give access for, ${line}`} value={hrs} onChange={(e) => setHrs(Number(e.target.value))}>
          {opts.map((h) => (
            <option key={h} value={h}>
              {hours(h)}
              {h === r.hours ? " (as asked)" : ""}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="btn sm"
          disabled={!!why}
          aria-label={`Approve: ${line}`}
          onClick={() => decide(r, "Approved", comment, hrs)}
        >
          <Icon name="unlock" />
          Approve
        </button>
        <button
          type="button"
          className="btn sm quiet danger-text"
          disabled={!!why}
          aria-label={`Deny: ${line}`}
          onClick={() => decide(r, "Denied", comment, hrs)}
        >
          Deny
        </button>
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
      <nav className="tabs" aria-label="Approvals">
        <button type="button" aria-current={tab === "wait" ? "page" : undefined} onClick={() => setTab("wait")}>
          Waiting <span className="n">{wait.length}</span>
        </button>
        <button type="button" aria-current={tab === "done" ? "page" : undefined} onClick={() => setTab("done")}>
          Decided <span className="n">{done.length}</span>
        </button>
      </nav>
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
            <table className="grid">
              <thead>
                <tr>
                  <th>Request</th>
                  <th>Asked</th>
                  <th>Answer</th>
                  <th>Decided by</th>
                </tr>
              </thead>
              <tbody>
                {done.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <span className="strong">{reqLine(r)}</span>
                      <br />
                      <span className="muted small">{r.comment ? `“${r.comment}”` : `“${r.reason}”`}</span>
                    </td>
                    <td className="muted">{ago(r.at)}</td>
                    <td className={r.verdict === "Approved" ? "ok-t" : "no-t"}>
                      {r.verdict}
                      {r.granted !== undefined && (
                        <>
                          <br />
                          <span className="muted small">for {hours(r.granted)}</span>
                        </>
                      )}
                    </td>
                    <td>
                      {r.by}
                      <br />
                      <span className="muted small">{ago(r.decided ?? null)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
    </section>
  );
}

export const pages: Pages = { "secrets/machines": Machines, "secrets/approvals": Approvals };
