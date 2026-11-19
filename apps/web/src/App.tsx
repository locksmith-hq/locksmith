import { useCallback, useEffect, useRef, useState } from "react";
import { createClient, type Agent, type AgentGrant, type AuditEvent, type AuditStatus, type Client } from "@locksmith/control-plane-client";

const ORG_KEY = "locksmith.org"; // an org id is not a secret; the enrollment secret is never stored

function loadOrg(): string {
  try { return localStorage.getItem(ORG_KEY) ?? ""; } catch { return ""; }
}
function saveOrg(v: string) {
  try { localStorage.setItem(ORG_KEY, v); } catch { /* storage unavailable */ }
}
const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

export function App({ client: injected }: { client?: Client }) {
  const [org, setOrg] = useState(loadOrg);
  const client = injected ?? (org ? createClient(org) : null);
  const [page, setPage] = useState<"agents" | "audit">("agents");
  return (
    <main>
      <h1>Locksmith</h1>
      <nav aria-label="Pages">
        <button aria-pressed={page === "agents"} onClick={() => setPage("agents")}>Agents</button>
        <button aria-pressed={page === "audit"} onClick={() => setPage("audit")}>Audit</button>
      </nav>
      {!injected && (
        <label>
          Org id
          <input value={org} onChange={(e) => { setOrg(e.target.value.trim()); saveOrg(e.target.value.trim()); }} />
        </label>
      )}
      {client ? (page === "audit" ? <Audit client={client} /> : <Agents client={client} />) : <p>Enter an org id to continue.</p>}
    </main>
  );
}

function Agents({ client }: { client: Client }) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [error, setError] = useState<string | null>(null);
  // Held in React state only; cleared on dismiss. Never written to storage or logged.
  const [secret, setSecret] = useState<{ agent: string; value: string } | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const refresh = useCallback(() => {
    client.listAgents().then(setAgents, (e) => setError(errMsg(e)));
  }, [client]);
  useEffect(refresh, [refresh]);

  const run = async (f: () => Promise<void>) => {
    setError(null);
    try { await f(); } catch (e) { setError(errMsg(e)); }
  };

  const create = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await client.createAgent({ name, description });
      setSecret({ agent: r.agent.name, value: r.enrollment_secret });
      setName(""); setDescription("");
      refresh();
    });
  };

  return (
    <>
      {error && <p role="alert">{error}</p>}
      {secret && (
        <section aria-label="Enrollment secret">
          <p>Enrollment secret for {secret.agent}. It is shown once and cannot be retrieved again.</p>
          <code data-testid="enrollment-secret">{secret.value}</code>
          <button onClick={() => setSecret(null)}>Dismiss</button>
        </section>
      )}
      <form onSubmit={create} aria-label="Create agent">
        <input aria-label="Agent name" required value={name} onChange={(e) => setName(e.target.value)} />
        <input aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        <button type="submit">Create agent</button>
      </form>
      {agents.length === 0 ? <p>No agents yet.</p> : (
        <ul>
          {agents.map((a) => (
            <li key={a.id}>
              <strong>{a.name}</strong> {a.description}
              <button onClick={() => void run(async () => { await client.deleteAgent(a.id); refresh(); })}>
                Delete {a.name}
              </button>
              <Grants client={client} agent={a} onError={setError} />
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function Grants({ client, agent, onError }: { client: Client; agent: Agent; onError: (m: string) => void }) {
  const [grants, setGrants] = useState<AgentGrant[]>([]);
  const [secretId, setSecretId] = useState("");
  const [expires, setExpires] = useState("");

  const refresh = useCallback(() => {
    client.listGrants(agent.id).then(setGrants, (e) => onError(errMsg(e)));
  }, [client, agent.id, onError]);
  useEffect(refresh, [refresh]);

  const act = (f: () => Promise<unknown>) => f().then(refresh, (e) => onError(errMsg(e)));

  return (
    <div aria-label={`Grants for ${agent.name}`}>
      <ul>
        {grants.map((g) => (
          <li key={g.id}>
            {g.secret_name} ({g.mode}) {g.expires_at ? `expires ${g.expires_at}` : "no expiry"}
            <button onClick={() => void act(() => client.revokeGrant(agent.id, g.id))}>
              Revoke {g.secret_name}
            </button>
          </li>
        ))}
      </ul>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void act(async () => {
            await client.createGrant(agent.id, {
              secret_id: secretId,
              mode: "relay",
              expires_at: expires ? new Date(expires).toISOString() : null,
            });
            setSecretId(""); setExpires("");
          });
        }}
      >
        <input aria-label={`Secret id for ${agent.name}`} required value={secretId} onChange={(e) => setSecretId(e.target.value.trim())} />
        <input aria-label={`Expiry for ${agent.name}`} type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
        <button type="submit">Grant {agent.name}</button>
      </form>
    </div>
  );
}

function chainSummary(s: AuditStatus): string {
  const v = s.latest_verify;
  if (!v) return "Not verified yet";
  if (v.ok) return `Verified OK at ${v.finished_at}`;
  return `Verification FAILED at ${v.finished_at}${v.broken_seq != null ? ` (first broken seq ${v.broken_seq}${v.break_kind ? `, ${v.break_kind}` : ""})` : ""}`;
}

type AuditFilter = "all" | "denied" | "redaction_failed";
const auditMatches = (e: AuditEvent, f: AuditFilter) =>
  f === "all" || (f === "denied" ? e.outcome === "denied" || e.kind === "relay.denied" : e.outcome === "redaction_failed");

function Audit({ client }: { client: Client }) {
  const [status, setStatus] = useState<AuditStatus | null>(null);
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const inflight = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<AuditFilter>("all");

  useEffect(() => {
    let live = true; // a response for an earlier client (org) is ignored
    setStatus(null); setEvents(null); setNext(null); setError(null); setLoadingMore(false);
    client.auditStatus().then((s) => live && setStatus(s), (e) => live && setError(errMsg(e)));
    client.listAuditEvents().then(
      (p) => { if (live) { setEvents(p.items); setNext(p.next ?? null); } },
      (e) => live && setError(errMsg(e)),
    );
    return () => { live = false; };
  }, [client]);

  const more = () => {
    if (inflight.current || !next) return;
    inflight.current = true;
    setLoadingMore(true);
    client.listAuditEvents({ cursor: next }).then(
      (p) => { setEvents((cur) => [...(cur ?? []), ...p.items]); setNext(p.next ?? null); setError(null); },
      (e) => setError(errMsg(e)),
    ).finally(() => { inflight.current = false; setLoadingMore(false); });
  };

  return (
    <section aria-label="Audit">
      <h2>Audit</h2>
      {error && <p role="alert">{error}</p>}
      {status && (
        <div aria-label="Chain status">
          <p>Head seq: {status.head_seq}</p>
          <p>
            Latest checkpoint:{" "}
            {status.latest_checkpoint ? `seq ${status.latest_checkpoint.seq} at ${status.latest_checkpoint.at}` : "none yet"}
          </p>
          <p data-testid="verify-result">{chainSummary(status)}</p>
        </div>
      )}
      <label>
        Outcome{" "}
        <select aria-label="Outcome filter" value={filter} onChange={(e) => setFilter(e.target.value as AuditFilter)}>
          <option value="all">All</option>
          <option value="denied">Denied</option>
          <option value="redaction_failed">Redaction failed</option>
        </select>
      </label>
      {!events ? (error ? null : <p>Reading the ledger…</p>) : events.length === 0 ? <p>No audit events yet.</p> : !events.some((e) => auditMatches(e, filter)) ? <p>No matching events{next ? " loaded yet" : ""}.</p> : (
        <table>
          <thead>
            <tr><th>Seq</th><th>Time</th><th>Kind</th><th>Actor</th><th>Target</th><th>Outcome</th></tr>
          </thead>
          <tbody>
            {events.filter((e) => auditMatches(e, filter)).map((e) => (
              <tr key={e.id}>
                <td>{e.seq}</td><td>{e.at}</td><td>{e.kind}</td><td>{e.actor}</td><td>{e.target ?? ""}</td><td>{e.outcome}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {next && <button disabled={loadingMore} onClick={more}>Load more</button>}
    </section>
  );
}
