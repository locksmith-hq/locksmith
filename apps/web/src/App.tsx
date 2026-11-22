import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createAuth, defaultConfig, type AuthService, type AuthState } from "./auth";
import { auditOutcomeMatches as auditMatches, buildWorkloadIdentity, createClient, hasPrefixCondition, isPrefixPattern, type WorkloadIdentity, type WorkloadPreset, type Agent, type AuditOutcomeFilter as AuditFilter, type AgentGrant, type AuditEvent, type AuditStatus, type Client, type McpClient, type McpToolSetting } from "@locksmith/control-plane-client";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

let defaultAuth: AuthService | undefined;
const getDefaultAuth = () => (defaultAuth ??= createAuth(defaultConfig()));

// `client` (tests, embedding) bypasses sign-in; otherwise the console is gated on an OIDC session.
export function App({ client, auth }: { client?: Client; auth?: AuthService }) {
  if (client) return <Console client={client} />;
  return <AuthGate auth={auth ?? getDefaultAuth()} />;
}

function AuthGate({ auth }: { auth: AuthService }) {
  const [state, setState] = useState<AuthState>(auth.getState());
  useEffect(() => {
    const off = auth.subscribe(setState);
    setState(auth.getState());
    void auth.start();
    return off;
  }, [auth]);
  const client = useMemo(() => createClient("", "", () => auth.token()), [auth]);

  if (state.status === "loading") return <main><p>Signing in…</p></main>;
  if (state.status === "signed-out") return <SignIn auth={auth} notice={state.notice} />;
  return (
    <Console
      client={client}
      header={
        <div aria-label="Account">
          <span data-testid="signed-in-as">{state.user.email ?? state.user.name ?? "Signed in"}</span>
          <button onClick={() => void auth.signOut()}>Sign out</button>
        </div>
      }
    />
  );
}

function SignIn({ auth, notice }: { auth: AuthService; notice?: string }) {
  return (
    <main>
      <h1>Locksmith</h1>
      {notice && <p role="alert">{notice}</p>}
      <section aria-label="Sign in">
        <button onClick={() => void auth.signIn("github")}>Continue with GitHub</button>
        <button onClick={() => void auth.signIn("google")}>Continue with Google</button>
        <button onClick={() => void auth.signIn("email")}>Continue with email</button>
      </section>
    </main>
  );
}

function Console({ client, header }: { client: Client; header?: ReactNode }) {
  const [page, setPage] = useState<"agents" | "workload" | "audit" | "tools" | "clients">("agents");
  return (
    <main>
      <h1>Locksmith</h1>
      {header}
      <nav aria-label="Pages">
        <button aria-pressed={page === "agents"} onClick={() => setPage("agents")}>Agents</button>
        <button aria-pressed={page === "workload"} onClick={() => setPage("workload")}>Workload identities</button>
        <button aria-pressed={page === "audit"} onClick={() => setPage("audit")}>Audit</button>
        <button aria-pressed={page === "tools"} onClick={() => setPage("tools")}>Tools</button>
        <button aria-pressed={page === "clients"} onClick={() => setPage("clients")}>Clients</button>
      </nav>
      {page === "audit" ? <Audit client={client} /> : page === "workload" ? <WorkloadIdentities client={client} /> : page === "tools" ? <McpTools client={client} /> : page === "clients" ? <McpClients client={client} /> : <Agents client={client} />}
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

const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";

function WorkloadIdentities({ client }: { client: Client }) {
  const [items, setItems] = useState<WorkloadIdentity[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [preset, setPreset] = useState<WorkloadPreset>("github");
  const [f, setF] = useState({ name: "", agentId: "", audience: "", issuer: "", repository: "", ref: "", environment: "", namespace: "", serviceaccount: "" });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  const refresh = useCallback(() => {
    client.listWorkloadIdentities().then(setItems, (e) => setError(errMsg(e)));
  }, [client]);
  useEffect(refresh, [refresh]);

  const body = buildWorkloadIdentity({ ...f, preset });
  const prefixWarn = hasPrefixCondition(body.conditions);

  const create = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    client.createWorkloadIdentity(body).then(
      () => { setF({ ...f, name: "", repository: "", ref: "", environment: "", namespace: "", serviceaccount: "" }); refresh(); },
      (er) => setError(errMsg(er)),
    );
  };

  return (
    <section aria-label="Workload identities">
      <h2>Workload identities</h2>
      <p>Let a CI job or cluster workload exchange its own OIDC token for a short-lived agent token. Nothing secret is stored or shown here: the policy handle is not a secret.</p>
      {error && <p role="alert">{error}</p>}
      <form onSubmit={create} aria-label="Create workload identity">
        <label>Issuer preset{" "}
          <select aria-label="Issuer preset" value={preset} onChange={(e) => setPreset(e.target.value as WorkloadPreset)}>
            <option value="github">GitHub Actions</option>
            <option value="kubernetes">Kubernetes</option>
          </select>
        </label>
        <input aria-label="Policy name" required value={f.name} onChange={set("name")} />
        <input aria-label="Agent id" required value={f.agentId} onChange={(e) => setF({ ...f, agentId: e.target.value.trim() })} />
        <input aria-label="Audience" required value={f.audience} onChange={set("audience")} />
        {preset === "github" ? (
          <>
            <p>Issuer: {GITHUB_ISSUER}</p>
            <input aria-label="Repository (owner/repo)" required value={f.repository} onChange={set("repository")} />
            <input aria-label="Ref (optional)" value={f.ref} onChange={set("ref")} />
            <input aria-label="Environment (optional)" value={f.environment} onChange={set("environment")} />
          </>
        ) : (
          <>
            <input aria-label="Issuer URL" type="url" required value={f.issuer} onChange={set("issuer")} />
            <input aria-label="Namespace" required value={f.namespace} onChange={set("namespace")} />
            <input aria-label="Service account" required value={f.serviceaccount} onChange={set("serviceaccount")} />
          </>
        )}
        {prefixWarn && (
          <p role="alert" data-testid="prefix-warning">
            Warning: a condition ends in * and matches every value with that prefix. Prefer exact values.
          </p>
        )}
        <button type="submit">Create workload identity</button>
      </form>
      {!items ? (error ? null : <p>Loading…</p>) : items.length === 0 ? <p>No workload identities yet.</p> : (
        <ul>
          {items.map((w) => (
            <li key={w.id} aria-label={`Workload identity ${w.name}`}>
              <strong>{w.name}</strong> ({w.issuer_kind}) {w.issuer} aud {w.audience} agent {w.agent_id}
              <div>Handle: <code>{w.handle}</code></div>
              <div>Last used: {w.last_used_at ?? "never"}</div>
              <ul>
                {w.conditions.map((c) => (
                  <li key={`${c.claim}=${c.pattern}`}>
                    {c.claim} = {c.pattern}{isPrefixPattern(c) ? " (prefix match)" : ""}
                  </li>
                ))}
              </ul>
              {hasPrefixCondition(w.conditions) && <p>Warning: this policy uses a prefix (*) condition.</p>}
              {confirming === w.id ? (
                <>
                  <button onClick={() => { setConfirming(null); setError(null); client.deleteWorkloadIdentity(w.id).then(refresh, (e) => setError(errMsg(e))); }}>
                    Confirm delete {w.name}
                  </button>
                  <button onClick={() => setConfirming(null)}>Cancel</button>
                </>
              ) : <button onClick={() => setConfirming(w.id)}>Delete {w.name}</button>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

const layerName = (l: string) => (l === "hub" ? "Hub (people)" : "Gateway (agents)");

function McpTools({ client }: { client: Client }) {
  const [tools, setTools] = useState<McpToolSetting[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setTools(null); setError(null);
    client.listMcpTools().then((t) => live && setTools(t), (e) => live && setError(errMsg(e)));
    return () => { live = false; };
  }, [client]);

  const toggle = async (t: McpToolSetting, enabled: boolean) => {
    setError(null);
    try {
      const u = await client.setMcpTool(t.layer, t.tool, enabled);
      setTools((cur) => cur?.map((x) => (x.layer === u.layer && x.tool === u.tool ? u : x)) ?? cur);
    } catch (e) { setError(errMsg(e)); }
  };

  return (
    <section aria-label="Tools">
      <h2>MCP tools</h2>
      {error && <p role="alert">{error}</p>}
      {!tools ? (error ? null : <p>Loading tools…</p>) : tools.length === 0 ? <p>No MCP tools.</p> : (
        (["hub", "agent"] as const).map((layer) => {
          const rows = tools.filter((t) => t.layer === layer);
          if (rows.length === 0) return null;
          return (
            <div key={layer} aria-label={`${layerName(layer)} tools`}>
              <h3>{layerName(layer)}</h3>
              <ul>
                {rows.map((t) => (
                  <li key={t.tool}>
                    <label>
                      <input
                        type="checkbox"
                        role="switch"
                        aria-label={`${t.tool} (${layer})`}
                        checked={t.enabled}
                        onChange={(e) => void toggle(t, e.target.checked)}
                      />{" "}
                      <strong>{t.tool}</strong>
                    </label>{" "}
                    {t.description} <em>{t.default_enabled ? "on by default" : "off by default"}{t.overridden ? ", changed" : ""}</em>
                  </li>
                ))}
              </ul>
            </div>
          );
        })
      )}
    </section>
  );
}

function McpClients({ client }: { client: Client }) {
  const [clients, setClients] = useState<McpClient[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setClients(null); setError(null);
    client.listMcpClients().then((c) => live && setClients(c), (e) => live && setError(errMsg(e)));
    return () => { live = false; };
  }, [client]);

  const revoke = async (c: McpClient) => {
    setError(null);
    try {
      const u = await client.revokeMcpClient(c.id);
      setClients((cur) => cur?.map((x) => (x.id === u.id ? u : x)) ?? cur);
    } catch (e) { setError(errMsg(e)); }
  };

  const label = (c: McpClient) => c.client_name || c.client_id;
  return (
    <section aria-label="Clients">
      <h2>MCP clients</h2>
      {error && <p role="alert">{error}</p>}
      {!clients ? (error ? null : <p>Loading clients…</p>) : clients.length === 0 ? <p>No MCP clients have signed in yet.</p> : (
        <table>
          <thead>
            <tr><th>Client</th><th>Layer</th><th>Principal</th><th>Last seen</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {clients.map((c) => (
              <tr key={c.id}>
                <td>{label(c)}</td><td>{layerName(c.layer)}</td><td>{c.principal}</td><td>{c.last_seen_at}</td>
                <td>{c.revoked_at ? `Revoked ${c.revoked_at}` : "Active"}</td>
                <td>{!c.revoked_at && <button onClick={() => void revoke(c)}>Revoke {label(c)}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
