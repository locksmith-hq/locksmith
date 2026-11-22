import { useCallback, useEffect, useState } from "react";
import { buildWorkloadIdentity, hasPrefixCondition, isPrefixPattern, type Client, type WorkloadIdentity, type WorkloadPreset } from "@locksmith/control-plane-client";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";

export function WorkloadIdentities({ client }: { client: Client }) {
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
