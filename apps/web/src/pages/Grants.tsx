import { useCallback, useEffect, useState } from "react";
import type { Agent, AgentGrant, Client } from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";
import { useQuery } from "@tanstack/react-query";
import { Head } from "@locksmith/ui";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

export function Grants({ client, agent, onError }: { client: Client; agent: Agent; onError: (m: string) => void }) {
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
      <ul className="plain">
        {grants.map((g) => (
          <li key={g.id}>
            {g.secret_name} ({g.mode}) {g.expires_at ? `expires ${g.expires_at}` : "no expiry"}
            <button className="btn sm quiet danger-text" onClick={() => void act(() => client.revokeGrant(agent.id, g.id))}>
              Revoke {g.secret_name}
            </button>
          </li>
        ))}
      </ul>
      <form
        className="inline-form"
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
        <button type="submit" className="btn sm primary">Grant {agent.name}</button>
      </form>
    </div>
  );
}

/** Grants page: every agent with its grants (mode, target, expiry) and the grant form. */
export function GrantsPage({ client }: { client: Client }) {
  const q = useQuery({ queryKey: ["agents"], queryFn: () => client.listAgents() });
  const [error, setError] = useState<string | null>(null);
  return (
    <section aria-label="Grants">
      <Head title="Grants" />
      {error && <p role="alert" className="state">{error}</p>}
      <QueryState query={q} empty="No agents yet, so no grants.">
        {(agents: Agent[]) => (
          <ul className="list">{agents.map((a) => <li key={a.id} className="row"><strong>{a.name}</strong><Grants client={client} agent={a} onError={setError} /></li>)}</ul>
        )}
      </QueryState>
    </section>
  );
}
