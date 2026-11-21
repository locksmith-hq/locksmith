import { useCallback, useEffect, useState } from "react";
import type { Agent, Client } from "@locksmith/control-plane-client";
import { Grants } from "./Grants";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

export function Agents({ client }: { client: Client }) {
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
