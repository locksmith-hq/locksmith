import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Agent, Client } from "@locksmith/control-plane-client";
import { Head } from "@locksmith/ui";
import { Grants } from "./Grants";
import { QueryState } from "../QueryState";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

export function Agents({ client }: { client: Client }) {
  const [error, setError] = useState<string | null>(null);
  // Held in React state only; cleared on dismiss. Never written to storage or logged.
  const [secret, setSecret] = useState<{ agent: string; value: string } | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const q = useQuery({ queryKey: ["agents"], queryFn: () => client.listAgents() });
  const refresh = () => void q.refetch();

  const run = async (f: () => Promise<void>) => {
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(errMsg(e));
    }
  };

  const create = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await client.createAgent({ name, description });
      setSecret({ agent: r.agent.name, value: r.enrollment_secret });
      setName("");
      setDescription("");
      refresh();
    });
  };

  return (
    <>
      <Head title="Agents" />
      {error && (
        <p role="alert" className="state">
          {error}
        </p>
      )}
      {secret && (
        <section aria-label="Enrollment secret" className="panel">
          <p>Enrollment secret for {secret.agent}. It is shown once and cannot be retrieved again.</p>
          <code data-testid="enrollment-secret">{secret.value}</code>
          <button
            className="btn sm"
            onClick={() =>
              void navigator.clipboard?.writeText(secret.value).catch(() => setError("Could not copy to the clipboard"))
            }
          >
            Copy
          </button>
          <button className="btn sm" onClick={() => setSecret(null)}>
            Dismiss
          </button>
        </section>
      )}
      <form onSubmit={create} aria-label="Create agent" className="panel form inline-form">
        <input aria-label="Agent name" required value={name} onChange={(e) => setName(e.target.value)} />
        <input aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        <button type="submit" className="btn primary">
          Create agent
        </button>
      </form>
      <QueryState query={q} empty="No agents yet.">
        {(agents: Agent[]) => (
          <ul className="list">
            {agents.map((a) => (
              <li key={a.id} className="row">
                <strong>{a.name}</strong> {a.description}
                <button
                  className="btn sm quiet danger-text"
                  onClick={() =>
                    void run(async () => {
                      await client.deleteAgent(a.id);
                      refresh();
                    })
                  }
                >
                  Delete {a.name}
                </button>
                <Grants client={client} agent={a} onError={setError} />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </>
  );
}
