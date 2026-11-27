import { Card } from "@locksmith-hq/card";
import { Alert, AlertDescription } from "@locksmith-hq/alert";
import { Button } from "@locksmith-hq/button";
import { Input } from "@locksmith-hq/input";
import { PageHeader } from "@locksmith-hq/page-header";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Agent, Client } from "@locksmith/control-plane-client";
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
      <PageHeader title="Agents" />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {secret && (
        <Card role="region" aria-label="Enrollment secret" className="mb-4 gap-3 px-5">
          <p>Enrollment secret for {secret.agent}. It is shown once and cannot be retrieved again.</p>
          <code data-testid="enrollment-secret" className="break-all">
            {secret.value}
          </code>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                void navigator.clipboard
                  ?.writeText(secret.value)
                  .catch(() => setError("Could not copy to the clipboard"))
              }
            >
              Copy
            </Button>
            <Button variant="outline" size="sm" onClick={() => setSecret(null)}>
              Dismiss
            </Button>
          </div>
        </Card>
      )}
      <form
        onSubmit={create}
        aria-label="Create agent"
        className="mb-4 flex flex-wrap items-center gap-2 [&_[data-slot=input]]:w-60"
      >
        <Input aria-label="Agent name" required value={name} onChange={(e) => setName(e.target.value)} />
        <Input aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        <Button type="submit">Create agent</Button>
      </form>
      <QueryState query={q} empty="No agents yet.">
        {(agents: Agent[]) => (
          <ul className="divide-y rounded-md border bg-card">
            {agents.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                <strong>{a.name}</strong> <span className="mr-auto text-muted-foreground">{a.description}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-(--destructive-text)"
                  onClick={() =>
                    void run(async () => {
                      await client.deleteAgent(a.id);
                      refresh();
                    })
                  }
                >
                  Delete {a.name}
                </Button>
                <Grants client={client} agent={a} onError={setError} />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </>
  );
}
