import { Alert, AlertDescription } from "@locksmith-hq/alert";
import { Button } from "@locksmith-hq/button";
import { Input } from "@locksmith-hq/input";
import { PageHeader } from "@locksmith-hq/page-header";
import { useState } from "react";
import type { Agent, AgentGrant, Client } from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";
import { useQuery } from "@tanstack/react-query";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

export function Grants({ client, agent, onError }: { client: Client; agent: Agent; onError: (m: string) => void }) {
  const [secretId, setSecretId] = useState("");
  const [expires, setExpires] = useState("");

  const q = useQuery({ queryKey: ["grants", agent.id], queryFn: () => client.listGrants(agent.id) });
  const refresh = () => void q.refetch();

  const act = (f: () => Promise<unknown>) => f().then(refresh, (e) => onError(errMsg(e)));

  return (
    <div aria-label={`Grants for ${agent.name}`} className="flex w-full flex-col gap-2">
      <QueryState query={q} empty="No grants yet.">
        {(grants: AgentGrant[]) => (
          <ul className="flex w-full flex-col gap-1">
            {grants.map((g) => (
              <li key={g.id} className="flex flex-wrap items-center gap-2 text-muted-foreground">
                {g.secret_name} ({g.mode}) {g.expires_at ? `expires ${g.expires_at}` : "no expiry"}
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-(--destructive-text)"
                  onClick={() => void act(() => client.revokeGrant(agent.id, g.id))}
                >
                  Revoke {g.secret_name}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </QueryState>
      <form
        className="flex flex-wrap items-center gap-2 [&_[data-slot=input]]:w-60"
        onSubmit={(e) => {
          e.preventDefault();
          void act(async () => {
            await client.createGrant(agent.id, {
              secret_id: secretId,
              mode: "relay",
              expires_at: expires ? new Date(expires).toISOString() : null,
            });
            setSecretId("");
            setExpires("");
          });
        }}
      >
        <Input
          aria-label={`Secret id for ${agent.name}`}
          required
          value={secretId}
          onChange={(e) => setSecretId(e.target.value.trim())}
        />
        <Input
          aria-label={`Expiry for ${agent.name}`}
          type="datetime-local"
          value={expires}
          onChange={(e) => setExpires(e.target.value)}
        />
        <Button size="sm" type="submit">
          Grant {agent.name}
        </Button>
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
      <PageHeader title="Grants" />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <QueryState query={q} empty="No agents yet, so no grants.">
        {(agents: Agent[]) => (
          <ul className="divide-y rounded-md border bg-card">
            {agents.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                <strong>{a.name}</strong>
                <Grants client={client} agent={a} onError={setError} />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </section>
  );
}
