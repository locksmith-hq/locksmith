import { Card } from "@locksmith-hq/card";
import { Button } from "@locksmith-hq/button";
import { PageHeader } from "@locksmith-hq/page-header";
import { useState } from "react";
import { useQueries } from "@tanstack/react-query";
import { Link } from "react-router";
import type { Client } from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";

const DISMISS_KEY = "ls-get-started-dismissed";
const readDismissed = () => {
  try {
    return localStorage.getItem(DISMISS_KEY) === "1";
  } catch {
    return false;
  }
};

/** Counts, recent activity and the dismissible "Get started" checklist. Metadata only. */
export function Overview({ client }: { client: Client }) {
  const [projects, agents, audit] = useQueries({
    queries: [
      { queryKey: ["projects"], queryFn: () => client.listProjects() },
      { queryKey: ["agents"], queryFn: () => client.listAgents() },
      { queryKey: ["audit", "recent"], queryFn: () => client.listAuditEvents({ limit: 5 }) },
    ],
  });
  const [dismissed, setDismissed] = useState(readDismissed);
  const dismiss = () => {
    setDismissed(true);
    try {
      localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      /* optional */
    }
  };

  return (
    <>
      <PageHeader title="Overview" />
      <Card role="region" aria-label="Counts" className="mb-4 gap-1 px-5">
        <QueryState query={projects} isEmpty={() => false}>
          {(p) => <p data-testid="count-projects">Projects: {p.length}</p>}
        </QueryState>
        <QueryState query={agents} isEmpty={() => false}>
          {(a) => <p data-testid="count-agents">Agents: {a.length}</p>}
        </QueryState>
      </Card>
      {!dismissed && (
        <Card role="region" aria-label="Get started" className="mb-4 gap-3 px-5">
          <h2 className="text-base font-semibold">Get started</h2>
          <ol className="list-decimal pl-5 [&_a]:underline [&_a]:underline-offset-3">
            <li>
              <Link to="/projects">Create a project</Link>
            </li>
            <li>
              <Link to="/secrets">Add a secret</Link>
            </li>
            <li>
              <Link to="/agents">Register an agent</Link>
            </li>
          </ol>
          <Button variant="outline" size="sm" className="self-start" onClick={dismiss}>
            Dismiss
          </Button>
        </Card>
      )}
      <Card role="region" aria-label="Recent activity" className="gap-3 px-5">
        <h2 className="text-base font-semibold">Recent activity</h2>
        <QueryState query={audit} isEmpty={(d) => d.items.length === 0} empty="No activity yet.">
          {(d) => (
            <ul>
              {d.items.map((e) => (
                <li key={e.id}>
                  {e.kind} ({e.outcome})
                </li>
              ))}
            </ul>
          )}
        </QueryState>
      </Card>
    </>
  );
}
