import { PageHeader } from "@locksmith-hq/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
import { useQuery } from "@tanstack/react-query";
import { bindingDetails, type BindingSummary, type Client } from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";

const KIND: Record<string, string> = { http: "HTTP", git: "Git", pg: "Postgres", aws: "AWS", mcp: "MCP" };

/** Bindings page: what the gateway can reach, non-secret fields only (never a password or template). */
export function Bindings({ client }: { client: Client }) {
  const q = useQuery({ queryKey: ["bindings"], queryFn: () => client.listBindings() });
  return (
    <section aria-label="Bindings">
      <PageHeader title="Bindings" />
      <QueryState query={q} empty="The gateway has not published any bindings yet.">
        {(bindings: BindingSummary[]) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {bindings.map((b) => (
                <TableRow key={`${b.kind}:${b.name}`}>
                  <TableCell>{b.name}</TableCell>
                  <TableCell>{KIND[b.kind] ?? b.kind}</TableCell>
                  <TableCell>
                    {bindingDetails(b)
                      .map(([l, v]) => `${l}: ${v}`)
                      .join(" · ")}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </QueryState>
    </section>
  );
}
