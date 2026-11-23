import { useQuery } from "@tanstack/react-query";
import { Head } from "@locksmith/ui";
import { bindingDetails, type BindingSummary, type Client } from "@locksmith/control-plane-client";
import { QueryState } from "../QueryState";

const KIND: Record<string, string> = { http: "HTTP", git: "Git", pg: "Postgres", aws: "AWS" };

/** Bindings page: what the gateway can reach, non-secret fields only (never a password or template). */
export function Bindings({ client }: { client: Client }) {
  const q = useQuery({ queryKey: ["bindings"], queryFn: () => client.listBindings() });
  return (
    <section aria-label="Bindings">
      <Head title="Bindings" />
      <QueryState query={q} empty="The gateway has not published any bindings yet.">
        {(bindings: BindingSummary[]) => (
          <table className="grid">
            <thead><tr><th>Name</th><th>Kind</th><th>Details</th></tr></thead>
            <tbody>
              {bindings.map((b) => (
                <tr key={`${b.kind}:${b.name}`}>
                  <td>{b.name}</td>
                  <td>{KIND[b.kind] ?? b.kind}</td>
                  <td>{bindingDetails(b).map(([l, v]) => `${l}: ${v}`).join(" · ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </QueryState>
    </section>
  );
}
