import { useQuery } from "@tanstack/react-query";
import { Head } from "@locksmith/ui";
import type { BindingView } from "@locksmith/api-types";
import { QueryState } from "../QueryState";
import type { BindingsClient } from "../api/bindings";

const list = (xs: string[]) => (xs.length ? xs.join(", ") : "none");

/** Bindings: where each secret may be used, with kind-specific non-secret fields only. */
export function Bindings({ client }: { client: BindingsClient }) {
  const q = useQuery({ queryKey: ["bindings"], queryFn: () => client.listBindings() });
  return (
    <section aria-label="Bindings">
      <Head title="Bindings" />
      <QueryState query={q} empty="No bindings yet.">
        {(items: BindingView[]) => (
          <table className="grid">
            <caption className="sr-only">Bindings</caption>
            <thead><tr><th>Kind</th><th>Target</th><th>Region</th><th>Allowed actions</th><th>Vend</th><th>Max duration</th></tr></thead>
            <tbody>
              {items.map((b) => b.kind === "aws" ? (
                <tr key={b.secret_id}>
                  <td>AWS</td><td>{b.role_arn}</td><td>{b.region}</td><td>{list(b.allowed_actions)}</td>
                  <td>{b.vend ? "On" : "Off"}</td><td>{b.max_duration_secs} s</td>
                </tr>
              ) : (
                <tr key={b.secret_id}>
                  <td>HTTP</td><td>{b.origin} ({b.header})</td><td>-</td><td>-</td><td>-</td><td>-</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </QueryState>
    </section>
  );
}
