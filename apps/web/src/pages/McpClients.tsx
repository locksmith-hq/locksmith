import { useEffect, useState } from "react";
import type { Client, McpClient } from "@locksmith/control-plane-client";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");
const layerName = (l: string) => (l === "hub" ? "Hub (people)" : "Gateway (agents)");

export function McpClients({ client }: { client: Client }) {
  const [clients, setClients] = useState<McpClient[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setClients(null); setError(null);
    client.listMcpClients().then((c) => live && setClients(c), (e) => live && setError(errMsg(e)));
    return () => { live = false; };
  }, [client]);

  const revoke = async (c: McpClient) => {
    setError(null);
    try {
      const u = await client.revokeMcpClient(c.id);
      setClients((cur) => cur?.map((x) => (x.id === u.id ? u : x)) ?? cur);
    } catch (e) { setError(errMsg(e)); }
  };

  const label = (c: McpClient) => c.client_name || c.client_id;
  return (
    <section aria-label="Clients">
      <h2>MCP clients</h2>
      {error && <p role="alert">{error}</p>}
      {!clients ? (error ? null : <p>Loading clients…</p>) : clients.length === 0 ? <p>No MCP clients have signed in yet.</p> : (
        <table>
          <thead>
            <tr><th>Client</th><th>Layer</th><th>Principal</th><th>Last seen</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {clients.map((c) => (
              <tr key={c.id}>
                <td>{label(c)}</td><td>{layerName(c.layer)}</td><td>{c.principal}</td><td>{c.last_seen_at}</td>
                <td>{c.revoked_at ? `Revoked ${c.revoked_at}` : "Active"}</td>
                <td>{!c.revoked_at && <button onClick={() => void revoke(c)}>Revoke {label(c)}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
