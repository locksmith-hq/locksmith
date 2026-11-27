import { Alert, AlertDescription } from "@locksmith-hq/alert";
import { Button } from "@locksmith-hq/button";
import { PageHeader } from "@locksmith-hq/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/table";
import { useEffect, useState } from "react";
import type { Client, McpClient } from "@locksmith/control-plane-client";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");
const layerName = (l: string) => (l === "hub" ? "Hub (people)" : "Gateway (agents)");

export function McpClients({ client }: { client: Client }) {
  const [clients, setClients] = useState<McpClient[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setClients(null);
    setError(null);
    client.listMcpClients().then(
      (c) => live && setClients(c),
      (e) => live && setError(errMsg(e)),
    );
    return () => {
      live = false;
    };
  }, [client]);

  const revoke = async (c: McpClient) => {
    setError(null);
    try {
      const u = await client.revokeMcpClient(c.id);
      setClients((cur) => cur?.map((x) => (x.id === u.id ? u : x)) ?? cur);
    } catch (e) {
      setError(errMsg(e));
    }
  };

  const label = (c: McpClient) => c.client_name || c.client_id;
  return (
    <section aria-label="Clients">
      <PageHeader title="MCP clients" />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {!clients ? (
        error ? null : (
          <p>Loading clients…</p>
        )
      ) : clients.length === 0 ? (
        <p>No MCP clients have signed in yet.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Client</TableHead>
              <TableHead>Layer</TableHead>
              <TableHead>Principal</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead>Status</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {clients.map((c) => (
              <TableRow key={c.id}>
                <TableCell>{label(c)}</TableCell>
                <TableCell>{layerName(c.layer)}</TableCell>
                <TableCell>{c.principal}</TableCell>
                <TableCell>{c.last_seen_at}</TableCell>
                <TableCell>{c.revoked_at ? `Revoked ${c.revoked_at}` : "Active"}</TableCell>
                <TableCell>
                  {!c.revoked_at && (
                    <Button variant="destructive" size="sm" onClick={() => void revoke(c)}>
                      Revoke {label(c)}
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  );
}
