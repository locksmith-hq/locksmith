import { Label } from "@locksmith-hq/ui/label";
import { Switch } from "@locksmith-hq/ui/switch";
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { PageHeader } from "@locksmith-hq/ui/page-header";
import { useEffect, useState } from "react";
import type { Client, McpToolSetting } from "@locksmith/control-plane-client";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");
const layerName = (l: string) => (l === "hub" ? "Hub (people)" : "Gateway (agents)");

export function McpTools({ client }: { client: Client }) {
  const [tools, setTools] = useState<McpToolSetting[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setTools(null);
    setError(null);
    client.listMcpTools().then(
      (t) => live && setTools(t),
      (e) => live && setError(errMsg(e)),
    );
    return () => {
      live = false;
    };
  }, [client]);

  const toggle = async (t: McpToolSetting, enabled: boolean) => {
    setError(null);
    try {
      const u = await client.setMcpTool(t.layer, t.tool, enabled);
      setTools((cur) => cur?.map((x) => (x.layer === u.layer && x.tool === u.tool ? u : x)) ?? cur);
    } catch (e) {
      setError(errMsg(e));
    }
  };

  return (
    <section aria-label="Tools">
      <PageHeader title="MCP tools" />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {!tools ? (
        error ? null : (
          <p>Loading tools…</p>
        )
      ) : tools.length === 0 ? (
        <p>No MCP tools.</p>
      ) : (
        (["hub", "agent"] as const).map((layer) => {
          const rows = tools.filter((t) => t.layer === layer);
          if (rows.length === 0) return null;
          return (
            <div key={layer} aria-label={`${layerName(layer)} tools`}>
              <h3 className="mt-4 mb-2 text-base font-semibold">{layerName(layer)}</h3>
              <ul className="divide-y rounded-md border bg-card">
                {rows.map((t) => (
                  <li key={t.tool} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                    <Label>
                      <Switch
                        aria-label={`${t.tool} (${layer})`}
                        checked={t.enabled}
                        onCheckedChange={(on) => void toggle(t, on)}
                      />
                      <strong>{t.tool}</strong>
                    </Label>{" "}
                    {t.description}{" "}
                    <em className="text-muted-foreground">
                      {t.default_enabled ? "on by default" : "off by default"}
                      {t.overridden ? ", changed" : ""}
                    </em>
                  </li>
                ))}
              </ul>
            </div>
          );
        })
      )}
    </section>
  );
}
