import { useEffect, useState } from "react";
import { Head } from "@locksmith/ui";
import type { Client, McpToolSetting } from "@locksmith/control-plane-client";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");
const layerName = (l: string) => (l === "hub" ? "Hub (people)" : "Gateway (agents)");

export function McpTools({ client }: { client: Client }) {
  const [tools, setTools] = useState<McpToolSetting[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setTools(null); setError(null);
    client.listMcpTools().then((t) => live && setTools(t), (e) => live && setError(errMsg(e)));
    return () => { live = false; };
  }, [client]);

  const toggle = async (t: McpToolSetting, enabled: boolean) => {
    setError(null);
    try {
      const u = await client.setMcpTool(t.layer, t.tool, enabled);
      setTools((cur) => cur?.map((x) => (x.layer === u.layer && x.tool === u.tool ? u : x)) ?? cur);
    } catch (e) { setError(errMsg(e)); }
  };

  return (
    <section aria-label="Tools">
      <Head title="MCP tools" />
      {error && <p role="alert" className="state">{error}</p>}
      {!tools ? (error ? null : <p>Loading tools…</p>) : tools.length === 0 ? <p>No MCP tools.</p> : (
        (["hub", "agent"] as const).map((layer) => {
          const rows = tools.filter((t) => t.layer === layer);
          if (rows.length === 0) return null;
          return (
            <div key={layer} aria-label={`${layerName(layer)} tools`}>
              <h3>{layerName(layer)}</h3>
              <ul className="list">
                {rows.map((t) => (
                  <li key={t.tool} className="row">
                    <label>
                      <input
                        type="checkbox"
                        className="switch"
                        role="switch"
                        aria-label={`${t.tool} (${layer})`}
                        checked={t.enabled}
                        onChange={(e) => void toggle(t, e.target.checked)}
                      />{" "}
                      <strong>{t.tool}</strong>
                    </label>{" "}
                    {t.description} <em>{t.default_enabled ? "on by default" : "off by default"}{t.overridden ? ", changed" : ""}</em>
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
