// MCP: how AI tools connect to Locksmith, in three layers with very different risk. Sample data; nothing is served.
import { Fragment, useState } from "react";
import { agents } from "../data";
import { Empty, Head, Icon, Switch, ago, plural, type PageProps } from "../kit";
import {
  APPS,
  KIND_LABEL,
  useAgentAccess,
  useClients,
  useServers,
  useTools,
  type App,
  type Layer,
  type Tool,
} from "./platform-store";
import "../settings.css";
import "./platform.css";

const HUB_URL = "https://mcp.locksmith.example/hub";
const AGENT_URL = "https://mcp.locksmith.example/agent";
const LAYERS: Layer[] = ["hub", "agent", "local"];
const NAME: Record<Layer, string> = { hub: "Hub MCP", agent: "Agent MCP", local: "Local MCP" };
const ADDRESS: Record<Layer, string> = { hub: HUB_URL, agent: AGENT_URL, local: "smith mcp" };
const LEDE: Record<Layer, string> = {
  hub: "Lets a person's AI assistant read and manage Locksmith with that person's own permissions. It never returns a secret value.",
  agent:
    "What a coding agent uses to do its job: use keys through the gateway, run commands through relays, ask for access. It never receives a stored secret value.",
  local:
    "The same agent tools on a developer's own machine, talking to the Locksmith desktop app. No cloud and no network address.",
};
const SIGNIN: Record<Layer, string> = {
  hub: "A person signs in with their Locksmith account in the browser the first time; the assistant then acts with that person's permissions and nothing more.",
  agent:
    "Each agent signs in with the token it was given when it was enrolled. The token names the agent, not a person.",
  local:
    "There is no network sign-in. The command is started on the developer's own machine and talks to the desktop app, which that person has already unlocked.",
};
const OFFING: Record<Layer, string> = {
  hub: "Every assistant using the Hub MCP is disconnected at once. People can still use the console.",
  agent:
    "Every agent loses its Locksmith tools at once. Jobs that reach keys through MCP fail until you turn it back on.",
  local:
    "Desktop apps in this organization refuse local MCP requests, and every developer's agent loses its Locksmith tools.",
};
const TABS: [string, string][] = [
  ["", "Overview"],
  ["hub", "Hub MCP"],
  ["agent", "Agent MCP"],
  ["local", "Local MCP"],
  ["clients", "Clients"],
];
const isLayer = (s: string | undefined): s is Layer => s === "hub" || s === "agent" || s === "local";

function Tabs({ at }: { at: string }) {
  const [clients] = useClients();
  return (
    <nav className="tabs" aria-label="MCP">
      {TABS.map(([k, label]) => (
        <a key={k} href={k ? `#/mcp/${k}` : "#/mcp"} aria-current={at === k ? "page" : undefined}>
          {label}
          {k === "clients" && <span className="n">{clients.length}</span>}
        </a>
      ))}
    </nav>
  );
}

export function Mcp({ sub, say }: PageProps) {
  const at = sub && TABS.some(([k]) => k === sub) ? sub : "";
  return (
    <section>
      {at === "" && <Overview />}
      {isLayer(at) && <LayerTab key={at} layer={at} say={say} />}
      {at === "clients" && <Clients say={say} />}
    </section>
  );
}

/* ---------- Overview ---------- */

function Overview() {
  const [servers] = useServers();
  const [clients] = useClients();
  const [tools] = useTools();
  const onOf = (l: Layer) => {
    const ts = tools.filter((t) => t.layer === l);
    return `${ts.filter((t) => t.on).length} of ${ts.length} tools on`;
  };
  const rows: [string, (l: Layer) => React.ReactNode][] = [
    [
      "Who signs in",
      (l) =>
        ({
          hub: "A person, with their own Locksmith account",
          agent: "An enrolled agent, with the token it was given",
          local: "Nobody separately: the developer on their own machine",
        })[l],
    ],
    [
      "Address",
      (l) =>
        l === "local" ? (
          <>
            On the developer's machine: <code>smith mcp</code>
          </>
        ) : (
          <code className="pf-wrap">{ADDRESS[l]}</code>
        ),
    ],
    ["Clients connected", (l) => plural(clients.filter((c) => c.layer === l).length, "client")],
    [
      "Status",
      (l) => (
        <>
          <span className="pf-st" data-s={servers[l] ? "connected" : "off"}>
            {servers[l] ? "On" : "Off"}
          </span>{" "}
          · {onOf(l)} · <a href={`#/mcp/${l}`}>Manage</a>
        </>
      ),
    ],
  ];
  return (
    <>
      <Head
        title="MCP"
        sub="MCP (the Model Context Protocol) is the standard way an AI tool asks another program to do things; here it is how assistants and agents talk to Locksmith."
      />
      <Tabs at="" />
      <div className="table-wrap pf-scroll">
        <table className="grid pf-compare">
          <thead>
            <tr>
              <th>
                <span className="sr-only">Question</span>
              </th>
              {LAYERS.map((l) => (
                <th key={l} scope="col">
                  <a href={`#/mcp/${l}`}>{NAME[l]}</a>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(([q, f]) => (
              <tr key={q}>
                <th scope="row">{q}</th>
                {LAYERS.map((l) => (
                  <td key={l}>{f(l)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="hint">
        Use the Hub MCP for your own assistant to ask about Locksmith, the Agent MCP for coding agents doing a job, and
        the Local MCP when one developer works on a laptop without the cloud.
      </p>
      <div className="panel pf-rule">
        <h2>
          <Icon name="shield" /> An agent never receives a stored secret value
        </h2>
        <p>
          Through the Agent MCP and the Local MCP, an agent gets the <b>result</b> of using a key, such as an API
          response or a command's output, and never the key itself. The one exception is{" "}
          <b>issue a short-lived credential</b>: a dynamic secret that lives minutes and works for one job. It is one
          switch on the Agent MCP and the Local MCP, off by default. See <a href="#/mcp/agent">Agent MCP</a>.
        </p>
      </div>
    </>
  );
}

/* ---------- One layer ---------- */

function LayerTab({ layer, say }: { layer: Layer; say: PageProps["say"] }) {
  const [servers, setServers] = useServers();
  const [tools, setTools] = useTools();
  const [clients, setClients] = useClients();
  const [ask, setAsk] = useState<string | null>(null);
  const [offAsk, setOffAsk] = useState(false);
  const mine = tools.filter((t) => t.layer === layer);
  const live = clients.filter((c) => c.layer === layer).length;
  const on = servers[layer];
  const setTool = (id: string, v: boolean) => setTools((ts) => ts.map((t) => (t.id === id ? { ...t, on: v } : t)));
  const flip = (t: Tool, v: boolean) => {
    if (v && (t.kind === "change" || t.kind === "credential")) setAsk(t.id);
    else {
      setTool(t.id, v);
      setAsk(null);
    }
  };
  const turnOff = () => {
    setServers((s) => ({ ...s, [layer]: false }));
    setClients((cs) => cs.filter((c) => c.layer !== layer));
    setOffAsk(false);
    say(`${NAME[layer]} is off`);
  };
  return (
    <>
      <Head title={NAME[layer]} sub={LEDE[layer]} />
      <Tabs at={layer} />

      <div className="panel pf-block">
        <h2>Server</h2>
        <div className="set-row">
          <div>
            <b>{layer === "local" ? "Command" : "Address"}</b>
            <p className="pf-wrap">
              <code>{ADDRESS[layer]}</code>
              {layer === "local"
                ? " starts on the developer's machine and talks to the desktop app."
                : " Clients connect here over HTTPS."}
            </p>
          </div>
        </div>
        <div className="set-row">
          <div>
            <b>How sign-in works</b>
            <p>{SIGNIN[layer]}</p>
          </div>
        </div>
        <div className="set-row">
          <div>
            <b>
              {NAME[layer]} is {on ? "on" : "off"}
            </b>
            <p>
              {on
                ? `Turning it off: ${OFFING[layer]}`
                : "Nothing can connect. Tool settings below are kept. Clients have to connect again after you turn it on."}
            </p>
          </div>
          <div className="set-ctl">
            <Switch
              label={`${NAME[layer]} server`}
              checked={on}
              onChange={(v) => (v ? setServers((s) => ({ ...s, [layer]: true })) : setOffAsk(true))}
            />
          </div>
        </div>
        {offAsk && (
          <p className="alert" role="alert">
            This disconnects {plural(live, "client")} now. {OFFING[layer]}
            <button type="button" className="btn sm danger" onClick={turnOff}>
              Turn off {NAME[layer]}
            </button>
            <button type="button" className="btn sm quiet" onClick={() => setOffAsk(false)}>
              Keep it on
            </button>
          </p>
        )}
      </div>

      <h2 className="pf-h">
        Tools{" "}
        <span className="n">
          {mine.filter((t) => t.on).length} of {mine.length} on
        </span>
      </h2>
      {layer !== "hub" && (
        <p className="pf-lead">
          Every tool here uses a key on the agent's behalf; none returns a stored value. <b>{KIND_LABEL.act}</b> means
          the gateway uses the key for the agent, and only where a grant and a policy allow it.{" "}
          <b>{KIND_LABEL.credential}</b> is the only kind that puts a credential in the agent's hands.
        </p>
      )}
      {layer === "hub" && (
        <p className="pf-lead">
          These run with the signed-in person's permissions. Tools that change things are off by default.
        </p>
      )}
      <div className="table-wrap pf-scroll" data-dim={!on}>
        <table className="grid pf-tools">
          <thead>
            <tr>
              <th>Tool</th>
              <th>What it does</th>
              <th>Type</th>
              <th>On</th>
            </tr>
          </thead>
          <tbody>
            {mine.map((t) => (
              <Fragment key={t.id}>
                <tr data-risk={t.kind === "credential" ? "credential" : undefined}>
                  <td>
                    <code>{t.name}</code>
                  </td>
                  <td className="wrap">{t.about}</td>
                  <td>
                    <span className="pf-kind" data-k={t.kind}>
                      {KIND_LABEL[t.kind]}
                    </span>
                  </td>
                  <td>
                    <Switch label={t.name} checked={t.on} onChange={(v) => flip(t, v)} />
                  </td>
                </tr>
                {ask === t.id && (
                  <tr className="detail">
                    <td colSpan={4}>
                      <p className="alert" role="alert">
                        <span>
                          <b>Turn on {t.name}?</b> {t.risk}
                        </span>
                        <button
                          type="button"
                          className="btn sm danger"
                          onClick={() => {
                            setTool(t.id, true);
                            setAsk(null);
                          }}
                        >
                          Turn on {t.name}
                        </button>
                        <button type="button" className="btn sm quiet" onClick={() => setAsk(null)}>
                          Keep it off
                        </button>
                      </p>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      {!on && <p className="hint">The server is off, so no client can call any of these.</p>}

      {layer === "agent" && <AgentTable />}
      <Connect layer={layer} />
    </>
  );
}

function AgentTable() {
  const [access, setAccess] = useAgentAccess();
  return (
    <>
      <h2 className="pf-h">
        Agents <span className="n">{agents.length}</span>
      </h2>
      <p className="pf-lead">
        Which enrolled agents may connect to the Agent MCP. An agent that may not connect gets no Locksmith tools at
        all.
      </p>
      <div className="table-wrap pf-scroll">
        <table className="grid">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Machine</th>
              <th>May connect</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.name}>
                <td>
                  <span className="strong">{a.name}</span>
                  <br />
                  <span className="muted">{a.description}</span>
                </td>
                <td className="mono">{a.machine}</td>
                <td>
                  <Switch
                    label={`${a.name} may connect`}
                    checked={access[a.name] ?? false}
                    onChange={(v) => setAccess((s) => ({ ...s, [a.name]: v }))}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ---------- Connect a client ---------- */

function snippet(layer: Layer, app: App): { text: string; note: string } {
  const url = ADDRESS[layer];
  const n = layer === "hub" ? "locksmith-hub" : "locksmith";
  const TOKEN = "YOUR_AGENT_TOKEN";
  if (layer === "local") {
    switch (app) {
      case "Claude Code":
        return {
          text: "claude mcp add locksmith -- smith mcp",
          note: "Run it in the project folder. The desktop app must be open and unlocked.",
        };
      case "Codex":
        return {
          text: `[mcp_servers.locksmith]\ncommand = "smith"\nargs = ["mcp"]`,
          note: "Add to ~/.codex/config.toml.",
        };
      case "Other":
        return {
          text: "command: smith\nargs: mcp\ntransport: stdio",
          note: "Any client that can start a command over stdio can use it.",
        };
      default:
        return {
          text: JSON.stringify({ mcpServers: { locksmith: { command: "smith", args: ["mcp"] } } }, null, 2),
          note: app === "Cursor" ? "Add to .cursor/mcp.json." : "Add to ~/.gemini/settings.json.",
        };
    }
  }
  switch (app) {
    case "Claude Code":
      return layer === "hub"
        ? {
            text: `claude mcp add --transport http ${n} ${url}`,
            note: "Then run /mcp inside Claude Code and sign in with your Locksmith account.",
          }
        : {
            text: `claude mcp add --transport http ${n} ${url} \\\n  --header "Authorization: Bearer ${TOKEN}"`,
            note: "Run it on the agent's machine.",
          };
    case "Codex":
      return {
        text: `[mcp_servers.${n}]\nurl = "${url}"\nbearer_token_env_var = "LOCKSMITH_MCP_TOKEN"\n\n# export LOCKSMITH_MCP_TOKEN=${TOKEN}`,
        note: "Add to ~/.codex/config.toml.",
      };
    case "Gemini CLI":
      return {
        text: JSON.stringify(
          { mcpServers: { [n]: { httpUrl: url, headers: { Authorization: `Bearer ${TOKEN}` } } } },
          null,
          2,
        ),
        note: "Add to ~/.gemini/settings.json.",
      };
    case "Cursor":
      return {
        text: JSON.stringify({ mcpServers: { [n]: { url, headers: { Authorization: `Bearer ${TOKEN}` } } } }, null, 2),
        note: "Add to .cursor/mcp.json.",
      };
    default:
      return {
        text: `url: ${url}\ntransport: streamable HTTP\nheader: Authorization: Bearer ${TOKEN}`,
        note: "Any client that speaks MCP over HTTP can use it.",
      };
  }
}

function Connect({ layer }: { layer: Layer }) {
  const [app, setApp] = useState<App>("Claude Code");
  const [copied, setCopied] = useState<"" | "ok" | "fail">("");
  const s = snippet(layer, app);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(s.text);
      setCopied("ok");
    } catch {
      setCopied("fail");
    }
  };
  return (
    <div className="panel pf-block pf-top">
      <h2>Connect a client</h2>
      <p className="muted">
        {layer === "local"
          ? "Nothing to sign in to: the client starts the command itself."
          : layer === "hub"
            ? "Add the Hub MCP to your assistant, then sign in as yourself."
            : "Add this on the agent's machine. The token is the one given when the agent was enrolled."}
      </p>
      <label className="field pf-client">
        Client
        <select
          value={app}
          onChange={(e) => {
            setApp(e.target.value as App);
            setCopied("");
          }}
        >
          {APPS.map((a) => (
            <option key={a}>{a}</option>
          ))}
        </select>
      </label>
      <p className="pf-when">{s.note}</p>
      <pre className="pf-code" tabIndex={0} aria-label={`Setup for ${app}`}>
        <code>{s.text}</code>
      </pre>
      <div className="pf-btns">
        <button type="button" className="btn sm" onClick={copy}>
          {copied === "ok" ? "Copied" : "Copy"}
        </button>
        <span role="status" className="pf-when">
          {copied === "ok"
            ? "Copied to your clipboard."
            : copied === "fail"
              ? "Could not copy here. Select the text and copy it yourself."
              : ""}
        </span>
      </div>
      {layer !== "local" && (
        <p className="hint">
          <code>YOUR_AGENT_TOKEN</code> is a placeholder, not a token. A real token is shown once, when it is created,
          and cannot be shown again.
        </p>
      )}
    </div>
  );
}

/* ---------- Clients ---------- */

function Clients({ say }: { say: PageProps["say"] }) {
  const [clients, setClients] = useClients();
  const [note, setNote] = useState("");
  const drop = (id: string) => {
    const c = clients.find((x) => x.id === id);
    if (!c) return;
    setClients((cs) => cs.filter((x) => x.id !== id));
    say(`Disconnected ${c.app} on ${c.host}`);
    setNote(
      `${c.app} on ${c.host} is disconnected. Its next call fails with "session ended" and it has to sign in again.`,
    );
  };
  return (
    <>
      <Head
        title="MCP clients"
        sub="Every AI tool connected to Locksmith right now, across the three layers. Disconnecting one ends it at once."
      />
      <Tabs at="clients" />
      {note && (
        <p className="pf-note" role="status">
          <Icon name="clock" />
          {note}
        </p>
      )}
      {clients.length === 0 ? (
        <Empty icon="s_terminal">
          <b>No clients connected.</b> Add one from the <a href="#/mcp/hub">Hub</a>, <a href="#/mcp/agent">Agent</a> or{" "}
          <a href="#/mcp/local">Local</a> tab.
        </Empty>
      ) : (
        <div className="table-wrap pf-scroll">
          <table className="grid">
            <thead>
              <tr>
                <th>Client</th>
                <th>Layer</th>
                <th>Signed in as</th>
                <th>Last call</th>
                <th>
                  <span className="sr-only">Disconnect</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {clients.map((c) => (
                <tr key={c.id}>
                  <td>
                    <span className="strong">{c.app}</span> <span className="muted">on {c.host}</span>
                  </td>
                  <td>{NAME[c.layer]}</td>
                  <td>{c.as}</td>
                  <td>{ago(c.last)}</td>
                  <td className="num">
                    <button
                      type="button"
                      className="btn sm quiet danger-text"
                      aria-label={`Disconnect ${c.app} on ${c.host} (${NAME[c.layer]})`}
                      onClick={() => drop(c.id)}
                    >
                      Disconnect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
