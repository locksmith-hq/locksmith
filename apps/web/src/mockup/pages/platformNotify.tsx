// Notification center: inbox, channels and rules. Sample data; nothing is sent.
import { useState } from "react";
import { connections } from "../data";
import { Crumbs, Empty, Head, Icon, NOW, ago, plural, type IconName, type PageProps } from "../kit";
import {
  CHANNEL_NAME,
  EVENTS,
  META,
  WHO,
  useChannels,
  useNotices,
  useRules,
  type Channel,
  type ChannelId,
  type Notice,
  type NoticeMeta,
  type Rule,
  type Who,
} from "./platform-store";
import "../settings.css";
import "./platform.css";

const PRODUCT_ICON: Record<string, IconName> = {
  "Agent Gateway": "relay",
  "Secret Management": "key",
  Security: "search",
  Certificates: "doc",
  "Access Broker": "db",
  Organization: "sessions",
};
const CHANNEL_ICON: Record<ChannelId, IconName> = {
  inapp: "alert",
  slack: "sessions",
  email: "arrow",
  webhook: "http",
};
const TABS: [string, string][] = [
  ["", "Inbox"],
  ["channels", "Channels"],
  ["rules", "Rules"],
];

const FALLBACK: NoticeMeta = {
  action: "Open",
  sent: [{ channel: "inapp", to: "Everyone signed in", ok: true, note: "Delivered" }],
};
const statusWord = (c: Channel) =>
  c.status === "connected"
    ? "Connected"
    : c.status === "attention"
      ? `Needs attention: ${c.problem ?? "check the connection"}`
      : "Not connected";
const needsAction = (n: Notice) => n.level !== "info";
const dayOf = (at: number) => {
  const d = Math.floor((NOW - at) / 86400);
  return d < 1 ? "Today" : d < 2 ? "Yesterday" : d < 7 ? "Earlier this week" : "Older";
};

function Tabs({ at, unread }: { at: string; unread: number }) {
  return (
    <nav className="tabs" aria-label="Notification center">
      {TABS.map(([k, label]) => (
        <a key={k} href={k ? `#/notifications/${k}` : "#/notifications"} aria-current={at === k ? "page" : undefined}>
          {label}
          {k === "" && unread > 0 && <span className="n">{unread} unread</span>}
        </a>
      ))}
    </nav>
  );
}

export function Notifications({ sub, say }: PageProps) {
  const [notices] = useNotices();
  const unread = notices.filter((x) => !x.read).length;
  const at = !sub ? "" : TABS.some(([k]) => k === sub) ? sub : "detail";
  return (
    <section>
      {at === "detail" ? (
        <Detail id={sub ?? ""} />
      ) : (
        <>
          {at === "" && <Inbox say={say} unread={unread} />}
          {at === "channels" && <Channels say={say} unread={unread} />}
          {at === "rules" && <Rules unread={unread} />}
        </>
      )}
    </section>
  );
}

/* ---------- Inbox ---------- */

function Inbox({ say, unread }: { say: PageProps["say"]; unread: number }) {
  const [notices, setNotices] = useNotices();
  const [view, setView] = useState<"all" | "unread" | "action">("all");
  const shown = notices
    .filter((x) => view === "all" || (view === "unread" ? !x.read : needsAction(x)))
    .sort((a, b) => b.at - a.at);
  const days = [...new Set(shown.map((x) => dayOf(x.at)))];
  const setRead = (id: string, read: boolean) => setNotices((ns) => ns.map((x) => (x.id === id ? { ...x, read } : x)));

  const row = (x: Notice) => {
    const meta = META[x.id] ?? FALLBACK;
    return (
      <li key={x.id} className="row pf-row" data-unread={!x.read}>
        <span className="ic">
          <Icon name={PRODUCT_ICON[x.product] ?? "alert"} />
        </span>
        <div>
          <a className="pf-title" href={`#/notifications/${x.id}`}>
            {x.title}
          </a>
          {!x.read && <span className="pf-flag">Unread</span>}
          {x.level === "urgent" && (
            <span className="pf-flag" data-l="urgent">
              Urgent
            </span>
          )}
          {x.level === "action" && (
            <span className="pf-flag" data-l="action">
              Needs action
            </span>
          )}
          <p>{x.body}</p>
          <p className="pf-when">
            {x.product} · {ago(x.at)}
          </p>
        </div>
        <span className="pf-acts">
          {x.href && (
            <a className={needsAction(x) ? "btn sm primary" : "btn sm"} href={x.href}>
              {meta.action}
            </a>
          )}
          <button type="button" className="btn sm quiet" onClick={() => setRead(x.id, !x.read)}>
            {x.read ? "Mark unread" : "Mark read"}
          </button>
        </span>
      </li>
    );
  };

  return (
    <>
      <Head
        title="Notifications"
        sub="What needs your attention across every product, newest first. Open one to see who else was told."
      >
        <button
          type="button"
          className="btn primary"
          disabled={unread === 0}
          onClick={() => {
            setNotices((ns) => ns.map((x) => ({ ...x, read: true })));
            say("Marked everything read");
          }}
        >
          Mark all read
        </button>
      </Head>
      <Tabs at="" unread={unread} />
      <div className="toolbar">
        <fieldset className="seg inline">
          <legend className="sr-only">Show</legend>
          {(
            [
              ["all", "All", notices.length],
              ["unread", "Unread", unread],
              ["action", "Needs action", notices.filter(needsAction).length],
            ] as const
          ).map(([k, label, count]) => (
            <label key={k}>
              <input type="radio" name="pf-view" checked={view === k} onChange={() => setView(k)} />
              {label}
              <span className="n">{count}</span>
            </label>
          ))}
        </fieldset>
      </div>
      {shown.length === 0 ? (
        <Empty icon="alert">
          <b>{view === "all" ? "No notifications yet." : "Nothing matches this filter."}</b> When an agent is blocked or
          a key needs attention, it shows up here.
        </Empty>
      ) : (
        days.map((d) => (
          <div key={d}>
            <h2 className="pf-day">{d}</h2>
            <ul className="list pf-list">{shown.filter((x) => dayOf(x.at) === d).map(row)}</ul>
          </div>
        ))
      )}
      <p className="hint">
        Rules decide what reaches this inbox and where else it goes: <a href="#/notifications/rules">open the rules</a>.
      </p>
    </>
  );
}

/** One notice and who was told: the place to see that a Slack or webhook delivery failed. */
function Detail({ id }: { id: string }) {
  const [notices] = useNotices();
  const x = notices.find((v) => v.id === id);
  if (!x) {
    return (
      <>
        <Head title="Notification not found" sub="It may have been removed, or the address is wrong." />
        <Empty icon="search">
          <b>No notification with that address.</b> <a href="#/notifications">Back to the inbox</a>.
        </Empty>
      </>
    );
  }
  const meta = META[x.id] ?? FALLBACK;
  const failed = meta.sent.filter((s) => !s.ok).length;
  return (
    <>
      <Crumbs trail={[["Notifications", "#/notifications"], [x.title]]} />
      <Head title={x.title} sub={x.body}>
        {x.href && (
          <a className="btn primary" href={x.href}>
            {meta.action}
          </a>
        )}
      </Head>
      <div className="panel">
        <h2>Who was told</h2>
        <p className="muted">
          {failed
            ? `${plural(failed, "delivery")} failed. The inbox copy still arrived.`
            : "Every delivery went through."}
        </p>
        <div className="table-wrap pf-scroll pf-gap">
          <table className="grid">
            <thead>
              <tr>
                <th>Channel</th>
                <th>Sent to</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {meta.sent.map((s) => (
                <tr key={s.channel}>
                  <td className="strong">{CHANNEL_NAME[s.channel]}</td>
                  <td className="wrap">{s.to}</td>
                  <td>
                    <span className="pf-res" data-ok={s.ok}>
                      {s.ok ? "Delivered" : `Failed: ${s.note}`}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="hint">
          Who is told, and where, is set by <a href="#/notifications/rules">the rules</a>.
        </p>
      </div>
    </>
  );
}

/* ---------- Channels ---------- */

function Channels({ say, unread }: { say: PageProps["say"]; unread: number }) {
  const [chs, setChs] = useChannels();
  const [rules, setRules] = useRules();
  const [form, setForm] = useState<ChannelId | null>(null);
  const [removing, setRemoving] = useState<ChannelId | null>(null);
  const [text, setText] = useState("");
  const [pick, setPick] = useState("");
  const [note, setNote] = useState("");
  const slackConns = connections.filter((c) => c.kind === "Notifications" && c.provider === "Slack");
  const stoppedBy = (id: ChannelId) => EVENTS.filter((e) => rules[e.id]?.on.includes(id));
  const patch = (id: ChannelId, f: Partial<Channel>) =>
    setChs((cs) => cs.map((c) => (c.id === id ? { ...c, ...f } : c)));

  const open = (id: ChannelId) => {
    setForm(id);
    setRemoving(null);
    setText("");
    setPick(slackConns[0]?.name ?? "");
  };
  const connect = (id: ChannelId, target: string) => {
    patch(id, { status: "connected", target, problem: undefined });
    setForm(null);
    say(`Connected ${CHANNEL_NAME[id]}`);
    setNote(`${CHANNEL_NAME[id]} is connected. Tick it for an event in Rules to start sending.`);
  };
  const disconnect = (id: ChannelId) => {
    setRules((r) =>
      Object.fromEntries(Object.entries(r).map(([k, v]) => [k, { ...v, on: v.on.filter((c) => c !== id) }])),
    );
    patch(id, { status: "off", target: "", problem: undefined });
    setRemoving(null);
    say(`Disconnected ${CHANNEL_NAME[id]}`);
    setNote(`${CHANNEL_NAME[id]} is disconnected.`);
  };
  const test = (c: Channel) =>
    setNote(
      c.status === "attention"
        ? `The test to ${CHANNEL_NAME[c.id]} failed: ${c.problem ?? "delivery failed"}.`
        : `The test to ${CHANNEL_NAME[c.id]} was delivered.`,
    );
  const submit = (e: React.FormEvent, c: Channel) => {
    e.preventDefault();
    const v = text.trim();
    if (c.id === "slack") return pick ? connect(c.id, pick) : undefined;
    if (c.id === "webhook" && !/^https:\/\/\S+\.\S+/.test(v))
      return setNote("Enter an address that starts with https://");
    connect(c.id, v);
  };

  const formFor = (c: Channel) => (
    <form className="pf-form" onSubmit={(e) => submit(e, c)} aria-label={`Connect ${CHANNEL_NAME[c.id]}`}>
      {c.id === "slack" &&
        (slackConns.length ? (
          <label className="field">
            Slack connection from Integrations
            <select value={pick} onChange={(e) => setPick(e.target.value)}>
              {slackConns.map((s) => (
                <option key={s.id}>{s.name}</option>
              ))}
            </select>
          </label>
        ) : (
          <p className="muted">
            There is no Slack connection yet. <a href="#/integrations">Add one in Integrations</a>, then come back.
          </p>
        ))}
      {c.id === "email" && (
        <label className="field">
          Shared address
          <input
            type="email"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="security@acme.example"
            autoComplete="off"
            required
          />
        </label>
      )}
      {c.id === "webhook" && (
        <label className="field">
          Webhook address
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="https://hooks.acme.example/locksmith"
            autoComplete="off"
            required
          />
        </label>
      )}
      <div className="pf-btns">
        <button type="submit" className="btn primary" disabled={c.id === "slack" && !pick}>
          Connect {CHANNEL_NAME[c.id]}
        </button>
        <button type="button" className="btn quiet" onClick={() => setForm(null)}>
          Cancel
        </button>
      </div>
    </form>
  );

  const row = (c: Channel) => {
    const stops = stoppedBy(c.id);
    return (
      <li key={c.id} className="row pf-row">
        <span className="ic">
          <Icon name={CHANNEL_ICON[c.id]} />
        </span>
        <div>
          <b>{CHANNEL_NAME[c.id]}</b>{" "}
          <span className="pf-st" data-s={c.status}>
            {statusWord(c)}
          </span>
          <p>
            {c.use}
            {c.target && c.id !== "inapp" && (
              <>
                {" "}
                Goes to <span className="pf-wrap">{c.target}</span>.
              </>
            )}
          </p>
          {form === c.id && formFor(c)}
          {removing === c.id && (
            <p className="alert" role="alert">
              {stops.length
                ? `Disconnecting ${CHANNEL_NAME[c.id]} stops ${plural(stops.length, "rule")} from delivering here: ${stops.map((e) => e.label).join(", ")}.`
                : `No rule uses ${CHANNEL_NAME[c.id]} yet, so nothing stops.`}{" "}
              The inbox is not affected.
              <button type="button" className="btn sm danger" onClick={() => disconnect(c.id)}>
                Disconnect {CHANNEL_NAME[c.id]}
              </button>
              <button type="button" className="btn sm quiet" onClick={() => setRemoving(null)}>
                Keep it
              </button>
            </p>
          )}
        </div>
        <span className="pf-acts">
          {c.status !== "off" && (
            <button type="button" className="btn sm" onClick={() => test(c)}>
              Send test
            </button>
          )}
          {c.id === "inapp" ? (
            <span className="muted small">Always on</span>
          ) : c.status === "off" ? (
            <button type="button" className="btn sm" disabled={form === c.id} onClick={() => open(c.id)}>
              Connect
            </button>
          ) : (
            <>
              {c.status === "attention" && (
                <button type="button" className="btn sm" onClick={() => open(c.id)}>
                  Fix connection
                </button>
              )}
              <button
                type="button"
                className="btn sm quiet danger-text"
                aria-label={`Disconnect ${CHANNEL_NAME[c.id]}`}
                onClick={() => {
                  setRemoving(c.id);
                  setForm(null);
                }}
              >
                Disconnect
              </button>
            </>
          )}
        </span>
      </li>
    );
  };

  return (
    <>
      <Head
        title="Notifications"
        sub="Where notifications can go. Connect a channel here, then choose which events use it in Rules."
      />
      <Tabs at="channels" unread={unread} />
      {note && (
        <p className="pf-note" role="status">
          <Icon name="clock" />
          {note}
        </p>
      )}
      <ul className="list pf-list">{chs.map(row)}</ul>
      <p className="hint">
        Slack uses the connection set up once under <a href="#/integrations">Integrations</a>. A channel that needs
        attention keeps its rules; deliveries to it fail until it is fixed.
      </p>
    </>
  );
}

/* ---------- Rules ---------- */

function Rules({ unread }: { unread: number }) {
  const [chs] = useChannels();
  const [rules, setRules] = useRules();
  const cols = chs.filter((c) => c.status !== "off");
  const toggle = (ev: string, ch: ChannelId) =>
    setRules((r) => {
      const cur = r[ev] ?? { on: [], who: "Owners and admins" as Who };
      return { ...r, [ev]: { ...cur, on: cur.on.includes(ch) ? cur.on.filter((x) => x !== ch) : [...cur.on, ch] } };
    });
  const setWho = (ev: string, who: Who) => setRules((r) => ({ ...r, [ev]: { on: r[ev]?.on ?? [], who } }));
  return (
    <>
      <Head title="Notifications" sub="Which events are sent where, and to whom. Changes apply as you make them." />
      <Tabs at="rules" unread={unread} />
      <div className="table-wrap pf-scroll">
        <table className="grid pf-matrix">
          <thead>
            <tr>
              <th>Event</th>
              <th>Who is told</th>
              {cols.map((c) => (
                <th key={c.id} className="pf-c">
                  {CHANNEL_NAME[c.id]}
                  <small>
                    {c.status === "attention" ? "Needs attention" : c.id === "inapp" ? "Always on" : "Connected"}
                  </small>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {EVENTS.map((e, i) => (
              <RuleRows
                key={e.id}
                id={e.id}
                label={e.label}
                about={e.about}
                product={e.product}
                first={e.product !== EVENTS[i - 1]?.product}
                cols={cols}
                rule={rules[e.id]}
                toggle={toggle}
                setWho={setWho}
              />
            ))}
          </tbody>
        </table>
      </div>
      <p className="hint">
        The in-app inbox always receives everything. A column appears here once its channel is connected under{" "}
        <a href="#/notifications/channels">Channels</a>.
      </p>
    </>
  );
}

function RuleRows({
  id,
  label,
  about,
  product,
  first,
  cols,
  rule,
  toggle,
  setWho,
}: {
  id: string;
  label: string;
  about: string;
  product: string;
  first: boolean;
  cols: Channel[];
  rule: Rule | undefined;
  toggle: (ev: string, ch: ChannelId) => void;
  setWho: (ev: string, who: Who) => void;
}) {
  return (
    <>
      {first && (
        <tr className="area">
          <th colSpan={cols.length + 2} scope="colgroup">
            {product}
          </th>
        </tr>
      )}
      <tr>
        <td>
          <span className="strong">{label}</span>
          <br />
          <span className="muted">{about}</span>
        </td>
        <td>
          <select
            aria-label={`Who is told about ${label}`}
            value={rule?.who ?? "Owners and admins"}
            onChange={(x) => setWho(id, x.target.value as Who)}
          >
            {WHO.map((w) => (
              <option key={w}>{w}</option>
            ))}
          </select>
        </td>
        {cols.map((c) => {
          const locked = c.id === "inapp";
          return (
            <td key={c.id} className="pf-c">
              <input
                type="checkbox"
                checked={locked || (rule?.on.includes(c.id) ?? false)}
                disabled={locked}
                aria-label={`${label}: ${CHANNEL_NAME[c.id]}${locked ? " (always on)" : ""}`}
                title={locked ? "Always on" : undefined}
                onChange={() => toggle(id, c.id)}
              />
            </td>
          );
        })}
      </tr>
    </>
  );
}
