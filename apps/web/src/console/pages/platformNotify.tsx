// Notification center: inbox, channels and rules. Sample data; nothing is sent.
import { Tabs as KitTabs, TabsList, TabsTrigger } from "@locksmith-hq/ui/tabs";
import { Checkbox } from "@locksmith-hq/ui/checkbox";
import { Card } from "@locksmith-hq/ui/card";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/ui/toggle-group";
import { Button } from "@locksmith-hq/ui/button";
import { Dropdown, Option } from "../../Dropdown";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
import { useState } from "react";
import { Crumbs, Empty, Head, Icon, NOW, ago, plural, type IconName, type PageProps, TabLoader } from "../kit";
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
import { paid } from "../paid";
import { GateBadge, Locked, useLocked } from "../plans";

export const PRODUCT_ICON: Record<string, IconName> = {
  "Agent Gateway": "relay",
  "Secret Management": "key",
  Security: "search",
  Certificates: "doc",
  "Access Broker": "db",
  Organization: "sessions",
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
const needsAction = (n: Notice) => n.level !== "info";
const dayOf = (at: number) => {
  const d = Math.floor((NOW - at) / 86400);
  return d < 1 ? "Today" : d < 2 ? "Yesterday" : d < 7 ? "Earlier this week" : "Older";
};

export function Tabs({ at, unread }: { at: string; unread: number }) {
  return (
    <>
      <KitTabs value={at || "index"} className="mb-5">
        <TabsList variant="line" aria-label="Notification center">
          {TABS.map(([k, label]) => (
            <TabsTrigger key={k} value={k || "index"} asChild>
              <a href={k ? `#/notifications/${k}` : "#/notifications"}>
                {label}
                {k === "" && unread > 0 && <span className="n">{unread} unread</span>}
                {k === "channels" && <GateBadge feature="channels" />}
              </a>
            </TabsTrigger>
          ))}
        </TabsList>
      </KitTabs>
      <TabLoader />
    </>
  );
}

export function Notifications({ sub, say }: PageProps) {
  const noChannels = useLocked("channels");
  const Channels = paid.pages["notifications/channels"];
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
          {at === "channels" &&
            (Channels && !noChannels ? (
              <Channels say={say} unread={unread} />
            ) : (
              <>
                <Head title="Notifications" sub="Where notifications can go. The in-app inbox is always on." />
                <Tabs at="channels" unread={unread} />
                <Locked feature="channels" />
              </>
            ))}
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
            <Button asChild size="sm" variant={needsAction(x) ? "default" : "outline"}>
              <a href={x.href}>{meta.action}</a>
            </Button>
          )}
          <Button variant="ghost" size="sm" type="button" onClick={() => setRead(x.id, !x.read)}>
            {x.read ? "Mark unread" : "Mark read"}
          </Button>
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
        <Button
          type="button"
          disabled={unread === 0}
          onClick={() => {
            setNotices((ns) => ns.map((x) => ({ ...x, read: true })));
            say("Marked everything read");
          }}
        >
          Mark all read
        </Button>
      </Head>
      <Tabs at="" unread={unread} />
      <div className="toolbar">
        <ToggleGroup type="single" value={String(view)} aria-label="Show">
          {(
            [
              ["all", "All", notices.length],
              ["unread", "Unread", unread],
              ["action", "Needs action", notices.filter(needsAction).length],
            ] as const
          ).map(([k, label, count]) => (
            <ToggleGroupItem key={k} size="sm" value={String(k)} onClick={() => setView(k)}>
              {label}
              <span className="n">{count}</span>
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
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
          <Button asChild>
            <a href={x.href}>{meta.action}</a>
          </Button>
        )}
      </Head>
      <Card className="panel">
        <h2>Who was told</h2>
        <p className="muted">
          {failed
            ? `${plural(failed, "delivery")} failed. The inbox copy still arrived.`
            : "Every delivery went through."}
        </p>
        <div className="table-wrap pf-scroll pf-gap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Channel</TableHead>
                <TableHead>Sent to</TableHead>
                <TableHead>Result</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {meta.sent.map((s) => (
                <TableRow key={s.channel}>
                  <TableCell className="strong">{CHANNEL_NAME[s.channel]}</TableCell>
                  <TableCell className="wrap">{s.to}</TableCell>
                  <TableCell>
                    <span className="pf-res" data-ok={s.ok}>
                      {s.ok ? "Delivered" : `Failed: ${s.note}`}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <p className="hint">
          Who is told, and where, is set by <a href="#/notifications/rules">the rules</a>.
        </p>
      </Card>
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
        <Table className="pf-matrix">
          <TableHeader>
            <TableRow>
              <TableHead>Event</TableHead>
              <TableHead>Who is told</TableHead>
              {cols.map((c) => (
                <TableHead key={c.id} className="pf-c">
                  {CHANNEL_NAME[c.id]}
                  <small>
                    {c.status === "attention" ? "Needs attention" : c.id === "inapp" ? "Always on" : "Connected"}
                  </small>
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
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
          </TableBody>
        </Table>
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
        <TableRow className="area">
          <TableHead colSpan={cols.length + 2} scope="colgroup">
            {product}
          </TableHead>
        </TableRow>
      )}
      <TableRow>
        <TableCell>
          <span className="strong">{label}</span>
          <br />
          <span className="muted">{about}</span>
        </TableCell>
        <TableCell>
          <Dropdown
            aria-label={`Who is told about ${label}`}
            value={rule?.who ?? "Owners and admins"}
            onChange={(x) => setWho(id, x as Who)}
          >
            {WHO.map((w) => (
              <Option key={w}>{w}</Option>
            ))}
          </Dropdown>
        </TableCell>
        {cols.map((c) => {
          const locked = c.id === "inapp";
          return (
            <TableCell key={c.id} className="pf-c">
              <Checkbox
                checked={locked || (rule?.on.includes(c.id) ?? false)}
                disabled={locked}
                aria-label={`${label}: ${CHANNEL_NAME[c.id]}${locked ? " (always on)" : ""}`}
                title={locked ? "Always on" : undefined}
                onCheckedChange={() => toggle(id, c.id)}
              />
            </TableCell>
          );
        })}
      </TableRow>
    </>
  );
}
