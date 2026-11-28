import { Wordmark } from "@locksmith-hq/ui/wordmark";
import {
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
} from "@locksmith-hq/ui/sidebar";
import { Popover, PopoverContent, PopoverTrigger } from "@locksmith-hq/ui/popover";
import { Tabs, TabsList, TabsTrigger } from "@locksmith-hq/ui/tabs";
import { Badge } from "@locksmith-hq/ui/badge";
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Label } from "@locksmith-hq/ui/label";
import { Card } from "@locksmith-hq/ui/card";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/ui/toggle-group";
import { Button } from "@locksmith-hq/ui/button";
import { Input } from "@locksmith-hq/ui/input";
import { Dropdown, Option } from "../Dropdown";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
import { Fragment, useContext, useEffect, useLayoutEffect, useState } from "react";
import { Bell } from "lucide-react";
import { Icon, Logo, Switch, TabBusy, TabLoader, type IconName } from "./kit";
import { Loader as KitLoader } from "@locksmith-hq/ui/loader";
import * as seed from "./data";
import { paid } from "./paid";
import { EnvEditor } from "./EnvEditor";
import { Environments } from "./Environments";
import { PlanAndBilling } from "./PlanAndBilling";
import { Settings } from "./Settings";
import { WorkspaceIcon } from "./WorkspaceIcon";
import { Upgrade } from "./Upgrade";
import { pageFor } from "./pages";
import { useSecrets } from "./pages/gateway-data";
import { useNotices } from "./pages/platform-store";
import {
  GateBadge,
  Locked,
  PlanContext,
  gateOf,
  lacks,
  planOf as limitsOf,
  useLocked,
  bestPlan,
  workspaceCap,
  type PlanId,
} from "./plans";
import { PRODUCT_ICON } from "./pages/platformNotify";
import "./settings.css";
import { NOW } from "./kit";
import { type Agent, type Secret, type Session } from "./data";

const pad = (n: number) => String(n).padStart(2, "0");
const clock = (ts: number) => {
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
};
const plural = (n: number, w: string) => `${n} ${n === 1 ? w : `${w}s`}`;
const ago = (ts: number | null) => {
  if (ts === null) return "never";
  const s = NOW - ts;
  return s < 60
    ? "just now"
    : s < 3600
      ? `${Math.floor(s / 60)}m ago`
      : s < 86400
        ? `${Math.floor(s / 3600)}h ago`
        : `${Math.floor(s / 86400)}d ago`;
};
const left = (s: number) => (s < 60 ? `${s}s` : `${Math.floor(s / 60)}m`);
const until = (ts: number | null) =>
  ts === null
    ? "no expiry"
    : ts - NOW < 86400
      ? `expires in ${Math.ceil((ts - NOW) / 3600)}h`
      : `expires in ${Math.ceil((ts - NOW) / 86400)}d`;
const EXPIRY: [string, number | null][] = [
  ["1 hour", 3600],
  ["8 hours", 8 * 3600],
  ["7 days", 7 * 86400],
  ["No expiry", null],
];

function useRoute() {
  const read = () => location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  const [r, setR] = useState(read);
  useEffect(() => {
    const f = () => setR(read());
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);
  return r;
}

type Appearance = "system" | "light" | "dark";
const APPEARANCE: [Appearance, string, IconName][] = [
  ["system", "System", "monitor"],
  ["light", "Light", "sun"],
  ["dark", "Dark", "moon"],
];
function useAppearance() {
  const [pref, setPref] = useState<Appearance>("system");
  useLayoutEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      document.documentElement.dataset.theme = pref === "system" ? (mq.matches ? "dark" : "light") : pref;
    };
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, [pref]);
  return [pref, setPref] as const;
}

const Chevrons = () => (
  <svg className="i sel" viewBox="0 0 16 16" aria-hidden="true">
    <path d="M5 6.5l3-3 3 3M5 9.5l3 3 3-3" />
  </svg>
);
const Check = () => (
  <svg className="i tick" viewBox="0 0 16 16" aria-hidden="true">
    <path d="M3.5 8.5l3 3 6-7" />
  </svg>
);
// How a notification's level reads in the bell menu: the tint of its icon and, when it needs someone, a word.
const LEVEL = {
  urgent: {
    tile: "bg-(--destructive-weak) text-(--destructive-text)",
    word: "Urgent",
    tone: "text-(--destructive-text)",
  },
  action: { tile: "bg-(--warning-weak) text-(--warning-text)", word: "Needs action", tone: "text-(--warning-text)" },
  info: { tile: "bg-muted text-muted-foreground", word: "", tone: "" },
} as const;

/** The bell in the top bar: the newest notifications at a glance. The full text is one click away, in the center. */
function NoticeMenu() {
  const [notices, setNotices] = useNotices();
  const [open, setOpen] = useState(false);
  const unread = notices.filter((n) => !n.read).length;
  const latest = [...notices].sort((a, b) => b.at - a.at).slice(0, 5);
  const read = (id?: string) => setNotices((ns) => ns.map((n) => (!id || n.id === id ? { ...n, read: true } : n)));
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon-sm"
          className="relative"
          aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
          title="Notifications"
        >
          <Bell />
          {unread > 0 && <span className="bell-n">{unread}</span>}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-88 gap-0 p-0">
        <div className="flex items-center gap-2 px-4 pt-3 pb-2">
          <b className="text-(length:--font-size-lg)">Notifications</b>
          {unread > 0 && <Badge>{unread} new</Badge>}
          <Button variant="link" size="sm" className="ml-auto" disabled={!unread} onClick={() => read()}>
            Mark all read
          </Button>
        </div>
        {latest.length ? (
          <ul className="flex flex-col gap-0.5 px-2 pb-2">
            {latest.map((n) => {
              const level = LEVEL[n.level];
              return (
                <li key={n.id}>
                  <a
                    href={`#/notifications/${n.id}`}
                    className="flex items-center gap-3 rounded-md px-2 py-2 hover:bg-(--state-hover)"
                    onClick={() => {
                      read(n.id);
                      setOpen(false);
                    }}
                  >
                    <span className={`grid size-8 shrink-0 place-items-center rounded-md ${level.tile}`}>
                      <Icon name={PRODUCT_ICON[n.product] ?? "alert"} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className={`block truncate ${n.read ? "text-muted-foreground" : "font-semibold"}`}>
                        {n.title}
                      </span>
                      <span className="block truncate text-(length:--font-size-xs) text-muted-foreground">
                        {level.word && <span className={`font-semibold ${level.tone}`}>{level.word} · </span>}
                        {n.product} · {ago(n.at)}
                      </span>
                    </span>
                    {!n.read && (
                      <span className="size-2 shrink-0 rounded-full bg-brand">
                        <span className="sr-only">Unread</span>
                      </span>
                    )}
                  </a>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="px-4 py-8 text-center text-muted-foreground">You are all caught up.</p>
        )}
        <div className="border-t p-2">
          <Button asChild variant="outline" size="sm" className="w-full">
            <a href="#/notifications" onClick={() => setOpen(false)}>
              View all notifications
            </a>
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

/** A workspace-style selector: a kit Popover on a quiet button. The menu body is given a way to shut it. */
function Selector({
  className,
  title,
  summary,
  children,
}: {
  className?: string;
  title: string;
  summary: React.ReactNode;
  children: (shut: () => void) => React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className={className ? `ws ${className}` : "ws"}>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button variant="ghost" className="org" title={title}>
            {summary}
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" className="ws-menu">
          {children(() => setOpen(false))}
        </PopoverContent>
      </Popover>
    </div>
  );
}

const me = seed.members[0]!;
const AppearanceSeg = ({ value, set }: { value: Appearance; set: (a: Appearance) => void }) => (
  <ToggleGroup type="single" value={String(value)} aria-label="Appearance" className="w-full">
    {APPEARANCE.map(([v, label, icon]) => (
      <ToggleGroupItem key={v} title={`Appearance: ${label}`} size="sm" value={String(v)} onClick={() => set(v)}>
        <Icon name={icon} />
        {label}
      </ToggleGroupItem>
    ))}
  </ToggleGroup>
);

function Account({ appearance, setAppearance }: { appearance: Appearance; setAppearance: (a: Appearance) => void }) {
  return (
    <section>
      <Head title="User settings" sub="These follow you across every workspace you belong to." />
      <Card className="panel form">
        <form className="contents" onSubmit={(e) => e.preventDefault()}>
          <h2>Profile</h2>
          <div className="add">
            <Label className="field">
              Name
              <Input defaultValue={me.name} autoComplete="name" />
            </Label>
            <Label className="field">
              Email
              <Input defaultValue={me.email} readOnly style={{ width: 260 }} />
            </Label>
            <Button variant="outline" type="submit">
              Save
            </Button>
            <span />
          </div>
        </form>
      </Card>
      <Card className="panel form">
        <h2>Appearance</h2>
        <p className="muted">System follows your computer's light or dark setting.</p>
        <div style={{ maxWidth: 280, marginTop: 12 }}>
          <AppearanceSeg value={appearance} set={setAppearance} />
        </div>
      </Card>
      <Card className="panel">
        <h2>Sign out</h2>
        <p className="muted">Ends this browser's session. Agents and their grants are not affected.</p>
        <Button variant="outline" type="button" style={{ marginTop: 12 }}>
          Sign out
        </Button>
      </Card>
    </section>
  );
}

/** A product stops being "Planned" once its first page exists, either built in or in ./pages. */
const built = (p: seed.Product) => !!p.href || !!pageFor(`${p.id}/${seed.spaces[p.id]?.[0]?.[0]}`);
/** The wordmark: the product's own typeface in spaced capitals. */
const Word = () => <Wordmark size={18} />;

/** Loading state: the small mark, its dial turning one notch at a time while the bolts draw in and out (all CSS). */
const Loader = () => <KitLoader className="page-loader" />;
// The pages whose tabs are part of the page: moving between them keeps the heading and the tabs in place.
const TABBED = new Set(["members", "mcp", "notifications"]);

/** Picks who the console is working for: one person, or an organization with members and teams. */
/** Said where a workspace would be added once the plan's limit is reached, with the way past it. */
function WorkspaceLimit({ limit }: { limit: { best: PlanId; cap: number } }) {
  return (
    <p className="muted">
      {limit.best === "Free" ? (
        <>
          The Free plan has {plural(limit.cap, "workspace")}. <a href="#/upgrade">Upgrade</a> for up to{" "}
          {workspaceCap("Team")}.
        </>
      ) : (
        <>
          The {limit.best} plan has up to {limit.cap} workspaces.{" "}
          <a href="mailto:sales@locksmith.example">Talk to us</a> for more.
        </>
      )}
    </p>
  );
}

function Workspace({ at, limit }: { at: number; limit: { best: PlanId; cap: number } | null }) {
  const w = seed.workspaces[at]!;
  return (
    <Selector
      title="Switch workspace"
      summary={
        <>
          <WorkspaceIcon w={w} />
          <span>
            {w.name}
            <small>{w.org ? "Organization" : "Personal"}</small>
          </span>
          <Chevrons />
        </>
      }
    >
      {(shut) => (
        <>
          {seed.workspaces.map((x, i) => (
            <Button
              variant="ghost"
              key={x.name}
              type="button"
              aria-current={i === at || undefined}
              onClick={() => {
                // Each workspace is its own account: switching to another one asks to sign in to it.
                if (i !== at) location.hash = `#/switch/${i}`;
                shut();
              }}
            >
              <WorkspaceIcon w={x} />
              <span>
                {x.name}
                <small>{x.sub}</small>
              </span>
              {i === at && <Check />}
            </Button>
          ))}
          {limit ? (
            <div className="ws-limit">
              <WorkspaceLimit limit={limit} />
            </div>
          ) : (
            <a href="#/welcome" onClick={shut}>
              <span className="av">
                <Icon name="plus" />
              </span>
              New workspace
            </a>
          )}
        </>
      )}
    </Selector>
  );
}

interface Acl {
  viewer: (typeof seed.members)[number];
  isAdmin: boolean;
  pm: typeof seed.projectMembers;
  setPm: React.Dispatch<React.SetStateAction<typeof seed.projectMembers>>;
  roleIn: (projectId: string) => seed.ProjectRole | undefined;
  /** Sample data only: look at the console as another member to see what they would see. */
  preview: (memberIndex: number) => void;
}

interface Db {
  sessions: Session[];
  secrets: Secret[];
  agents: Agent[];
  paused: boolean;
  revoke: (ids: string[]) => void;
  pause: () => void;
  resume: () => void;
  setSecrets: React.Dispatch<React.SetStateAction<Secret[]>>;
  setAgents: React.Dispatch<React.SetStateAction<Agent[]>>;
  say: (note: string) => void;
}

export function Console() {
  const route = useRoute();
  const [appearance, setAppearance] = useAppearance();
  const [sessions, setSessions] = useState(seed.sessions);
  // One copy of secrets and grants for the whole console, shared with the Grants, Policies and Overview pages.
  const [secrets, setSecrets] = useSecrets();
  const [agents, setAgents] = useState(seed.agents);
  const [paused, setPaused] = useState(false);
  const [note, say] = useState("");
  const [at, setAt] = useState(1);
  const ws = seed.workspaces[at]!;
  const live = sessions.filter((s) => s.state === "active");
  const page = route[0] ?? "home";
  // Folded sidebar: an icon-only rail. Remembered per browser; the page works the same if storage is blocked.
  const [brandHover, setBrandHover] = useState(false);
  const [folded, setFolded] = useState(() => {
    try {
      return localStorage.getItem("locksmith.console.folded") === "1";
    } catch {
      return false;
    }
  });
  const fold = () =>
    setFolded((f) => {
      try {
        localStorage.setItem("locksmith.console.folded", f ? "0" : "1");
      } catch {
        /* keep it for this page only */
      }
      return !f;
    });
  // shortcut: the console has no data to wait for, so every page change waits a fixed second to show the loading state (?load=5000 tries a slow one).
  const where = route.join("/");
  // On a page with tabs of its own, a change of tab reloads only what is under the tabs (TabLoader), not the page.
  // Beyond the page itself (the toggle of environments, a filter), a change of route is not a new page either:
  // a project page is secrets/<project>/<tab>, an Agent Gateway page access/<tab>.
  const whole = TABBED.has(route[0] ?? "") ? route[0]! : route.slice(0, route[0] === "access" ? 2 : 3).join("/");
  // A note belongs to the moment it was said: it goes after a few seconds, and when the page changes.
  useEffect(() => say(""), [where]);
  useEffect(() => {
    if (!note) return;
    const t = setTimeout(() => say(""), 4000);
    return () => clearTimeout(t);
  }, [note]);
  const [loaded, setLoaded] = useState({ whole: "", where: "" });
  useEffect(() => {
    const t = setTimeout(
      () => setLoaded({ whole, where }),
      Number(new URLSearchParams(location.search).get("load")) || 1000,
    );
    return () => clearTimeout(t);
  }, [whole, where]);
  // For the phone layout (console.css), where a table's rows stack: each cell carries its column's heading.
  // shortcut: read from the rendered table, so every page's table gets it without changes; move it into the
  // kit's Table if another app needs the same.
  useEffect(() => {
    const main = document.querySelector("main");
    if (!main) return;
    const label = () => {
      for (const table of main.querySelectorAll("table")) {
        const heads = [...table.querySelectorAll("thead th")].map((th) => th.textContent?.trim() ?? "");
        for (const row of table.querySelectorAll("tbody tr"))
          [...row.children].forEach((cell, i) => {
            const text = i > 0 && row.children.length === heads.length ? heads[i] : "";
            if (text && cell.getAttribute("data-label") !== text) cell.setAttribute("data-label", text);
          });
      }
    };
    label();
    const seen = new MutationObserver(label);
    seen.observe(main, { childList: true, subtree: true });
    return () => seen.disconnect();
  }, []);
  const unread = useNotices()[0].filter((n) => !n.read).length;
  const HubPage = pageFor(`hub/${page}`);
  const [planOf, setPlanOf] = useState<PlanId[]>(["Free", "Team"]); // one subscription per workspace
  // The account's best plan sets how many workspaces it may have (Free 1, Team 3, Enterprise by arrangement).
  const best = bestPlan(planOf);
  const wsCap = workspaceCap(best);
  const wsLimit = wsCap !== null && seed.workspaces.length >= wsCap ? { best, cap: wsCap } : null;
  const gate = gateOf(route); // the feature this address needs, when it is not in every plan
  const Billing = paid.billing ?? PlanAndBilling; // the billing module replaces the open page when a build has it
  const [viewerAt, preview] = useState(0);
  const [pm, setPm] = useState(seed.projectMembers);
  const viewer = seed.members[viewerAt]!;
  const isAdmin = viewer.role === "Owner" || viewer.role === "Admin";
  const acl: Acl = {
    viewer,
    isAdmin,
    pm,
    setPm,
    preview,
    roleIn: (pid) => (isAdmin ? "Admin" : pm[pid]?.[viewer.email]),
  };
  // A project the viewer cannot open is treated exactly like one that does not exist.
  const proj = page === "secrets" ? seed.projects.find((p) => p.id === route[1] && acl.roleIn(p.id)) : undefined;
  const own = proj ? secrets.filter((x) => x.project === proj.id) : secrets;
  // A product is its own space with its own sidebar. Secrets needs a project first; planned products only have placeholders.
  const product =
    page === "access"
      ? "access"
      : proj
        ? "secrets"
        : page === "app" && seed.spaces[route[1] ?? ""]
          ? route[1]!
          : undefined;
  // The product's own front door (no project open yet): Projects and Secret sharing.
  const lobby = !product && (page === "secrets" || page === "sharing" || page === "sm");
  const lobbyTab = page === "secrets" ? "projects" : page === "sharing" ? "sharing" : (route[1] ?? "");
  const crumbProduct = product ?? (lobby ? "secrets" : undefined);
  // Members and Settings of a project are for its admins only.
  const items = (product ? seed.spaces[product]! : []).filter(
    ([t]) => !proj || !["members", "machines", "settings"].includes(t) || acl.roleIn(proj.id) === "Admin",
  );
  const base = product === "access" ? "#/access" : product === "secrets" ? `#/secrets/${route[1]}` : `#/app/${product}`;
  const tab = (product === "access" ? route[1] : route[2]) ?? items[0]?.[0] ?? "";
  const link = (id: string, label: string, icon: IconName, count?: number) => (
    <SidebarMenuItem key={id}>
      <SidebarMenuButton asChild>
        <a
          href={`#/${id}`}
          title={label}
          aria-current={route.join("/").startsWith(id) || (id === "home" && !route.length) ? "page" : undefined}
        >
          <Icon name={icon} />
          {label}
          {count !== undefined && <span className="count">{count}</span>}
        </a>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );

  const revoke = (ids: string[]) => {
    setSessions((ss) => ss.map((s) => (ids.includes(s.id) ? { ...s, state: "revoked", endedAt: NOW } : s)));
    say(`Revoked ${plural(ids.length, "session")}`);
  };
  const pause = () => {
    revoke(live.map((s) => s.id));
    setPaused(true);
    say("");
  };
  const resume = () => {
    setPaused(false);
    say("Agents resumed");
  };
  const db: Db = { sessions, secrets, agents, paused, revoke, pause, resume, setSecrets, setAgents, say };

  return (
    <PlanContext value={planOf[at]!}>
      <div className="app" data-folded={folded || undefined}>
        <aside className="side">
          <SidebarProvider className="contents">
            <a
              className="brand"
              href="#/home"
              aria-label="Locksmith home"
              onMouseEnter={() => setBrandHover(true)}
              onMouseLeave={() => setBrandHover(false)}
            >
              <Logo size={36} open={brandHover} />
              <Word />
            </a>
            {product ? (
              <>
                <nav className="nav" aria-label={seed.products.find((x) => x.id === product)!.name}>
                  <SidebarMenu>
                    {items.map(([t, label, icon, group], i) => (
                      <Fragment key={t}>
                        {group && group !== items[i - 1]?.[3] && (
                          <SidebarGroupLabel asChild>
                            <li className="nav-h">{group}</li>
                          </SidebarGroupLabel>
                        )}
                        <SidebarMenuItem>
                          <SidebarMenuButton asChild>
                            <a href={`${base}/${t}`} title={label} aria-current={tab === t ? "page" : undefined}>
                              <Icon name={icon} />
                              {label}
                              {t === "secrets" && <span className="count">{own.length}</span>}
                              {product === "access" && t === "sessions" && <span className="count">{live.length}</span>}
                            </a>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      </Fragment>
                    ))}
                  </SidebarMenu>
                </nav>
              </>
            ) : lobby ? (
              <nav className="nav" aria-label="Secret Management">
                <SidebarMenu>
                  {seed.spaces["secrets-lobby"]!.map(([t, label, icon]) => (
                    <SidebarMenuItem key={t}>
                      <SidebarMenuButton asChild>
                        <a
                          href={t === "projects" ? "#/secrets" : t === "sharing" ? "#/sharing" : `#/sm/${t}`}
                          title={label}
                          aria-current={lobbyTab === t ? "page" : undefined}
                        >
                          <Icon name={icon} />
                          {label}
                          {t === "projects" && (
                            <span className="count">{seed.projects.filter((x) => acl.roleIn(x.id)).length}</span>
                          )}
                        </a>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </nav>
            ) : (
              <>
                <nav className="nav" aria-label="Main">
                  <SidebarMenu>
                    {link("home", "Home", "grid")}
                    {link("notifications", "Notifications", "alert", unread || undefined)}
                    {link("integrations", "Integrations", "s_code")}
                    {link("mcp", "MCP", "s_terminal")}
                    {isAdmin && (
                      <>
                        <SidebarGroupLabel asChild>
                          <li className="nav-h">Administration</li>
                        </SidebarGroupLabel>
                        {ws.org && link("members", "User Management", "sessions", seed.members.length)}
                        {link("billing", "Plan and billing", "clock")}
                        {link("projects", "Projects", "s_folder")}
                        {link("environments", "Environments", "s_layers")}
                        {link("settings", "Settings", "s_window")}
                      </>
                    )}
                  </SidebarMenu>
                </nav>
              </>
            )}
            <div className="side-foot">
              <Selector
                className="user"
                title={`${me.name}, your account`}
                summary={
                  <>
                    <span className="av">{me.name[0]}</span>
                    <span>
                      {me.name.split(" ")[0]} <Badge className="tier">{planOf[at]}</Badge>
                      <small>{me.email}</small>
                    </span>
                    <Chevrons />
                  </>
                }
              >
                {(shut) => (
                  <>
                    <a href="#/account" onClick={shut}>
                      <span className="av">
                        <Icon name="sessions" />
                      </span>
                      User settings
                    </a>
                    <AppearanceSeg value={appearance} set={setAppearance} />
                    <Button variant="ghost" type="button">
                      <span className="av">
                        <Icon name="power" />
                      </span>
                      Sign out
                    </Button>
                  </>
                )}
              </Selector>
            </div>
          </SidebarProvider>
        </aside>

        <div className="work">
          <header className="vault" aria-label={proj ? "Project" : "Workspace"} data-paused={paused}>
            <Button
              variant="ghost"
              type="button"
              className="fold"
              aria-pressed={folded}
              aria-label={folded ? "Show sidebar" : "Hide sidebar"}
              title={folded ? "Show sidebar" : "Hide sidebar"}
              onClick={fold}
            >
              <svg className="i" viewBox="0 0 16 16" aria-hidden="true">
                <rect x="2" y="3" width="12" height="10" rx="1.75" />
                <path d="M6 3v10" />
              </svg>
            </Button>
            <nav className="crumbbar" aria-label="Breadcrumb">
              {crumbProduct && <ProductSwitch id={crumbProduct} />}
              {proj ? (
                <>
                  <i aria-hidden="true">/</i>
                  <ProjectSwitch id={proj.id} tab={tab} can={(pid) => !!acl.roleIn(pid)} />
                </>
              ) : (
                lobby && (
                  <>
                    <i aria-hidden="true">/</i>
                    <span>{seed.spaces["secrets-lobby"]!.find(([t]) => t === lobbyTab)?.[1]}</span>
                  </>
                )
              )}
              {product && (
                <>
                  <i aria-hidden="true">/</i>
                  <span>{items.find(([t]) => t === tab)?.[1]}</span>
                </>
              )}
            </nav>
            <div className="vault-line" aria-live="polite" aria-atomic="true">
              {paused && (
                <b className="vault-state">
                  <span className="dot" aria-hidden="true" />
                  Agents paused
                </b>
              )}
              {paused && (
                <span className="vault-meta">
                  <span>No token is issued until you resume</span>
                </span>
              )}
              {note && <span className="vault-note">{note}</span>}
              {viewerAt !== 0 && (
                <span className="previewing">
                  Previewing as {viewer.name} · {viewer.role}
                </span>
              )}
            </div>
            <div className="acts">
              {viewerAt !== 0 && (
                <Button variant="outline" size="sm" type="button" onClick={() => preview(0)}>
                  Stop preview
                </Button>
              )}
              {paused && (
                <Button type="button" onClick={resume}>
                  <Icon name="unlock" />
                  Resume agents
                </Button>
              )}
              <NoticeMenu />
              <Workspace at={at} limit={wsLimit} />
            </div>
          </header>
          <TabBusy value={loaded.where !== where}>
            <main aria-busy={loaded.where !== where}>
              {loaded.whole !== whole ? (
                <Loader />
              ) : gate && (lacks(planOf[at]!, gate) || !pageFor(`secrets/${route[2]}`)) ? (
                <section>
                  <Locked feature={gate} />
                </section>
              ) : page === "secrets" ? (
                route[1] ? (
                  <Project db={db} acl={acl} id={route[1]} tab={proj ? tab : undefined} env={route[3]} />
                ) : (
                  <Projects db={db} acl={acl} />
                )
              ) : page === "access" ? (
                tab === "agents" ? (
                  <Agents db={db} />
                ) : tab === "activity" ? (
                  <section>
                    <Head
                      title="Activity"
                      sub="Every request the gateway relayed or blocked for this workspace's agents."
                    />
                    <Log events={seed.events} />
                  </section>
                ) : tab === "sessions" ? (
                  <Overview db={db} />
                ) : (
                  <Soon id="access" tab={tab} sub={route[2]} say={say} />
                )
              ) : HubPage ? (
                <HubPage sub={route[1]} say={say} />
              ) : page === "upgrade" ? (
                <Upgrade
                  name={ws.name}
                  plan={planOf[at]!}
                  setPlan={(p) => {
                    setPlanOf((x) => x.map((v, i) => (i === at ? p : v)));
                    say(`${ws.name} is now on ${p}`);
                  }}
                />
              ) : page === "billing" ? (
                <Billing
                  ws={at}
                  name={ws.name}
                  plan={planOf[at]!}
                  setPlan={(p) => {
                    setPlanOf((x) => x.map((v, i) => (i === at ? p : v)));
                    say(`${ws.name} is now on ${p}`);
                  }}
                />
              ) : page === "projects" ? (
                <Projects db={db} acl={acl} all />
              ) : page === "environments" ? (
                <Environments />
              ) : page === "settings" ? (
                <Settings key={ws.name} ws={ws} say={say} />
              ) : page === "integrations" ? (
                <Integrations say={say} />
              ) : page === "sharing" ? (
                <Sharing say={say} />
              ) : page === "sm" ? (
                <Soon id="secrets" tab={route[1]} space="secrets-lobby" sub={route[2]} say={say} />
              ) : page === "members" ? (
                <Members acl={acl} tab={route[1]} />
              ) : page === "account" ? (
                <Account appearance={appearance} setAppearance={setAppearance} />
              ) : page === "app" ? (
                <Soon id={route[1]} tab={product ? tab : undefined} sub={route[3]} say={say} />
              ) : page === "switch" ? (
                <SignInTo
                  at={Number(route[1])}
                  from={ws.name}
                  signIn={(i) => {
                    setAt(i);
                    location.hash = "#/home";
                  }}
                />
              ) : page === "welcome" ? (
                wsLimit ? (
                  <section>
                    <Head title="Create a workspace" />
                    <WorkspaceLimit limit={wsLimit!} />
                  </section>
                ) : (
                  <Welcome
                    create={(w) => {
                      seed.workspaces.push(w);
                      setPlanOf((x) => [...x, "Free"]);
                      setAt(seed.workspaces.length - 1);
                    }}
                  />
                )
              ) : (
                <Hub db={db} org={ws.org} name={ws.name} />
              )}
            </main>
          </TabBusy>
        </div>
      </div>
    </PlanContext>
  );
}

const Head = ({ title, sub, children }: { title: string; sub?: React.ReactNode; children?: React.ReactNode }) => (
  <div className="screen-head">
    <div>
      <h1>{title}</h1>
      {sub && <p className="lede">{sub}</p>}
    </div>
    {children}
  </div>
);
function Hub({ db, org, name }: { db: Db; org: boolean; name: string }) {
  const live = db.sessions.filter((s) => s.state === "active").length;
  const stats: Record<string, [number | string, string][]> = {
    secrets: [
      [db.secrets.length, "secrets"],
      [new Set(db.secrets.map((s) => s.project + s.env)).size, "environments"],
      [seed.projects.length, "projects"],
    ],
    access: [
      [db.agents.length, "agents"],
      [live, "live sessions"],
      [db.secrets.reduce((n, s) => n + s.grants.length, 0), "grants"],
    ],
  };
  const groups = [...new Set(seed.products.map((p) => p.group))];
  return (
    <section className="hub">
      <Head
        title={org ? `${name} home` : "Your home"}
        sub={
          org
            ? "Every Locksmith product for your organization. Members and teams share this view."
            : "Every Locksmith product for your own work. Only you can see this workspace."
        }
      />
      {groups.map((g, i) => (
        <Fragment key={g}>
          {groups.length > 1 && (
            <div className={i ? "sec-h spaced" : "sec-h"}>
              <h2>{g}</h2>
            </div>
          )}
          <div className="hub-grid">
            {seed.products
              .filter((p) => p.group === g)
              .map((p) => (
                <a key={p.id} className="pcard" href={p.href ?? `#/app/${p.id}`} data-planned={!built(p) || undefined}>
                  <span className="pic" data-tint={p.tint}>
                    <Icon name={p.icon} />
                  </span>
                  <span className="pname">
                    {p.name}
                    {!built(p) && <Badge variant="secondary">Planned</Badge>}
                  </span>
                  <span className="pblurb">{p.blurb}</span>
                  {stats[p.id] && (
                    <span className="pstats">
                      {stats[p.id]!.map(([n, l]) => (
                        <span key={l}>
                          <b>{n}</b> {l}
                        </span>
                      ))}
                    </span>
                  )}
                </a>
              ))}
          </div>
        </Fragment>
      ))}
    </section>
  );
}

function Soon({
  id,
  tab,
  space,
  project,
  sub,
  say,
}: {
  id?: string;
  tab?: string;
  space?: string;
  project?: string;
  sub?: string;
  say: (note: string) => void;
}) {
  const p = [...seed.products, ...seed.extras].find((x) => x.id === id);
  if (!p)
    return (
      <p className="state">
        No such product. <a href="#/home">Back to home</a>
      </p>
    );
  const key = space ?? p.id;
  const Page = pageFor(`${key}/${tab}`);
  if (Page) return <Page project={project} sub={sub} say={say} />;
  const item = seed.spaces[key]?.find(([t]) => t === tab);
  const what = item ? `${item[1]} in ${p.name}` : p.name;
  return (
    <section>
      <Head title={item ? item[1] : p.name} sub={seed.about[`${key}/${tab}`] ?? p.blurb} />
      <div className="state empty">
        <span className="state-ic">
          <Icon name={item ? item[2] : p.icon} />
        </span>
        <div>
          <b>{what} is planned and not available yet.</b> There is nothing to set up today.
        </div>
      </div>
    </section>
  );
}

function Integrations({ say }: { say: (note: string) => void }) {
  const [rows, setRows] = useState(seed.connections);
  const [kind, setKind] = useState<seed.Kind | "All">("All");
  const [adding, setAdding] = useState(false);
  const [newKind, setNewKind] = useState<seed.Kind>("Source and CI");
  const [removing, setRemoving] = useState<string | null>(null);
  const shown = rows.filter((c) => kind === "All" || c.kind === kind);
  const add = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setRows((r) => [
      ...r,
      {
        id: `c_new${r.length}`,
        kind: newKind,
        provider: String(f.get("provider")),
        name: String(f.get("name")),
        icon: "relay",
        uses: [],
        scope: String(f.get("scope")),
      },
    ]);
    say(`Connected ${f.get("name")}`);
    setAdding(false);
  };
  const remove = (c: seed.Connection) => {
    setRows((r) => r.filter((x) => x !== c));
    setRemoving(null);
    say(`Removed ${c.name}`);
  };
  return (
    <section>
      <Head
        title="Integrations"
        sub="Connections to the systems outside Locksmith. Set one up here once; each product then picks it from a list."
      >
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Add connection
        </Button>
      </Head>
      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={add} aria-label="Add connection">
            <h2>Add a connection</h2>
            <div className="add share">
              <Label className="field">
                Kind
                <Dropdown value={newKind} onChange={(e) => setNewKind(e as seed.Kind)}>
                  {seed.kinds.map((k) => (
                    <Option key={k}>{k}</Option>
                  ))}
                </Dropdown>
              </Label>
              <Label className="field">
                System
                <Dropdown name="provider" key={newKind}>
                  {seed.providers[newKind].map((p) => (
                    <Option key={p}>{p}</Option>
                  ))}
                </Dropdown>
              </Label>
              <Label className="field">
                Name
                <Input name="name" required autoFocus placeholder="Staging account" autoComplete="off" />
              </Label>
              <Label className="field">
                Who may use it
                <Dropdown name="scope">
                  <Option>All projects</Option>
                  {seed.projects.map((p) => (
                    <Option key={p.id}>{p.id}</Option>
                  ))}
                </Dropdown>
              </Label>
              <Button type="submit">Connect</Button>
              <Button variant="ghost" type="button" style={{ justifySelf: "start" }} onClick={() => setAdding(false)}>
                Cancel
              </Button>
            </div>
            <p className="hint">
              The next step signs you in to that system. Its credential is kept as a Locksmith secret and rotated like
              any other; nobody sees it here.
            </p>
          </form>
        </Card>
      )}
      <div className="toolbar">
        <ToggleGroup type="single" value={String(kind)} aria-label="Kind">
          {(["All", ...seed.kinds] as const).map((k) => (
            <ToggleGroupItem key={k} size="sm" value={String(k)} onClick={() => setKind(k)}>
              {k}
              {k !== "All" && <span className="n">{rows.filter((c) => c.kind === k).length}</span>}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
      </div>
      {shown.length === 0 ? (
        <div className="state empty">
          <span className="state-ic">
            <Icon name="relay" />
          </span>
          <div>
            <b>No {kind === "All" ? "" : `${kind.toLowerCase()} `}connections yet.</b> Add one, then pick it from inside
            a product.
          </div>
        </div>
      ) : (
        <ul className="list conns">
          {shown.map((c) => (
            <li key={c.id} className="row">
              <span className="ic">
                {c.icon === "s_claude" ? (
                  <span className="src-claude">
                    <Icon name="s_claude" />
                  </span>
                ) : (
                  <Icon name={c.icon} />
                )}
              </span>
              <div>
                <b>{c.name}</b>{" "}
                <span className="muted small">
                  {c.provider} · {c.kind}
                </span>
                <p>
                  {c.uses.length === 0
                    ? "Not used by any product yet."
                    : c.uses.map(([p, what]) => (
                        <span key={p} className="use">
                          <b>{p}</b> {what}
                        </span>
                      ))}
                </p>
                {c.problem && (
                  <p className="warn">
                    <Icon name="alert" />
                    {c.problem}
                  </p>
                )}
                {removing === c.id && (
                  <Alert variant="destructive" style={{ margin: "10px 0 0" }}>
                    <AlertDescription>
                      Removing this stops {c.uses.map(([p, what]) => `${what} in ${p}`).join(", ")}.
                      <Button variant="destructive" size="sm" type="button" onClick={() => remove(c)}>
                        Remove anyway
                      </Button>
                      <Button variant="ghost" size="sm" type="button" onClick={() => setRemoving(null)}>
                        Keep
                      </Button>
                    </AlertDescription>
                  </Alert>
                )}
              </div>
              <span className="meta">
                <span title="Which projects may pick this connection">{c.scope}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-(--destructive-text)"
                  type="button"
                  aria-label={`Remove ${c.name}`}
                  onClick={() => (c.uses.length ? setRemoving(c.id) : remove(c))}
                >
                  Remove
                </Button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Sharing({ say }: { say: (note: string) => void }) {
  const [rows, setRows] = useState(seed.shares);
  const [adding, setAdding] = useState(false);
  const [once, setOnce] = useState<string | null>(null);
  const create = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const id = `shr_new${rows.length}`;
    // The value field is dropped on purpose: the console never keeps what was typed.
    setRows((r) => [
      {
        id,
        label: String(f.get("label")),
        by: me.name,
        created: NOW,
        expires: NOW + Number(f.get("ttl")),
        views: 0,
        maxViews: Number(f.get("views")),
      },
      ...r,
    ]);
    setOnce(id);
    setAdding(false);
  };
  return (
    <section>
      <Head
        title="Secret sharing"
        sub="Hand one secret to a person outside this workspace through a link that expires and counts its views. Agents never get these links."
      >
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          Share a secret
        </Button>
      </Head>
      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={create} aria-label="Share a secret">
            <h2>Share a secret</h2>
            <div className="add share">
              <Label className="field">
                What it is
                <Input
                  name="label"
                  required
                  autoFocus
                  placeholder="Staging DB password for Sam"
                  autoComplete="off"
                  style={{ width: 300 }}
                />
              </Label>
              <Label className="field">
                Value
                <Input name="value" type="password" required autoComplete="off" placeholder="Paste the value" />
              </Label>
              <Label className="field">
                Expires after
                <Dropdown name="ttl" defaultValue={86400}>
                  <Option value={3600}>1 hour</Option>
                  <Option value={86400}>1 day</Option>
                  <Option value={604800}>7 days</Option>
                </Dropdown>
              </Label>
              <Label className="field">
                Can be opened
                <Dropdown name="views" defaultValue={1}>
                  <Option value={1}>Once</Option>
                  <Option value={5}>5 times</Option>
                </Dropdown>
              </Label>
              <Button type="submit">Create link</Button>
              <Button variant="ghost" type="button" onClick={() => setAdding(false)}>
                Cancel
              </Button>
            </div>
            <p className="hint">
              The value is encrypted in this browser and the key travels only inside the link, so Locksmith cannot read
              it. After the last view or the expiry, the link shows nothing.
            </p>
          </form>
        </Card>
      )}
      {once && (
        <Card className="panel once" role="status">
          <h2>Copy the link now</h2>
          <p>It is shown once. Anyone with the link can open the secret until it expires or runs out of views.</p>
          <code className="block">https://share.locksmith.example/s/{once}#sample-key-not-real</code>
          <Button variant="outline" size="sm" type="button" style={{ marginTop: 12 }} onClick={() => setOnce(null)}>
            I have copied it
          </Button>
        </Card>
      )}
      {rows.length === 0 ? (
        <div className="state empty">
          <span className="state-ic">
            <Icon name="arrow" />
          </span>
          <div>
            <b>No active links.</b> Share a secret to send one to someone who is not in this workspace.
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Shared secret</TableHead>
                <TableHead>Created by</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Opened</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="strong">{r.label}</TableCell>
                  <TableCell>{r.by}</TableCell>
                  <TableCell className="muted">{ago(r.created)}</TableCell>
                  <TableCell>{until(r.expires).replace("expires ", "")}</TableCell>
                  <TableCell className="mono">
                    {r.views} of {r.maxViews}
                  </TableCell>
                  <TableCell className="num">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      type="button"
                      aria-label={`Revoke link: ${r.label}`}
                      onClick={() => {
                        setRows((x) => x.filter((y) => y !== r));
                        say("Link revoked");
                      }}
                    >
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}

function Members({ acl, tab }: { acl: Acl; tab?: string }) {
  const at = tab === "groups" || tab === "roles" ? tab : "users";
  const roles = seed.roles;
  const [users, setUsers] = useState(() => seed.members.map((m, i) => ({ ...m, i, invited: false })));
  const [inviting, setInviting] = useState(false);
  const noGroups = useLocked("groups");
  const Groups = paid.pages["members/groups"];
  const plan = useContext(PlanContext);
  const cap = limitsOf(plan).users; // null on a per-seat plan: seats are bought on the billing page
  const full = cap !== null && users.length >= cap;
  const elevated = (role: string) => roles.find((r) => r.name === role)?.can.includes("sm.all");
  const projectsOf = (u: (typeof users)[number]) =>
    elevated(u.role)
      ? "All projects"
      : seed.projects
          .filter((p) => acl.pm[p.id]?.[u.email])
          .map((p) => p.id)
          .join(", ") || "None yet";
  const invite = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const email = String(f.get("email")).trim();
    setUsers((us) => [
      ...us,
      {
        name: email.split("@")[0]!,
        email,
        role: String(f.get("role")),
        team: String(f.get("group")),
        seen: NOW,
        i: -1,
        invited: true,
      },
    ]);
    setInviting(false);
  };
  return (
    <section>
      <Head
        title="User Management"
        sub="Who is in this organization, what their role lets them do, and which projects they can open."
      >
        {at === "users" && (
          <Button
            type="button"
            onClick={() => setInviting(true)}
            disabled={inviting || full}
            title={full ? `The ${plan} plan has ${cap} users` : undefined}
          >
            <Icon name="plus" />
            Invite user
          </Button>
        )}
      </Head>
      <Tabs value={at} className="mb-5">
        <TabsList variant="line" aria-label="User Management">
          <TabsTrigger value="users" asChild>
            <a href="#/members">
              Users <span className="n">{users.length}</span>
            </a>
          </TabsTrigger>
          <TabsTrigger value="groups" asChild>
            <a href="#/members/groups">
              Groups <span className="n">{seed.groups.length}</span>
              <GateBadge feature="groups" />
            </a>
          </TabsTrigger>
          <TabsTrigger value="roles" asChild>
            <a href="#/members/roles">
              Roles
              <GateBadge feature="groups" />
            </a>
          </TabsTrigger>
        </TabsList>
      </Tabs>
      <TabLoader />

      {at === "users" && full && (
        <Alert>
          <AlertDescription>
            This workspace has {users.length} of the {cap} users in the {plan} plan. Nobody is removed; to invite more,{" "}
            <a className="ls-link" href="#/upgrade">
              see the plans
            </a>
            .
          </AlertDescription>
        </Alert>
      )}
      {at === "users" && (
        <>
          {inviting && (
            <Card className="panel form">
              <form className="contents" onSubmit={invite} aria-label="Invite user">
                <h2>Invite a user</h2>
                <div className="add share">
                  <Label className="field">
                    Email
                    <Input
                      name="email"
                      type="email"
                      required
                      autoFocus
                      placeholder="name@acme.example"
                      autoComplete="off"
                      style={{ width: 260 }}
                    />
                  </Label>
                  <Label className="field">
                    Role
                    <Dropdown name="role" defaultValue="Member">
                      {roles.map((r) => (
                        <Option key={r.name}>{r.name}</Option>
                      ))}
                    </Dropdown>
                  </Label>
                  <Label className="field">
                    Group
                    <Dropdown name="group">
                      {seed.groups.map((g) => (
                        <Option key={g.name}>{g.name}</Option>
                      ))}
                    </Dropdown>
                  </Label>
                  <span />
                  <Button type="submit">Send invite</Button>
                  <Button
                    variant="ghost"
                    type="button"
                    style={{ justifySelf: "start" }}
                    onClick={() => setInviting(false)}
                  >
                    Cancel
                  </Button>
                </div>
                <p className="hint">
                  They get an email with a link. Until they accept, they are listed as invited and can open nothing.
                </p>
              </form>
            </Card>
          )}
          <div className="table-wrap">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Group</TableHead>
                  <TableHead>Projects</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.email}>
                    <TableCell>
                      <span className="strong">{u.name}</span>
                      <br />
                      <span className="mono muted">{u.email}</span>
                    </TableCell>
                    <TableCell>
                      {u.i === 0 ? (
                        "Owner"
                      ) : (
                        <Dropdown
                          aria-label={`Role of ${u.name}`}
                          value={u.role}
                          onChange={(e) => setUsers((us) => us.map((x) => (x === u ? { ...x, role: e } : x)))}
                        >
                          {roles.map((r) => (
                            <Option key={r.name}>{r.name}</Option>
                          ))}
                        </Dropdown>
                      )}
                    </TableCell>
                    <TableCell>{u.team}</TableCell>
                    <TableCell className={elevated(u.role) ? "muted" : undefined}>
                      {u.invited ? <span className="muted">After they accept</span> : projectsOf(u)}
                    </TableCell>
                    <TableCell>
                      {u.invited ? (
                        <Badge variant="secondary" data-by="agent">
                          Invited
                        </Badge>
                      ) : (
                        <span className="muted">Active {ago(u.seen)}</span>
                      )}
                    </TableCell>
                    <TableCell className="num nowrap">
                      {u.i > 0 && (
                        <Button
                          variant="outline"
                          size="sm"
                          type="button"
                          title="See the console as this person sees it"
                          onClick={() => {
                            acl.preview(u.i);
                            location.hash = "#/secrets";
                          }}
                        >
                          Preview as
                        </Button>
                      )}
                      {u.i !== 0 && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-(--destructive-text)"
                          type="button"
                          aria-label={`${u.invited ? "Cancel invite for" : "Remove"} ${u.name}`}
                          onClick={() => setUsers((us) => us.filter((x) => x !== u))}
                        >
                          {u.invited ? "Cancel invite" : "Remove"}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </>
      )}

      {at !== "users" && (noGroups || !Groups) && <Locked feature="groups" />}
      {at !== "users" && !noGroups && Groups && <Groups at={at} users={users} />}
    </section>
  );
}

const ROLES: seed.ProjectRole[] = ["Admin", "Developer", "Viewer"];
function ProjectMembers({ acl, id }: { acl: Acl; id: string }) {
  const here = acl.pm[id] ?? {};
  const set = (email: string, role?: seed.ProjectRole) =>
    acl.setPm((pm) => {
      const next = { ...pm[id] };
      if (role) next[email] = role;
      else delete next[email];
      return { ...pm, [id]: next };
    });
  const admins = seed.members.filter((m) => m.role !== "Member");
  const added = seed.members.filter((m) => here[m.email]);
  const free = seed.members.filter((m) => m.role === "Member" && !here[m.email]);
  return (
    <section>
      <Head
        title="Members"
        sub={`People who can open ${id}. Admins manage members and settings, developers change secrets and grants, viewers only read names and activity.`}
      />
      <div className="table-wrap">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Role in this project</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {added.map((m) => (
              <TableRow key={m.email}>
                <TableCell className="strong">{m.name}</TableCell>
                <TableCell className="mono">{m.email}</TableCell>
                <TableCell>
                  <Dropdown
                    aria-label={`Role of ${m.name}`}
                    value={here[m.email]}
                    onChange={(e) => set(m.email, e as seed.ProjectRole)}
                  >
                    {ROLES.map((r) => (
                      <Option key={r}>{r}</Option>
                    ))}
                  </Dropdown>
                </TableCell>
                <TableCell className="num">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-(--destructive-text)"
                    type="button"
                    aria-label={`Remove ${m.name} from ${id}`}
                    onClick={() => set(m.email)}
                  >
                    Remove
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {admins.map((m) => (
              <TableRow key={m.email}>
                <TableCell className="strong">{m.name}</TableCell>
                <TableCell className="mono">{m.email}</TableCell>
                <TableCell className="muted">Admin, as organization {m.role.toLowerCase()}</TableCell>
                <TableCell />
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {free.length > 0 && (
        <form
          className="inline-form"
          style={{ marginTop: 16 }}
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            set(String(f.get("who")), f.get("role") as seed.ProjectRole);
          }}
        >
          <Dropdown name="who" aria-label="Member">
            {free.map((m) => (
              <Option key={m.email} value={m.email}>
                {m.name}
              </Option>
            ))}
          </Dropdown>
          <Dropdown name="role" aria-label="Role" defaultValue="Developer">
            {ROLES.map((r) => (
              <Option key={r}>{r}</Option>
            ))}
          </Dropdown>
          <Button variant="outline" size="sm" type="submit">
            Add to project
          </Button>
        </form>
      )}
    </section>
  );
}

/** Moving to another workspace: it is a different account, so it asks to sign in (sample: one button). */
function SignInTo({ at, from, signIn }: { at: number; from: string; signIn: (i: number) => void }) {
  const w = seed.workspaces[at];
  if (!w)
    return (
      <p className="state">
        There is no such workspace. <a href="#/home">Back to {from}</a>
      </p>
    );
  return (
    <section>
      <Head
        title={`Sign in to ${w.name}`}
        sub={`${w.name} is ${w.org ? "an organization" : "a personal workspace"} with its own account. You are signed out of ${from} and sign in again to continue.`}
      />
      <div className="inline-form">
        <Button type="button" onClick={() => signIn(at)}>
          Sign in to {w.name}
        </Button>
        <Button asChild variant="ghost">
          <a href="#/home">Stay in {from}</a>
        </Button>
      </div>
    </section>
  );
}

const WHO = ["Personal", "Organization"];
function Welcome({ create }: { create: (w: (typeof seed.workspaces)[number]) => void }) {
  const [name, setName] = useState("");
  const [who, setWho] = useState(0);
  return (
    <form
      className="welcome"
      onSubmit={(e) => {
        e.preventDefault();
        create({ name: name.trim(), org: who === 1, sub: who === 1 ? "1 member · 0 teams" : "Personal" });
        location.hash = "#/home";
      }}
    >
      <Head
        title="Create a workspace"
        sub="A workspace holds your projects, agents and people. You can add people later, so start with whichever fits today."
      />
      <ToggleGroup type="single" value={String(who)} aria-label="Who is this workspace for">
        {WHO.map((w, i) => (
          <ToggleGroupItem key={w} size="sm" value={String(i)} onClick={() => setWho(i)}>
            {w}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
      <div className="add" style={{ margin: "16px 0 20px", gridTemplateColumns: "auto 1fr" }}>
        <Label className="field">
          {who === 0 ? "Workspace name" : "Organization name"}
          <Input
            required
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={who === 0 ? "Tomer" : "Acme"}
            autoComplete="off"
          />
        </Label>
      </div>
      <Button type="submit">Create workspace</Button>
    </form>
  );
}

const AgentIcon = ({ a }: { a?: Agent }) =>
  a?.icon === "s_claude" ? (
    <span className="src-claude">
      <Icon name="s_claude" />
    </span>
  ) : (
    <Icon name={a?.icon ?? "s_unknown"} />
  );

function Overview({ db }: { db: Db }) {
  const [striking, setStriking] = useState<string | null>(null);
  const live = db.sessions.filter((s) => s.state === "active").sort((a, b) => a.expires - b.expires);
  const ended = db.sessions.filter((s) => s.state !== "active");
  const span = 900 * 1.06;
  const ticks = [300, 600, 900]
    .map((t) => Math.floor(NOW / 300) * 300 + t)
    .filter((t) => (t - NOW) / span > 0.12 && (t - NOW) / span < 0.95);
  const x = (t: number) => `${(Math.max(0, t - NOW) / span) * 100}%`;
  const grid = ticks.map((t) => <i key={t} className="tick" style={{ left: x(t) }} />);
  const agentOf = (name: string) => db.agents.find((a) => a.name === name);
  const who = (s: Session) => (
    <span className="who">
      <span className="who-1">
        <AgentIcon a={agentOf(s.agent)} />
        <span className="who-name">{s.agent}</span>
        <span className="mono id">{s.id}</span>
      </span>
      <span className="who-2">
        {s.project} / <span className={s.env === "production" ? "prod" : undefined}>{s.env}</span> ·{" "}
        {agentOf(s.agent)?.machine ?? "removed agent"}
      </span>
    </span>
  );
  const names = (s: Session) => (
    <ul className="scopes-t mono" aria-label="Secrets in use">
      {s.secrets.map((n) => (
        <li key={n}>{n}</li>
      ))}
    </ul>
  );
  const revokeOne = (id: string) => {
    setStriking(id);
    setTimeout(() => {
      db.revoke([id]);
      setStriking(null);
    }, 480);
  };
  return (
    <section className="overview">
      <Head
        title="Sessions"
        sub="What agents hold right now, and until when. A session is a 15-minute token; revoking it stops the agent at once."
      >
        <Button
          variant="ghost"
          className="text-(--destructive-text)"
          type="button"
          disabled={!live.length}
          onClick={() => db.revoke(live.map((s) => s.id))}
        >
          Revoke all
        </Button>
        {db.paused ? (
          <Button type="button" onClick={db.resume}>
            <Icon name="unlock" />
            Resume agents
          </Button>
        ) : (
          <Button
            variant="destructive"
            type="button"
            title="Revokes every session and stops new tokens until you resume"
            onClick={db.pause}
          >
            <Icon name="lock" />
            Pause agents
          </Button>
        )}
      </Head>
      <div className="sec-h">
        <h2>Sessions</h2>
        <span className="n">
          {live.length} live{ended.length > 0 && ` · ${ended.length} ended`}
        </span>
      </div>
      <div className="tl-list" role="list" aria-label="Sessions">
        {live.length > 0 && (
          <div className="tl-row tl-axis" aria-hidden="true">
            <span>Agent</span>
            <span>Secrets in use</span>
            <span className="tl">
              <b className="tick-l now" style={{ left: 0 }}>
                now
              </b>
              {grid}
              {ticks.map((t) => (
                <b key={t} className="tick-l mono" style={{ left: x(t) }}>
                  {clock(t)}
                </b>
              ))}
            </span>
            <span className="r">Left</span>
            <span />
          </div>
        )}
        {live.length === 0 && (
          <div className="tl-row tl-empty" role="listitem">
            {db.paused ? (
              <p>
                <b>Agents are paused.</b> Every session was revoked and no agent can get a token until you resume.
              </p>
            ) : (
              <p>
                <b>No live sessions.</b> An enrolled agent opens one when it next asks for a secret it has access to.
              </p>
            )}
          </div>
        )}
        {live.map((s) => (
          <div
            key={s.id}
            role="listitem"
            className="tl-row"
            data-soon={s.expires - NOW < 180 || undefined}
            data-striking={striking === s.id || undefined}
          >
            {who(s)}
            {names(s)}
            <span className="tl" aria-hidden="true">
              {grid}
              <span className="bar" style={{ width: x(s.expires) }} />
            </span>
            <span className="r mono left" title={`Token expires ${clock(s.expires)}`}>
              {left(s.expires - NOW)}
            </span>
            <Button
              variant="ghost"
              size="sm"
              className="reveal text-(--destructive-text)"
              type="button"
              aria-label={`Revoke ${s.agent} session ${s.id}`}
              disabled={striking !== null}
              onClick={() => revokeOne(s.id)}
            >
              Revoke
            </Button>
          </div>
        ))}
        {ended.length > 0 && (
          <div className="tl-div" role="presentation">
            <span>Recently ended</span>
          </div>
        )}
        {ended.map((s) => (
          <div key={s.id} role="listitem" className="tl-row ended" data-state={s.state}>
            {who(s)}
            {names(s)}
            <span className="tl mono end">
              {s.state} {s.endedAt === NOW ? "just now" : clock(s.endedAt ?? s.expires)}
            </span>
            <span />
            <span />
          </div>
        ))}
      </div>

      <div className="sec-h spaced">
        <h2 id="h-events">Activity</h2>
        <a className="link" href="#/access/activity">
          All activity
        </a>
      </div>
      <Log events={seed.events.slice(0, 10)} />
      <p className="log-foot">
        <Icon name="shield" />
        Ledger chain verified {ago(NOW - 240)} · 18,420 entries
      </p>
    </section>
  );
}

const Log = ({ events }: { events: seed.Event[] }) =>
  events.length === 0 ? (
    <p className="quiet-state">Nothing in the ledger yet.</p>
  ) : (
    <ol className="log" aria-label="Activity">
      {events.map((e) => (
        <li
          key={e.seq}
          data-kind={e.outcome === "ok" ? (e.label.includes("revoked") ? "revoked" : "allowed") : "blocked"}
        >
          <time className="mono">{clock(e.at)}</time>
          <span className="mk" aria-hidden="true" />
          <span className="what">{e.label}</span>
          <span className="mono tgt" title={e.target}>
            {e.target}
          </span>
          <span className="who-s">{e.actor}</span>
        </li>
      ))}
    </ol>
  );

/** Inside a project the sidebar belongs to that project; this switches to a sibling or back to the list. */
/** Inside a product space: jump to another product without going back to Home. */
function ProductSwitch({ id }: { id: string }) {
  const at = seed.products.find((x) => x.id === id)!;
  return (
    <Selector
      title="Switch product"
      summary={
        <>
          <span className="pic" data-tint={at.tint}>
            <Icon name={at.icon} />
          </span>
          <span>
            {at.name}
            <small>Product</small>
          </span>
          <Chevrons />
        </>
      }
    >
      {(shut) => (
        <>
          {seed.products.map((x) => (
            <a key={x.id} href={x.href ?? `#/app/${x.id}`} aria-current={x.id === id || undefined} onClick={shut}>
              <span className="pic" data-tint={x.tint}>
                <Icon name={x.icon} />
              </span>
              {x.name}
              {x.id === id ? <Check /> : !built(x) && <Badge variant="secondary">Planned</Badge>}
            </a>
          ))}
        </>
      )}
    </Selector>
  );
}

function ProjectSwitch({ id, tab, can }: { id: string; tab: string; can: (projectId: string) => boolean }) {
  const [q, setQ] = useState("");
  const found = seed.projects.filter((x) => can(x.id) && x.id.includes(q.trim().toLowerCase()));
  return (
    <Selector
      title="Switch project"
      summary={
        <>
          <span className="av">{id[0]!.toUpperCase()}</span>
          <span>
            {id}
            <small>Project</small>
          </span>
          <Chevrons />
        </>
      }
    >
      {(shut) => (
        <>
          <Input
            type="search"
            aria-label="Find a project"
            placeholder="Find a project"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          {/* Switching keeps the page you are on, so Access stays Access in the next project. */}
          {found.map((x) => (
            <a
              key={x.id}
              href={`#/secrets/${x.id}/${tab}`}
              aria-current={x.id === id || undefined}
              onClick={() => {
                shut();
                setQ("");
              }}
            >
              <span className="av">{x.id[0]!.toUpperCase()}</span>
              {x.id}
              {x.id === id && <Check />}
            </a>
          ))}
          {found.length === 0 && <p className="muted small">No project matches “{q}”.</p>}
          <a
            className="all"
            href="#/secrets"
            onClick={() => {
              shut();
              setQ("");
            }}
          >
            <span className="av">
              <Icon name="grid" />
            </span>
            All projects
          </a>
        </>
      )}
    </Selector>
  );
}

function ProjectAccess({ db, id }: { db: Db; id: string }) {
  const rows = db.secrets.filter((s) => s.project === id).flatMap((s) => s.grants.map((g) => ({ s, g })));
  return (
    <section>
      <Head title="Access" sub={`Every agent that can use a secret in ${id}, across its environments.`} />
      {rows.length === 0 ? (
        <p className="state">No agent has access to anything in this project.</p>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Agent</TableHead>
                <TableHead>Secret</TableHead>
                <TableHead>Environment</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map(({ s, g }) => (
                <TableRow key={s.id + g.agent}>
                  <TableCell className="strong">{g.agent}</TableCell>
                  <TableCell className="mono">{s.name}</TableCell>
                  <TableCell className={s.env === "production" ? "prod" : undefined}>{s.env}</TableCell>
                  <TableCell className="muted">{until(g.expires)}</TableCell>
                  <TableCell className="num">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      type="button"
                      aria-label={`Revoke ${g.agent} from ${s.name} in ${s.env}`}
                      onClick={() =>
                        db.setSecrets((ss) =>
                          ss.map((x) => (x.id === s.id ? { ...x, grants: x.grants.filter((y) => y !== g) } : x)),
                        )
                      }
                    >
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}

function ProjectSettings({ p }: { p: seed.Project }) {
  const [inherit, setInherit] = useState(p.inherit);
  const [envs, setEnvsNow] = useState(p.envs);
  const [confirm, setConfirm] = useState("");
  // Editing the list makes it this project's own (the setter on Project turns inheriting off).
  const setEnvs = (change: (x: string[]) => string[]) => {
    const next = change(envs);
    p.envs = next;
    setInherit(false);
    setEnvsNow(next);
  };
  const inheritNow = (on: boolean) => {
    if (on) p.inherit = true;
    else p.envs = [...seed.defaults.envs];
    setInherit(on);
    setEnvsNow(p.envs);
  };
  return (
    <section>
      <Head title="Settings" sub={`The environments of ${p.id}, its description, and deleting it.`} />
      <EnvEditor
        envs={envs}
        setEnvs={setEnvs}
        readOnly={inherit}
        about="Each environment holds its own set of secrets. The last one is treated as production: access to it can be made to need a second person."
        scope="deletes every secret in it and the access agents have to them."
      >
        <label className="inline-form">
          <Switch label="Inherit the organization's environments" checked={inherit} onChange={inheritNow} />
          <span>
            {inherit
              ? "Follows the organization's list: a change there applies here."
              : "Has its own list. Turn this on to follow the organization's again."}
          </span>
        </label>
      </EnvEditor>
      <Card className="panel form">
        <form className="contents" onSubmit={(e) => e.preventDefault()}>
          <h2>Description</h2>
          <div className="add" style={{ gridTemplateColumns: "minmax(0, 1fr) auto" }}>
            <Label className="field">
              What this project is
              <Input defaultValue={p.description} style={{ width: "100%" }} />
            </Label>
            <Button variant="outline" type="submit">
              Save
            </Button>
          </div>
        </form>
      </Card>
      <Card className="panel">
        <h2>Delete project</h2>
        <p className="muted">
          Deletes every secret and grant in {p.id}. Agents lose access at once. This cannot be undone.
        </p>
        <div className="inline-form" style={{ marginTop: 12 }}>
          <Input
            aria-label={`Type ${p.id} to confirm`}
            placeholder={`Type ${p.id} to confirm`}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="off"
          />
          <Button variant="destructive" type="button" disabled={confirm !== p.id}>
            Delete project
          </Button>
        </div>
      </Card>
    </section>
  );
}

/** The projects list: in Secret Management, and as the organization's own Projects page (`all`). */
function Projects({ db, acl, all = false }: { db: Db; acl: Acl; all?: boolean }) {
  const mine = seed.projects.filter((p) => acl.roleIn(p.id));
  const plan = useContext(PlanContext);
  const projectCap = limitsOf(plan).projects;
  const projectsFull = projectCap !== null && seed.projects.length >= projectCap;
  const [naming, setNaming] = useState(false);
  // A new project starts out inheriting the organization's environments (`seed.defaults`).
  const create = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const id = String(new FormData(e.currentTarget).get("name"))
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");
    if (!id || seed.projects.some((p) => p.id === id)) return;
    seed.projects.push(seed.newProject(id));
    setNaming(false);
  };
  return (
    <section>
      <Head
        title={all ? "Projects" : "Secret Management"}
        sub={
          acl.isAdmin
            ? "A project groups the secrets of one codebase, split by environment. As an organization admin you see every project."
            : `A project groups the secrets of one codebase, split by environment. You see the ${plural(mine.length, "project")} you were added to.`
        }
      >
        {acl.isAdmin && (
          <Button
            type="button"
            onClick={() => setNaming(true)}
            disabled={projectsFull || naming}
            title={projectsFull ? `The ${plan} plan has ${projectCap} projects` : undefined}
          >
            <Icon name="plus" />
            New project
          </Button>
        )}
      </Head>
      {naming && (
        <form className="inline-form" onSubmit={create}>
          <Input name="name" required autoFocus aria-label="Project name" placeholder="my-project" autoComplete="off" />
          <Button type="submit">Create project</Button>
          <Button type="button" variant="ghost" onClick={() => setNaming(false)}>
            Cancel
          </Button>
        </form>
      )}
      {projectsFull && acl.isAdmin && (
        <Alert>
          <AlertDescription>
            This workspace has {seed.projects.length} of the {projectCap} projects in the {plan} plan. To add another,{" "}
            <a className="ls-link" href="#/upgrade">
              see the plans
            </a>
            .
          </AlertDescription>
        </Alert>
      )}
      {mine.length === 0 && (
        <div className="state empty">
          <span className="state-ic">
            <Icon name="key" />
          </span>
          <div>
            <b>You are not in any project yet.</b> Ask an organization admin to add you to one.
          </div>
        </div>
      )}
      <div className="list">
        {mine.map((p) => {
          const own = db.secrets.filter((s) => s.project === p.id);
          const withAccess = new Set(own.flatMap((s) => s.grants.map((g) => g.agent))).size;
          return (
            <a key={p.id} className="row" href={`#/secrets/${p.id}`}>
              <span className="ic">
                <Icon name="key" />
              </span>
              <span>
                <b>{p.id}</b>
                <p>{p.description}</p>
              </span>
              <span className="meta">
                <span>{plural(p.envs.length, "environment")}</span>
                <span>{plural(own.length, "secret")}</span>
                <span>{plural(withAccess, "agent")}</span>
                <Icon name="arrow" />
              </span>
            </a>
          );
        })}
      </div>
    </section>
  );
}

function Project({ db, acl, id, tab, env: envParam }: { db: Db; acl: Acl; id: string; tab?: string; env?: string }) {
  const p = seed.projects.find((x) => x.id === id);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const role = acl.roleIn(id);
  if (!p || !role)
    return (
      <p className="state">
        There is no project named <b>{id}</b>, or you were not added to it. <a href="#/secrets">Back to projects</a>
      </p>
    );
  if (tab === "members") return <ProjectMembers acl={acl} id={id} />;
  if (tab && !["secrets", "access", "activity", "settings"].includes(tab))
    return <Soon id="secrets" tab={tab} project={id} sub={envParam} say={db.say} />;
  if (tab === "access") return <ProjectAccess db={db} id={id} />;
  if (tab === "activity")
    return (
      <section>
        <Head title="Activity" sub={`What agents and people did in ${id}.`} />
        <Log events={seed.events.filter((e) => e.target.startsWith(`${id}/`))} />
      </section>
    );
  if (tab === "settings") return <ProjectSettings p={p} />;
  const env = envParam && p.envs.includes(envParam) ? envParam : p.envs[p.envs.length - 1]!;
  const rows = db.secrets.filter(
    (s) => s.project === id && s.env === env && s.name.toLowerCase().includes(q.toLowerCase()),
  );
  const patch = (sid: string, f: (s: Secret) => Secret) =>
    db.setSecrets((ss) => ss.map((s) => (s.id === sid ? f(s) : s)));

  const add = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const name = String(new FormData(e.currentTarget).get("name"))
      .trim()
      .toUpperCase()
      .replace(/[^A-Z0-9_]/g, "_");
    // The value field is dropped on purpose: the console never keeps what was typed.
    db.setSecrets((ss) => [
      { id: `sec_new_${ss.length}`, project: id, env, name, version: 1, updated: NOW, lastUsed: null, grants: [] },
      ...ss,
    ]);
    db.say(`Saved ${name}`);
    setAdding(false);
  };

  return (
    <section>
      <Head title="Secrets" sub={p.description} />
      <div className="toolbar">
        <ToggleGroup type="single" value={env ?? ""} aria-label="Environment">
          {p.envs.map((v) => (
            <ToggleGroupItem
              key={v}
              size="sm"
              value={v}
              onClick={() => {
                location.hash = `#/secrets/${id}/secrets/${v}`;
                setOpen(null);
              }}
            >
              <span className={v === "production" ? "prod" : undefined}>{v}</span>
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <label className="search push">
          <span className="sr-only">Find a secret</span>
          <Icon name="search" />
          <Input type="search" placeholder="Find a secret" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <Button
          type="button"
          onClick={() => setAdding(true)}
          disabled={adding || role === "Viewer"}
          title={role === "Viewer" ? "Viewers cannot add secrets" : undefined}
        >
          <Icon name="plus" />
          Add secret
        </Button>
      </div>

      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={add} aria-label="Add secret">
            <h2>Add a secret to {env}</h2>
            <div className="add">
              <Label className="field">
                Name
                <Input
                  name="name"
                  required
                  autoFocus
                  placeholder="STRIPE_SECRET_KEY"
                  autoComplete="off"
                  spellCheck={false}
                />
              </Label>
              <Label className="field">
                Value
                <Input name="value" type="password" required autoComplete="off" placeholder="Paste the value" />
              </Label>
              <Button type="submit">Save secret</Button>
              <Button variant="ghost" type="button" style={{ justifySelf: "start" }} onClick={() => setAdding(false)}>
                Cancel
              </Button>
            </div>
            <p className="hint">
              The value is encrypted in this browser before it is sent. After you save it, nobody can read it back here:
              not you, not an agent. It can only be replaced by a new version.
            </p>
          </form>
        </Card>
      )}

      {rows.length === 0 ? (
        <div className="state empty">
          <span className="state-ic">
            <Icon name="key" />
          </span>
          <div>
            {q ? (
              <>
                <b>No secret matches “{q}”</b> in {env}.
              </>
            ) : (
              <>
                <b>No secrets in {env} yet.</b> Add one, then grant an agent access to it.
              </>
            )}
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead>Agents with access</TableHead>
                <TableHead>Last used</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((s) => (
                <Fragment key={s.id}>
                  <TableRow>
                    <TableCell>
                      <Button
                        variant="ghost"
                        type="button"
                        className="cell-btn"
                        aria-expanded={open === s.id}
                        onClick={() => setOpen(open === s.id ? null : s.id)}
                      >
                        <Icon name="arrow" />
                        {s.name}
                      </Button>
                    </TableCell>
                    <TableCell className="mono">v{s.version}</TableCell>
                    <TableCell>{ago(s.updated)}</TableCell>
                    <TableCell>
                      {s.grants.length ? (
                        s.grants.map((g) => g.agent).join(", ")
                      ) : (
                        <span className="muted">No agent</span>
                      )}
                    </TableCell>
                    <TableCell className={s.lastUsed === null ? "muted" : undefined}>{ago(s.lastUsed)}</TableCell>
                  </TableRow>
                  {open === s.id && (
                    <TableRow className="detail">
                      <TableCell colSpan={5}>
                        <SecretDetail s={s} db={db} patch={(f) => patch(s.id, f)} />
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}

function SecretDetail({ s, db, patch }: { s: Secret; db: Db; patch: (f: (s: Secret) => Secret) => void }) {
  const [rotating, setRotating] = useState(false);
  const free = db.agents.filter((a) => !s.grants.some((g) => g.agent === a.name));
  const grant = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const secs = EXPIRY[Number(f.get("expiry"))]![1];
    patch((x) => ({
      ...x,
      grants: [...x.grants, { agent: String(f.get("agent")), expires: secs === null ? null : NOW + secs }],
    }));
    db.say(`Granted ${f.get("agent")} access to ${s.name}`);
  };
  return (
    <div className="detail-cols">
      <div>
        <h3>Agents with access</h3>
        {s.grants.length === 0 && (
          <p className="muted small" style={{ margin: "0 0 10px" }}>
            No agent can use this secret.
          </p>
        )}
        <ul className="plain">
          {s.grants.map((g) => (
            <li key={g.agent}>
              <span className="strong">{g.agent}</span>
              <span className="muted small">relay · {until(g.expires)}</span>
              <Button
                variant="ghost"
                size="sm"
                className="text-(--destructive-text)"
                type="button"
                onClick={() => {
                  patch((x) => ({ ...x, grants: x.grants.filter((y) => y !== g) }));
                  db.say(`Revoked ${g.agent} from ${s.name}`);
                }}
              >
                Revoke
              </Button>
            </li>
          ))}
        </ul>
        {free.length > 0 && (
          <form className="inline-form" onSubmit={grant}>
            <Dropdown name="agent" aria-label="Agent">
              {free.map((a) => (
                <Option key={a.name}>{a.name}</Option>
              ))}
            </Dropdown>
            <Dropdown name="expiry" aria-label="Expiry" defaultValue={1}>
              {EXPIRY.map(([l], i) => (
                <Option key={l} value={i}>
                  {l}
                </Option>
              ))}
            </Dropdown>
            <Button variant="outline" size="sm" type="submit">
              Grant access
            </Button>
          </form>
        )}
      </div>
      <div>
        <h3>Versions</h3>
        <ul className="plain">
          {Array.from({ length: Math.min(3, s.version) }, (_, i) => (
            <li key={i}>
              <span className="mono">v{s.version - i}</span>
              <span className="muted small">
                {i === 0 ? `current · ${ago(s.updated)}` : ago(s.updated - i * 30 * 86400)}
              </span>
            </li>
          ))}
        </ul>
        {rotating ? (
          <form
            className="inline-form"
            onSubmit={(e) => {
              e.preventDefault();
              patch((x) => ({ ...x, version: x.version + 1, updated: NOW }));
              db.say(`${s.name} is now v${s.version + 1}`);
              setRotating(false);
            }}
          >
            <Input
              type="password"
              required
              autoFocus
              autoComplete="off"
              aria-label="New value"
              placeholder="Paste the new value"
            />
            <Button variant="outline" size="sm" type="submit">
              Save v{s.version + 1}
            </Button>
            <Button variant="ghost" size="sm" type="button" onClick={() => setRotating(false)}>
              Cancel
            </Button>
          </form>
        ) : (
          <Button variant="outline" size="sm" type="button" onClick={() => setRotating(true)}>
            <Icon name="rotate" />
            New version
          </Button>
        )}
      </div>
    </div>
  );
}

function Agents({ db }: { db: Db }) {
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [once, setOnce] = useState<string | null>(null);
  const create = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const name = String(f.get("name"))
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-");
    db.setAgents((as) => [
      {
        name,
        description: String(f.get("description")),
        icon: "s_terminal",
        machine: "not enrolled yet",
        enrolled: NOW,
        lastSeen: NOW,
      },
      ...as,
    ]);
    setOnce(name);
    setAdding(false);
  };
  const grantsOf = (name: string) => db.secrets.filter((s) => s.grants.some((g) => g.agent === name));
  return (
    <section>
      <Head
        title="Agents"
        sub="An agent is an identity you enroll on one machine. It uses secrets through the gateway and never receives a value."
      >
        <Button type="button" onClick={() => setAdding(true)} disabled={adding}>
          <Icon name="plus" />
          New agent
        </Button>
      </Head>
      {adding && (
        <Card className="panel form">
          <form className="contents" onSubmit={create} aria-label="New agent">
            <h2>New agent</h2>
            <div className="add">
              <Label className="field">
                Name
                <Input
                  name="name"
                  required
                  autoFocus
                  placeholder="claude-laptop"
                  autoComplete="off"
                  spellCheck={false}
                />
              </Label>
              <Label className="field">
                What it is for
                <Input name="description" placeholder="Claude Code on my laptop" autoComplete="off" />
              </Label>
              <Button type="submit">Create agent</Button>
              <Button variant="ghost" type="button" style={{ justifySelf: "start" }} onClick={() => setAdding(false)}>
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}
      {once && (
        <Card className="panel once" role="status">
          <h2>Enroll {once} now</h2>
          <p>Run this on the agent's machine. The enrollment secret is shown once and cannot be retrieved again.</p>
          <code className="block">smith agent enroll --name {once} --secret lse_sample_not_a_real_secret</code>
          <Button variant="outline" size="sm" type="button" style={{ marginTop: 12 }} onClick={() => setOnce(null)}>
            I have copied it
          </Button>
        </Card>
      )}
      <ul className="sess-list">
        {db.agents.map((a) => {
          const gs = grantsOf(a.name);
          const live = db.sessions.some((s) => s.agent === a.name && s.state === "active");
          return (
            <li key={a.name} className="sess">
              <div className="sess-main">
                <Button
                  variant="ghost"
                  type="button"
                  className="sess-toggle"
                  aria-expanded={open === a.name}
                  onClick={() => setOpen(open === a.name ? null : a.name)}
                >
                  <span className="av">
                    <AgentIcon a={a} />
                  </span>
                  <span className="who">
                    <span className="who-1">
                      <span className="who-name">{a.name}</span>
                      {live && <span className="live-dot" title="Has a live session" />}
                    </span>
                    <span className="who-2">
                      {a.description} · {a.machine}
                    </span>
                  </span>
                </Button>
                <span className="muted small">{plural(gs.length, "secret")}</span>
                <span className="r muted small nowrap">{ago(a.lastSeen)}</span>
                <span />
              </div>
              {open === a.name && (
                <dl className="sess-det">
                  <dt>Enrolled</dt>
                  <dd>
                    {ago(a.enrolled)} on {a.machine}
                  </dd>
                  <dt>Can use</dt>
                  <dd>
                    {gs.length === 0 ? (
                      <span className="muted">Nothing yet. Open a secret in Secrets and grant this agent access.</span>
                    ) : (
                      <ul className="plain">
                        {gs.map((s) => (
                          <li key={s.id}>
                            <span className="mono">{s.name}</span>
                            <span className="muted small">
                              {s.project} / {s.env} · {until(s.grants.find((g) => g.agent === a.name)!.expires)}
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-(--destructive-text)"
                              type="button"
                              onClick={() =>
                                db.setSecrets((ss) =>
                                  ss.map((x) =>
                                    x.id === s.id ? { ...x, grants: x.grants.filter((g) => g.agent !== a.name) } : x,
                                  ),
                                )
                              }
                            >
                              Revoke
                            </Button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </dd>
                  <dt>Enrollment</dt>
                  <dd className="inline-form">
                    <Button variant="outline" size="sm" type="button" onClick={() => setOnce(a.name)}>
                      <Icon name="rotate" />
                      Rotate enrollment secret
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      type="button"
                      onClick={() => {
                        db.setAgents((as) => as.filter((x) => x !== a));
                        db.say(`Removed ${a.name}`);
                      }}
                    >
                      Remove agent
                    </Button>
                  </dd>
                </dl>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
