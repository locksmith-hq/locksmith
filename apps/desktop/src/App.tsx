import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import type { StatusView } from "@locksmith/api-types";
import * as api from "./api";
import {
  Bot,
  FileText,
  Fingerprint,
  FolderClosed,
  KeyRound,
  LayoutGrid,
  Lock,
  LockOpen,
  Monitor,
  Moon,
  Plug,
  Power,
  ScrollText,
  SquareTerminal,
  Sun,
  Ticket,
  TriangleAlert,
  Waypoints,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Button } from "@locksmith-hq/ui/button";
import { Mark } from "@locksmith-hq/ui/mark";
import { Pill } from "@locksmith-hq/ui/pill";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
} from "@locksmith-hq/ui/sidebar";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/ui/toggle-group";
import { Wordmark } from "@locksmith-hq/ui/wordmark";
import {
  Agents,
  Audit,
  Bindings,
  Keys,
  McpClients,
  McpTools,
  OrgAudit,
  Overview,
  Projects,
  Relays,
  Secrets,
  Sessions,
  Tokens,
  WorkloadIdentities,
  clock,
  errCode,
  msg,
  plural,
  type ScreenProps,
} from "./screens";

const TABS = {
  Overview,
  Sessions,
  Keys,
  Tokens,
  Agents,
  "Workload identities": WorkloadIdentities,
  Bindings,
  Projects,
  Secrets,
  Relays,
  Audit,
  "Org audit": OrgAudit,
  "MCP tools": McpTools,
  "MCP clients": McpClients,
} as const;
export type Tab = keyof typeof TABS;
const TAB_ICON: Record<Tab, LucideIcon> = {
  Overview: LayoutGrid,
  Sessions: SquareTerminal,
  Keys: KeyRound,
  Tokens: Ticket,
  Agents: Bot,
  "Workload identities": Fingerprint,
  Bindings: Plug,
  Projects: FolderClosed,
  Secrets: Lock,
  Relays: Waypoints,
  Audit: FileText,
  "Org audit": ScrollText,
  "MCP tools": Wrench,
  "MCP clients": Monitor,
};
const POLL_MS = 5000;

type Appearance = "system" | "light" | "dark";
const APPEARANCE: { v: Appearance; label: string; Icon: LucideIcon }[] = [
  { v: "system", label: "System", Icon: Monitor },
  { v: "light", label: "Light", Icon: Sun },
  { v: "dark", label: "Dark", Icon: Moon },
];
const PREF = "locksmith.appearance";
const readPref = (): Appearance => {
  try {
    const v = localStorage.getItem(PREF);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
};

/** Sets `data-theme` on <html> from the stored choice, following the system while it is "system". */
function useAppearance() {
  const [pref, setPref] = useState<Appearance>(readPref);
  useLayoutEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    const apply = () => {
      document.documentElement.dataset.theme = pref === "system" ? (mq?.matches ? "dark" : "light") : pref;
    };
    apply();
    mq?.addEventListener?.("change", apply);
    try {
      if (pref === "system") localStorage.removeItem(PREF);
      else localStorage.setItem(PREF, pref);
    } catch {
      /* storage blocked: keep the choice for this window only */
    }
    return () => mq?.removeEventListener?.("change", apply);
  }, [pref]);
  return [pref, setPref] as const;
}

/** `since`: when the vault last changed to its current state, from the ledger's UNLOCK/LOCK events. */
interface Counts {
  tokens?: number;
  relays?: number;
  since?: Partial<Record<"UNLOCK" | "LOCK", number>>;
}

export function App() {
  const [tab, setTab] = useState<Tab>("Overview");
  const [st, setSt] = useState<StatusView | null>(null);
  const [down, setDown] = useState<string | null>(null);
  const [counts, setCounts] = useState<Counts>({});
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const [appearance, setAppearance] = useAppearance();

  const refresh = useCallback(async () => {
    try {
      setSt(await api.status());
      setDown(null);
    } catch (e) {
      // A poll never hides an action error; only "daemon gone" replaces the screen.
      if (errCode(e) === "Unavailable") {
        setDown(msg(e));
        setSt(null);
      }
      return;
    }
    // Sidebar counts are best effort: a failure leaves the count off, never an error.
    const [t, r, a] = await Promise.allSettled([api.tokenList(), api.relayInfo(), api.auditList(200)]);
    const since: Counts["since"] = {};
    if (a.status === "fulfilled")
      for (const e of a.value ?? []) if (e.action === "UNLOCK" || e.action === "LOCK") since[e.action] = e.ts;
    setCounts({
      since,
      tokens: t.status === "fulfilled" ? t.value?.length : undefined,
      relays:
        r.status === "fulfilled" && r.value
          ? [r.value.git_port, r.value.http_port, r.value.aws_port].filter((p) => p != null).length
          : undefined,
    });
  }, []);
  useEffect(() => {
    void refresh();
    const t = setInterval(() => {
      if (document.visibilityState !== "hidden") void refresh();
    }, POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  const act: ScreenProps["act"] = useCallback(
    async (fn, label) => {
      setErr("");
      setNote("");
      try {
        const r = await fn();
        const l = label?.(r);
        if (l) setNote(l);
      } catch (e) {
        setErr(msg(e));
      }
      await refresh();
    },
    [refresh],
  );

  const live = st ? st.leases.filter((l) => l.state === "active") : [];
  const Screen = TABS[tab];
  const open = st ? !st.locked : false;
  const count: Partial<Record<Tab, number>> = {
    Overview: st ? live.length : undefined,
    Sessions: st ? live.length : undefined,
    Tokens: counts.tokens,
    Relays: counts.relays,
  };
  const lock = () => act(api.lock, () => "Vault locked");
  const unlock = () =>
    act(api.unlockSecure, (r) => (r === "cancelled" ? "Unlock cancelled, the vault stays locked" : ""));
  const revokeAll = () =>
    act(
      () => api.revoke(null),
      (n) => `Revoked ${plural(n, "session")}`,
    );
  const since = counts.since?.[open ? "UNLOCK" : "LOCK"];

  return (
    <SidebarProvider className="h-svh">
      <Sidebar collapsible="none" className="h-svh border-r">
        <SidebarHeader>
          <div className="logo flex items-center gap-2.5 px-2 py-1.5">
            <Mark small size={26} open={open} />
            <Wordmark />
          </div>
        </SidebarHeader>
        <SidebarContent>
          <nav aria-label="Main">
            <SidebarGroup>
              <SidebarGroupContent>
                <SidebarMenu>
                  {(Object.keys(TABS) as Tab[]).map((t) => {
                    const TabIcon = TAB_ICON[t];
                    return (
                      <SidebarMenuItem key={t}>
                        <SidebarMenuButton
                          type="button"
                          isActive={t === tab}
                          aria-current={t === tab ? "page" : undefined}
                          onClick={() => setTab(t)}
                        >
                          <TabIcon />
                          {t}
                          {count[t] !== undefined && (
                            <span className="ml-auto text-xs text-muted-foreground">{count[t]}</span>
                          )}
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    );
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </nav>
        </SidebarContent>
        <SidebarFooter className="gap-3">
          <ToggleGroup
            type="single"
            size="sm"
            aria-label="Appearance"
            className="w-full"
            value={appearance}
            // Radix sends "" when the pressed item is pressed again; one appearance is always chosen.
            onValueChange={(v) => v && setAppearance(v as Appearance)}
          >
            {APPEARANCE.map(({ v, label, Icon }) => (
              <ToggleGroupItem key={v} value={v} title={`Appearance: ${label}`} className="flex-1 px-1 text-xs">
                <Icon />
                {label}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          <Pill tone={down ? "danger" : st ? "live" : undefined} className="w-fit">
            <span>
              <b>locksmithd</b> · {down ? "not running" : st ? "running" : "connecting"}
            </span>
          </Pill>
        </SidebarFooter>
      </Sidebar>

      <div className="min-w-0 flex-1 overflow-auto">
        {down ? (
          <main className="max-w-2xl px-7 pt-18 pb-10" aria-labelledby="h-down">
            <span className="grid size-12 place-items-center rounded-xl bg-(--destructive-weak) text-(--destructive-text)">
              <Power />
            </span>
            <h1 id="h-down" className="mt-5 mb-2 text-2xl font-bold tracking-tight">
              The Locksmith daemon is not running
            </h1>
            <p className="mb-4 text-muted-foreground">
              This window reads everything from <code>locksmithd</code>. Start it in a terminal; this window reconnects
              on its own within a few seconds.
            </p>
            <pre className="mb-4 rounded-lg border bg-card px-4 py-3">
              <code>locksmithd</code>
            </pre>
            <p className="text-[13px] text-muted-foreground">Detail: {down}</p>
          </main>
        ) : (
          <>
            <header
              className="sticky top-0 z-10 flex min-h-15 items-center gap-4 border-b bg-background/90 px-7 py-2.5 backdrop-blur"
              aria-label="Vault"
              data-open={open}
            >
              <div
                className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1"
                aria-live="polite"
                aria-atomic="true"
              >
                <span className="text-[15px] font-bold">Vault</span>
                {st ? (
                  <>
                    <Pill tone={open ? "live" : undefined}>{open ? "Unlocked" : "Locked"}</Pill>
                    <span className="vault-meta text-[13px] text-muted-foreground">
                      {open ? (
                        <span>{plural(live.length, "session")}</span>
                      ) : (
                        <span>Agents cannot start sessions or use keys</span>
                      )}
                      {since !== undefined && (
                        <span>
                          since{" "}
                          <time
                            className="font-mono text-xs text-foreground"
                            dateTime={new Date(since * 1000).toISOString()}
                          >
                            {clock(since)}
                          </time>
                        </span>
                      )}
                    </span>
                  </>
                ) : (
                  <span className="text-[13px] text-muted-foreground">Reading the vault…</span>
                )}
                {note && <span className="text-[13px] font-semibold text-(--brand-text)">{note}</span>}
              </div>
              {st && (
                <div className="flex flex-none gap-1.5">
                  <Button
                    type="button"
                    variant="ghost"
                    className="text-(--destructive-text)"
                    aria-label="Revoke all sessions"
                    disabled={!live.length}
                    onClick={revokeAll}
                  >
                    Revoke all
                  </Button>
                  {open ? (
                    <Button type="button" onClick={lock}>
                      <Lock />
                      Lock vault
                    </Button>
                  ) : (
                    <Button
                      type="button"
                      title="Opens a native Locksmith prompt; the passphrase never enters this window"
                      onClick={unlock}
                    >
                      <LockOpen />
                      Unlock vault
                    </Button>
                  )}
                </div>
              )}
            </header>
            <main className="max-w-[1240px] px-7 pt-7 pb-10">
              {err && (
                <Alert variant="destructive" className="mb-4">
                  <TriangleAlert />
                  <AlertDescription>{err}</AlertDescription>
                </Alert>
              )}
              <Screen st={st} act={act} go={setTab} />
            </main>
          </>
        )}
      </div>
    </SidebarProvider>
  );
}
