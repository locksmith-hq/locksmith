import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import type { StatusView } from "@locksmith/api-types";
import * as api from "./api";
import {
  CircleAlert,
  FileText,
  KeyRound,
  LayoutGrid,
  Lock,
  LockOpen,
  Monitor,
  Moon,
  Network,
  Power,
  Sun,
  Terminal,
  Ticket,
  type LucideIcon,
} from "lucide-react";
import { Alert } from "@locksmith-hq/alert";
import { Button } from "@locksmith-hq/button";
import { LiveDot } from "@locksmith-hq/live-dot";
import { Mark } from "@locksmith-hq/mark";
import { PageHeader } from "@locksmith-hq/page-header";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
} from "@locksmith-hq/sidebar";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/toggle-group";
import { Wordmark } from "@locksmith-hq/wordmark";
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
  Sessions: Terminal,
  Keys: KeyRound,
  Tokens: Ticket,
  Agents: Terminal,
  "Workload identities": KeyRound,
  Bindings: Network,
  Projects: LayoutGrid,
  Secrets: KeyRound,
  Relays: Network,
  Audit: FileText,
  "Org audit": FileText,
  "MCP tools": KeyRound,
  "MCP clients": Terminal,
};
const POLL_MS = 5000;

type Appearance = "system" | "light" | "dark";
const APPEARANCE: { v: Appearance; label: string; icon: LucideIcon }[] = [
  { v: "system", label: "System", icon: Monitor },
  { v: "light", label: "Light", icon: Sun },
  { v: "dark", label: "Dark", icon: Moon },
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
    <SidebarProvider>
      <Sidebar collapsible="none" className="sticky top-0 h-svh border-r">
        <SidebarHeader>
          <div className="flex items-center gap-2.5 px-2 py-1.5">
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
                          isActive={t === tab}
                          aria-current={t === tab ? "page" : undefined}
                          onClick={() => setTab(t)}
                        >
                          <TabIcon />
                          {t}
                          {count[t] !== undefined && <SidebarMenuBadge>{count[t]}</SidebarMenuBadge>}
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
            variant="outline"
            size="sm"
            spacing={0}
            aria-label="Appearance"
            className="w-full"
            value={appearance}
            onValueChange={(v) => v && setAppearance(v as Appearance)}
          >
            {APPEARANCE.map((a) => (
              <ToggleGroupItem
                key={a.v}
                value={a.v}
                aria-label={a.label}
                title={`Appearance: ${a.label}`}
                className="flex-1"
              >
                <a.icon />
                {a.label}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          <p
            className="flex items-center gap-2 border-t px-1.5 pt-3 text-xs text-muted-foreground"
            data-up={!down && !!st}
          >
            {!down && !!st ? (
              <LiveDot pulse={false} />
            ) : (
              <span className="size-2 rounded-full bg-destructive" aria-hidden="true" />
            )}
            <span>
              <b className="font-semibold text-foreground">locksmithd</b> ·{" "}
              {down ? "not running" : st ? "running" : "connecting"}
            </span>
          </p>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset className="min-w-0 overflow-auto">
        {down ? (
          <section className="max-w-2xl px-7 pt-18" aria-labelledby="h-down">
            <span className="mb-5 grid size-12 place-items-center rounded-2xl bg-destructive/10 text-destructive">
              <Power className="size-5" />
            </span>
            <PageHeader title="The Locksmith daemon is not running" id="h-down" />
            <p className="mb-4 max-w-[64ch] text-muted-foreground">
              This window reads everything from <code>locksmithd</code>. Start it in a terminal; this window reconnects
              on its own within a few seconds.
            </p>
            <pre className="mb-4 rounded-lg border bg-card px-4 py-3">
              <code>locksmithd</code>
            </pre>
            <p className="text-[13px] text-muted-foreground">Detail: {down}</p>
          </section>
        ) : (
          <>
            <header
              className="sticky top-0 z-10 flex min-h-15 items-center gap-4 border-b bg-background/90 px-7 py-2.5 backdrop-blur"
              aria-label="Vault"
              data-open={open}
            >
              <div
                className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-3 gap-y-1"
                aria-live="polite"
                aria-atomic="true"
              >
                <span className="text-[15px] font-bold tracking-tight">Vault</span>
                {st ? (
                  <>
                    <b
                      className={`inline-flex items-center gap-1.5 font-semibold ${open ? "text-success" : "text-muted-foreground"}`}
                    >
                      {open ? (
                        <LiveDot pulse={false} />
                      ) : (
                        <span className="size-2 rounded-full border-[1.5px] border-current" aria-hidden="true" />
                      )}
                      {open ? "Unlocked" : "Locked"}
                    </b>
                    <span className="text-[13px] text-muted-foreground">
                      {open ? (
                        <span>{plural(live.length, "session")}</span>
                      ) : (
                        <span>Agents cannot start sessions or use keys</span>
                      )}
                      {since !== undefined && (
                        <span className="before:mx-1.5 before:content-['·']">
                          since{" "}
                          <time className="font-mono text-foreground" dateTime={new Date(since * 1000).toISOString()}>
                            {clock(since)}
                          </time>
                        </span>
                      )}
                    </span>
                  </>
                ) : (
                  <span className="text-[13px] text-muted-foreground">Reading the vault…</span>
                )}
                {note && <span className="text-[13px] font-semibold text-primary">{note}</span>}
              </div>
              {st && (
                <div className="flex flex-none gap-1.5">
                  <Button
                    type="button"
                    variant="ghost"
                    className="text-destructive"
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
            <div className="max-w-[1240px] px-7 pt-7 pb-10">
              {err && (
                <Alert variant="destructive" className="mb-4">
                  <CircleAlert />
                  {err}
                </Alert>
              )}
              <Screen st={st} act={act} go={setTab} />
            </div>
          </>
        )}
      </SidebarInset>
    </SidebarProvider>
  );
}
