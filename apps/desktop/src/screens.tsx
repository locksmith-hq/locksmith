import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import type {
  AuditEvent,
  AuditVerifyView,
  HttpTokenInfo,
  LeaseInfo,
  RelayInfo,
  SourceKind,
  StatusView,
} from "@locksmith/api-types";
import * as api from "./api";
import {
  ApiError,
  auditOutcomeMatches,
  bindingDetails,
  buildWorkloadIdentity,
  hasPrefixCondition,
  isPrefixPattern,
  type AuditOutcomeFilter,
  type Client,
  type Environment,
  type Project,
  type Secret,
  type SecretVersion,
} from "@locksmith/control-plane-client";
import {
  AppWindow,
  CircleHelp,
  Cloud,
  Code,
  Database,
  GitBranch,
  Globe,
  KeyRound,
  Loader as ClaudeRays,
  Play,
  Plus,
  RotateCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Ticket,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { Alert as KitAlert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Badge } from "@locksmith-hq/ui/badge";
import { Button } from "@locksmith-hq/ui/button";
import { Card, CardContent } from "@locksmith-hq/ui/card";
import { ConfirmDialog } from "@locksmith-hq/ui/confirm-dialog";
import { EmptyState } from "@locksmith-hq/ui/empty-state";
import { Facts } from "@locksmith-hq/ui/facts";
import { Field, FieldLabel } from "@locksmith-hq/ui/field";
import { Input } from "@locksmith-hq/ui/input";
import { LiveDot } from "@locksmith-hq/ui/live-dot";
import { Loader } from "@locksmith-hq/ui/loader";
import { PageHeader } from "@locksmith-hq/ui/page-header";
import { Pill } from "@locksmith-hq/ui/pill";
import { ScopeChip } from "@locksmith-hq/ui/scope-chip";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@locksmith-hq/ui/select";
import { SettingRow } from "@locksmith-hq/ui/setting-row";
import { Switch } from "@locksmith-hq/ui/switch";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";

import { InlineCode, LogFoot, Quiet, ROWS, SecCount, SecH, WHO } from "./ui";

export interface ScreenProps {
  st: StatusView | null;
  /** Runs an action, shows its rejection under the vault banner and refreshes status. */
  act: <T>(fn: () => Promise<T>, label?: (r: T) => string) => Promise<void>;
  /** Switches the main screen. */
  go: (
    tab: "Overview" | "Sessions" | "Keys" | "Tokens" | "Agents" | "Projects" | "Secrets" | "Relays" | "Audit",
  ) => void;
}

export const msg = (e: unknown) =>
  e && typeof e === "object" && "message" in e ? String((e as { message: unknown }).message) : String(e);
export const errCode = (e: unknown) =>
  e && typeof e === "object" && "code" in e ? String((e as { code: unknown }).code) : "";
export const plural = (n: number, word: string) => `${n} ${n === 1 ? word : `${word}s`}`;

const pad = (n: number) => String(n).padStart(2, "0");
export const clock = (ts: number) => {
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
};
const clockS = (ts: number) => `${clock(ts)}:${pad(new Date(ts * 1000).getSeconds())}`;
const stamp = (ts: number) => {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${clockS(ts)}`;
};
const left = (s: number) =>
  s <= 0
    ? "expired"
    : s < 60
      ? `${s}s`
      : s < 3600
        ? `${Math.floor(s / 60)}m`
        : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
/** The agent is the basename of the session command's first word: "/opt/homebrew/bin/codex exec" is "codex". */
const agent = (command: string) => command.trim().split(/\s+/)[0]!.split("/").pop() || command;
const nowSecs = () => Math.floor(Date.now() / 1000);
const isBad = (e: AuditEvent) =>
  e.decision.toUpperCase() === "DENY" || e.action === "BLOCKED" || e.action === "HOOK_DENY";
const kind = (e: AuditEvent) =>
  isBad(e) ? "blocked" : e.action === "REVOKE" || e.action === "TOKEN_REVOKE" ? "revoked" : "allowed";
const LABELS: Record<string, string> = {
  HOOK_DENY: "Blocked hook",
  BLOCKED: "Blocked",
  ACCESS: "Key used",
  TOKEN_ISSUE: "Token issued",
  TOKEN_REVOKE: "Token revoked",
  SESSION_START: "Session started",
  SESSION_END: "Session ended",
  REVOKE: "Revoked",
  EXPIRE: "Expired",
  SECRET_PUT: "Key saved",
  UNLOCK: "Vault unlocked",
  LOCK: "Vault locked",
  AWS_ISSUE: "AWS credentials issued",
};
/** Ledger actions in sentence case; unknown ones fall back to their own name, de-shouted. */
const label = (action: string) =>
  LABELS[action] ?? action[0]!.toUpperCase() + action.slice(1).toLowerCase().replace(/_/g, " ");
/** Ledger payloads break only after "/" and ":", never mid-token. */
const breakable = (s: string) =>
  s.split(/(?<=[/:])/).map((part, i) => (
    <Fragment key={i}>
      {i > 0 && <wbr />}
      {part}
    </Fragment>
  ));
const reducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
const STRIKE_MS = 480;
const SOON_S = 600;

/** Loads once per `deps` change and reports its own failure inline. */
function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState("");
  const load = useCallback(async () => {
    try {
      setData(await fn());
      setErr("");
    } catch (e) {
      setErr(msg(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    void load();
  }, [load]);
  return { data, err, load, alert: err ? <Alert>{err}</Alert> : null };
}

/** An error line. `role` can be cleared for a warning that is part of the page, not an announcement. */
const Alert = ({ children, ...props }: React.ComponentProps<typeof KitAlert>) => (
  <KitAlert variant="destructive" className="mb-4" {...props}>
    <TriangleAlert />
    <AlertDescription>{children}</AlertDescription>
  </KitAlert>
);
const Loading = ({ what }: { what: string }) => <Loader aria-busy="true">Reading {what}…</Loader>;
const Empty = EmptyState;
/** A one-line form: its fields and the button that submits it. */
const ROW = "mb-4 flex flex-wrap items-center gap-2 *:data-[slot=input]:w-56";
const STACK = "flex flex-col gap-3";

const SCOPE_ICONS: Record<string, LucideIcon> = { run: Play, git: GitBranch, http: Globe, db: Database, aws: Cloud };
const Scopes = ({ scopes }: { scopes: readonly string[] }) => (
  <ul
    className="m-0 flex list-none flex-wrap gap-1 p-0"
    aria-label={scopes.length ? `Scopes granted: ${scopes.join(", ")}` : "No scopes granted"}
  >
    {scopes.map((s) => {
      const ScopeIcon = SCOPE_ICONS[s] ?? KeyRound;
      return (
        <li key={s}>
          <ScopeChip icon={<ScopeIcon />}>{s}</ScopeChip>
        </li>
      );
    })}
  </ul>
);

export function Overview({ st, act, go }: ScreenProps) {
  // A wider window than the rows shown, so ended rows can find their REVOKE time.
  const ev = useLoad(() => api.auditList(40), [st]);
  const ver = useLoad(api.auditVerify, []);
  const cp = useCpCounts();
  const [striking, setStriking] = useState<string | null>(null);
  const now = nowSecs();
  const live = (st?.leases.filter((l) => l.state === "active") ?? []).sort((a, b) => a.expires_at - b.expires_at);
  const ended = st?.leases.filter((l) => l.state !== "active") ?? [];
  const events = [...(ev.data ?? [])].reverse().slice(0, 10);
  const leaseOf = (id: string | null) => st?.leases.find((l) => l.id === id);
  const revokeOne = async (id: string) => {
    if (!reducedMotion()) {
      setStriking(id);
      await new Promise((r) => setTimeout(r, STRIKE_MS));
    }
    await act(
      () => api.revoke(id),
      (n) => `Revoked ${plural(n, "session")}`,
    );
    setStriking(null);
  };
  return (
    <section className="max-w-[1120px]" aria-labelledby="h-overview">
      <h1 id="h-overview" className="sr-only">
        Overview
      </h1>

      <SecH tight>
        <h2>Sessions</h2>
        {st && (
          <SecCount>
            {live.length} active{ended.length > 0 && ` · ${ended.length} ended`}
          </SecCount>
        )}
      </SecH>
      {!st ? (
        <Loading what="sessions" />
      ) : (
        <Timeline
          live={live}
          ended={ended}
          events={ev.data ?? []}
          now={now}
          locked={st.locked}
          striking={striking}
          onRevoke={revokeOne}
        />
      )}

      {cp && (
        <section aria-label="Control plane counts">
          <SecH tight spaced>
            <h2>Control plane</h2>
          </SecH>
          <Quiet data-testid="cp-counts">
            Projects: <b data-testid="count-projects">{cp.projects ?? "n/a"}</b> · Agents:{" "}
            <b data-testid="count-agents">{cp.agents ?? "n/a"}</b>
          </Quiet>
        </section>
      )}

      <SecH tight spaced>
        <h2 id="h-events">Activity</h2>
        <Button type="button" variant="link" className="h-auto p-0" onClick={() => go("Audit")}>
          Open audit
        </Button>
      </SecH>
      {ev.alert}
      {!ev.data && !ev.err ? (
        <Loading what="the ledger" />
      ) : events.length === 0 ? (
        <Quiet>Nothing in the ledger yet.</Quiet>
      ) : (
        <ol className="m-0 list-none p-0" aria-labelledby="h-events">
          {events.map((e) => {
            const k = kind(e);
            const who = leaseOf(e.session_id);
            const target = e.target ?? "";
            return (
              <li key={e.seq} data-kind={k} className={LOG_ROW}>
                <time
                  className="font-mono text-xs text-muted-foreground"
                  dateTime={new Date(e.ts * 1000).toISOString()}
                  title={stamp(e.ts)}
                >
                  {clockS(e.ts)}
                </time>
                <span className={LOG_MARK} aria-hidden="true" />
                <span className={LOG_WHAT}>{label(e.action)}</span>
                <span data-slot="tgt" className={LOG_TGT} title={target}>
                  {target}
                </span>
                <span
                  className="min-w-0 truncate text-right text-[12.5px] text-muted-foreground"
                  title={e.session_id ?? e.actor_exe}
                >
                  {who ? (
                    <>
                      {agent(who.command)} <span className="font-mono text-xs">{e.session_id}</span>
                    </>
                  ) : e.session_id ? (
                    <span className="font-mono text-xs">{e.session_id}</span>
                  ) : (
                    e.actor_exe.split("/").pop()
                  )}
                </span>
              </li>
            );
          })}
        </ol>
      )}
      {ver.data &&
        (ver.data.broken_at === null ? (
          <LogFoot>
            <ShieldCheck />
            Ledger chain verified · {ver.data.events.toLocaleString("en-US")} entries
          </LogFoot>
        ) : (
          <LogFoot bad>
            <ShieldAlert />
            Ledger BROKEN at seq {ver.data.broken_at}
          </LogFoot>
        ))}
    </section>
  );
}

const LOG_ROW =
  "group grid min-h-[34px] grid-cols-[64px_8px_160px_minmax(0,1fr)_minmax(0,190px)] items-center gap-x-3 border-t px-2.5 text-[length:var(--font-size-sm)] last:border-b hover:bg-(--state-hover) max-[1100px]:grid-cols-[64px_8px_150px_minmax(0,1fr)_minmax(0,150px)]";
const LOG_MARK =
  "size-[7px] rounded-full bg-(--live) opacity-80 group-data-[kind=blocked]:size-2 group-data-[kind=blocked]:rotate-45 group-data-[kind=blocked]:rounded-[1px] group-data-[kind=blocked]:border-[1.5px] group-data-[kind=blocked]:border-(--warning) group-data-[kind=blocked]:bg-transparent group-data-[kind=blocked]:opacity-100 group-data-[kind=revoked]:h-0.5 group-data-[kind=revoked]:w-2 group-data-[kind=revoked]:rounded-[1px] group-data-[kind=revoked]:bg-(--destructive) group-data-[kind=revoked]:opacity-100";
const LOG_WHAT =
  "truncate font-medium group-data-[kind=blocked]:font-semibold group-data-[kind=blocked]:text-(--warning-text) group-data-[kind=revoked]:text-(--destructive-text)";
const LOG_TGT =
  "min-w-0 truncate font-mono text-xs text-muted-foreground group-data-[kind=blocked]:text-(--warning-text)";
/** The lease axis: every live lease on one shared axis from "now" to the latest expiry. */
const TL_LIST =
  "[--tl-cols:minmax(200px,260px)_156px_minmax(140px,1fr)_72px_76px] max-[1100px]:[--tl-cols:minmax(160px,200px)_152px_minmax(120px,1fr)_64px_70px]";
const TL_ROW = "grid min-h-[52px] grid-cols-(--tl-cols) items-center gap-x-4 border-t py-0 pr-1 pl-2.5";
/** The "now" rule is the left edge every lease starts from. */
const TL =
  "relative min-w-0 self-stretch before:absolute before:-bottom-px before:left-0 before:w-[1.5px] before:bg-(--brand) before:opacity-70 group-data-[state]:before:hidden";
const TICK_L = "absolute top-[5px] text-[11.5px] font-medium whitespace-nowrap";

/** Round clock steps for the lease axis, in seconds. */
const STEPS = [300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];

interface TimelineProps {
  live: LeaseInfo[];
  ended: LeaseInfo[];
  events: AuditEvent[];
  now: number;
  locked: boolean;
  striking: string | null;
  onRevoke: (id: string) => void;
}

/** Every live lease on one axis from now to the latest expiry, so who holds access and until when reads at a glance. */
function Timeline({ live, ended, events, now, locked, striking, onRevoke }: TimelineProps) {
  const span = Math.max(1800, ...live.map((l) => l.expires_at - now)) * 1.06;
  const step = STEPS.find((s) => span / s <= 5) ?? 86400;
  // shortcut: ticks align to UTC multiples of the step, so half-hour time zones see :30 labels on hourly steps; fine for a glance axis.
  const ticks: number[] = [];
  // Ticks too close to "now" or the right edge would collide with its label, so they are left out.
  for (let t = Math.ceil((now + 1) / step) * step; t < now + span; t += step)
    if ((t - now) / span > 0.12 && (t - now) / span < 0.95) ticks.push(t);
  const x = (t: number) => `${(Math.max(0, t - now) / span) * 100}%`;
  const grid = (top: string) =>
    ticks.map((t) => <i key={t} className={`absolute -bottom-px w-px bg-border ${top}`} style={{ left: x(t) }} />);
  const revokedAt = (id: string) => events.find((e) => e.action === "REVOKE" && e.target === id)?.ts;
  const endedLabel = (l: LeaseInfo) => {
    if (l.state === "expired") return `expired ${clock(l.expires_at)}`;
    const t = l.state === "revoked" ? revokedAt(l.id) : undefined;
    return t ? `revoked ${clock(t)}` : l.state;
  };
  return (
    <div className={TL_LIST} role="list" aria-label="Sessions">
      {live.length > 0 && (
        <div
          className={`${TL_ROW} min-h-[30px] border-t-0 text-[length:var(--font-size-xs)] text-muted-foreground`}
          aria-hidden="true"
        >
          <span>Agent</span>
          <span>Scopes</span>
          <span className={`${TL} h-[30px] before:top-[18px]`}>
            <b className={`${TICK_L} pl-1.5 font-semibold text-(--brand-text)`} style={{ left: 0 }}>
              now
            </b>
            {grid("top-[22px]")}
            {ticks.map((t) => (
              <b key={t} className={`${TICK_L} -translate-x-1/2 font-mono`} style={{ left: x(t) }}>
                {clock(t)}
              </b>
            ))}
          </span>
          <span className="text-right">Left</span>
          <span />
        </div>
      )}
      {live.length === 0 && (
        <div
          className="block min-h-[52px] border-t px-2.5 py-3.5 text-muted-foreground last:border-b [&_b]:font-semibold [&_b]:text-foreground"
          role="listitem"
        >
          {locked ? (
            <p>No sessions. The vault is locked, so no agent can start one until you unlock it.</p>
          ) : (
            <p>
              <b>No active sessions.</b> Agents get access only inside a session you start from a terminal:{" "}
              <InlineCode>smith session start -- &lt;agent&gt;</InlineCode>
            </p>
          )}
        </div>
      )}
      {live.map((l) => {
        const rest = l.expires_at - now;
        const soon = rest < SOON_S;
        const name = agent(l.command);
        return (
          <div
            key={l.id}
            role="listitem"
            className={`${TL_ROW} group transition-[background-color,opacity] duration-[120ms] last:border-b hover:bg-(--state-hover) focus-within:bg-(--state-hover) data-[striking]:opacity-50`}
            data-soon={soon || undefined}
            data-striking={striking === l.id || undefined}
            aria-label={`${name} session ${l.id}`}
          >
            <Who l={l} />
            <ScopeText scopes={l.scopes} />
            <span className={`${TL} before:top-0`} aria-hidden="true">
              {grid("top-0")}
              <span
                className="absolute top-1/2 left-0 -mt-[3px] h-1.5 rounded-r-[3px] bg-(--brand) opacity-85 group-data-[soon]:bg-(--warning) group-data-[soon]:opacity-100 group-data-[striking]:bg-(--destructive) after:absolute after:-top-1 after:-right-px after:h-3.5 after:w-0.5 after:rounded-[1px] after:bg-inherit"
                style={{ width: x(l.expires_at) }}
              />
            </span>
            <span
              className="text-right font-mono text-[12.5px] font-medium whitespace-nowrap group-data-[soon]:text-(--warning-text)"
              title={`Expires ${clock(l.expires_at)}`}
            >
              {left(rest)}
              <span className="sr-only"> left, expires {clock(l.expires_at)}</span>
            </span>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="justify-self-end text-(--destructive-text) opacity-0 group-hover:opacity-100 focus-visible:opacity-100"
              aria-label={`Revoke ${name} session ${l.id}`}
              disabled={striking !== null}
              onClick={() => onRevoke(l.id)}
            >
              Revoke
            </Button>
          </div>
        );
      })}
      {ended.length > 0 && (
        <div
          className="flex items-center gap-2.5 border-t border-input px-2.5 pt-3.5 pb-1 text-[length:var(--font-size-xs)] text-muted-foreground"
          role="presentation"
        >
          <span>Recently ended</span>
        </div>
      )}
      {ended.map((l) => (
        <div
          key={l.id}
          role="listitem"
          className={`${TL_ROW} group min-h-11 text-muted-foreground last:border-b`}
          data-state={l.state}
          aria-label={`${agent(l.command)} session ${l.id}, ${endedLabel(l)}`}
        >
          <Who l={l} struck />
          <ScopeText scopes={l.scopes} />
          <span
            data-slot="end"
            className="min-w-0 self-center font-mono text-xs group-data-[state=revoked]:text-(--destructive-text)"
          >
            {endedLabel(l)}
          </span>
          <span />
          <span />
        </div>
      ))}
    </div>
  );
}

const Who = ({ l, struck }: { l: LeaseInfo; struck?: boolean }) => {
  const name = agent(l.command);
  return (
    <span className="flex min-w-0 flex-col gap-px" title={l.command}>
      <span className="flex min-w-0 items-baseline gap-2 text-foreground">
        <SourceMark kind={l.source.kind} />
        {struck ? (
          <s data-slot="who-name" className="font-medium text-muted-foreground decoration-[1.5px]">
            {name}
          </s>
        ) : (
          <b
            data-slot="who-name"
            className="bg-[linear-gradient(var(--destructive),var(--destructive))] bg-[position:0_55%] bg-no-repeat bg-[size:0_1.5px] font-semibold transition-[background-size] duration-500 ease-(--ease-out) group-data-[striking]:bg-[size:100%_1.5px]"
          >
            {name}
          </b>
        )}
        <span className="truncate font-mono text-[11px] text-muted-foreground">{l.id}</span>
      </span>
      <span className={WHO_LINE}>
        {l.project} / <Env env={l.env} />
      </span>
      {(l.report?.model ?? l.report?.agent) || l.started_by === "agent" ? (
        <span className={`${WHO_LINE} flex gap-1`}>
          <span className="flex-none">{l.source.label} ·</span> <ReportedModel l={l} wide />
        </span>
      ) : null}
    </span>
  );
};

const WHO_LINE = "truncate text-[12.5px] leading-[17px] text-muted-foreground";
/** The environment name; production is called out. */
const Env = ({ env }: { env: string }) => (
  <span className={env === "production" ? "text-(--warning-text)" : undefined}>{env}</span>
);

const ScopeText = ({ scopes }: { scopes: readonly string[] }) => (
  <ul
    className="m-0 flex list-none flex-nowrap overflow-hidden p-0 font-mono text-xs whitespace-nowrap text-(--chip-text) group-data-[state]:text-muted-foreground [&>li+li]:before:mx-[5px] [&>li+li]:before:text-muted-foreground [&>li+li]:before:content-['·']"
    aria-label={scopes.length ? `Scopes granted: ${scopes.join(", ")}` : "No scopes granted"}
  >
    {scopes.map((s) => (
      <li key={s}>{s}</li>
    ))}
  </ul>
);

const SOURCE_GLYPH: Record<SourceKind, LucideIcon> = {
  claude_code_cli: Terminal,
  codex: Terminal,
  gemini_cli: Terminal,
  aider: Terminal,
  opencode: Terminal,
  grok: Terminal,
  claude_desktop_app: AppWindow,
  cursor: Code,
  windsurf: Code,
  vscode: Code,
  jetbrains: Code,
  copilot: Code,
  other: Sparkles,
  unknown: CircleHelp,
};
const isClaude = (k: SourceKind) => k === "claude_code_cli" || k === "claude_desktop_app";
/** Source glyph; the two Claude kinds get the Claude mark, labelled so it is findable and announced. */
const SourceMark = ({ kind }: { kind: SourceKind }) => {
  const Glyph = SOURCE_GLYPH[kind] ?? CircleHelp;
  return isClaude(kind) ? (
    <span
      className="inline-flex self-center text-[#d97757] [&>svg]:size-3.5"
      role="img"
      aria-label="Claude"
      title="Claude"
    >
      <ClaudeRays />
    </span>
  ) : (
    <Glyph className="size-3.5 flex-none self-center" />
  );
};
/** The agent's own model claim with its 'unverified' tooltip; nothing for a human-started session that reported none. */
const ReportedModel = ({ l, wide }: { l: LeaseInfo; wide?: boolean }) => {
  const claim = l.report?.model ?? l.report?.agent;
  const text = claim ? `${claim} (reported by agent)` : l.started_by === "agent" ? "model not reported" : null;
  return (
    text && (
      <span
        className={`${claim ? "cursor-help border-b border-dotted border-muted-foreground" : "text-muted-foreground"} ${wide ? "min-w-0 flex-1 basis-0 truncate" : "inline-block max-w-[22ch] truncate align-bottom"}`}
        title={`${text}. ${SELF_REPORTED}`}
      >
        {text}
      </span>
    )
  );
};
const SELF_REPORTED = "Self-reported by the agent and unverified. Locksmith never uses it to decide anything.";
const useNow = () => {
  const [n, setN] = useState(nowSecs);
  useEffect(() => {
    const t = setInterval(() => setN(nowSecs()), 1000);
    return () => clearInterval(t);
  }, []);
  return n;
};

export function Sessions({ st, act }: ScreenProps) {
  const now = useNow();
  const [open, setOpen] = useState<string | null>(null);
  const all = st?.leases ?? [];
  const live = all.filter((l) => l.state === "active").sort((a, b) => a.expires_at - b.expires_at);
  const ended = all.filter((l) => l.state !== "active").sort((a, b) => b.expires_at - a.expires_at);
  const row = (l: LeaseInfo) => {
    const active = l.state === "active";
    const r = l.report;
    const rest = l.expires_at - now;
    const name = l.source.label;
    return (
      <li key={l.id} data-state={l.state} data-open={open === l.id || undefined}>
        <div className="grid grid-cols-[minmax(0,1fr)_auto_72px_76px] items-center gap-3.5 py-2.5 pr-4 pl-2 max-[760px]:grid-cols-[minmax(0,1fr)_auto] max-[760px]:[&>ul]:hidden">
          <Button
            type="button"
            variant="ghost"
            className="h-auto min-w-0 justify-start gap-3 px-2 py-1 text-left font-normal"
            aria-expanded={open === l.id}
            aria-label={`${name} session ${l.id}`}
            onClick={() => setOpen(open === l.id ? null : l.id)}
          >
            <span className="grid size-8 flex-none place-items-center rounded-md bg-muted" data-kind={l.source.kind}>
              <SourceMark kind={l.source.kind} />
            </span>
            <span className="grid min-w-0 gap-0.5">
              <span className="flex min-w-0 items-baseline gap-2 truncate text-foreground">
                <b data-slot="who-name" className={active ? "font-semibold" : "font-medium text-muted-foreground"}>
                  {name}
                </b>
                {l.host && <span className="text-muted-foreground"> in {l.host}</span>}
                <Badge variant={l.started_by === "agent" ? "default" : "secondary"} className="ml-2">
                  {l.started_by === "agent" ? "Agent started" : "Human started"}
                </Badge>
              </span>
              <span className={WHO_LINE}>
                {l.project} / <Env env={l.env} />
                {(l.report?.model ?? l.report?.agent) || l.started_by === "agent" ? (
                  <>
                    {" "}
                    · <ReportedModel l={l} />
                  </>
                ) : null}
              </span>
            </span>
          </Button>
          <Scopes scopes={l.scopes} />
          <span data-slot="left" className="text-right font-mono text-[12.5px] font-medium whitespace-nowrap">
            {active ? (
              <>
                {left(rest)}
                <span className="sr-only"> left, expires {clock(l.expires_at)}</span>
              </>
            ) : (
              l.state
            )}
          </span>
          {active ? (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="text-(--destructive-text)"
              aria-label={`Revoke ${name} session ${l.id}`}
              onClick={() =>
                act(
                  () => api.revoke(l.id),
                  (n) => `Revoked ${plural(n, "session")}`,
                )
              }
            >
              Revoke
            </Button>
          ) : (
            <span />
          )}
        </div>
        {open === l.id && (
          <Facts
            className="px-4 pt-1 pb-3.5 pl-15"
            items={[
              { label: "Session", value: mono(l.id) },
              { label: "Command", value: mono(l.command) },
              { label: "Root", value: mono(`${l.root_exe || "unknown"} · pid ${l.root_pid}`) },
              { label: "Created", value: mono(stamp(l.created_at)) },
              { label: active ? "Expires" : "Expired or ended", value: mono(stamp(l.expires_at)) },
              ...(l.inject
                ? [
                    {
                      label: "Keys",
                      value: `${l.inject.length ? `${l.inject.join(", ")} (${l.inject.length} injectable)` : "none injectable"}; every other key is relay-only`,
                    },
                  ]
                : []),
              ...(r && (r.agent || r.model)
                ? [
                    {
                      label: "Reported",
                      value: (
                        <span title={SELF_REPORTED}>
                          {[r.agent, r.model].filter(Boolean).join(" · ")} (reported by agent, unverified)
                        </span>
                      ),
                    },
                  ]
                : []),
            ]}
          />
        )}
      </li>
    );
  };
  return (
    <section aria-label="Sessions">
      <PageHeader
        title="Sessions"
        lede="Every agent that has been given access, who started it and when it runs out."
      />
      {!st ? (
        <Loading what="sessions" />
      ) : all.length === 0 ? (
        <Empty title={st.locked ? "No sessions." : "No sessions yet."}>
          {st.locked ? (
            "The vault is locked, so no agent can start one until you unlock it."
          ) : (
            <>
              Agents get access only inside a session: start one with{" "}
              <InlineCode>smith session start -- &lt;agent&gt;</InlineCode>
            </>
          )}
        </Empty>
      ) : (
        <>
          {live.length > 0 && (
            <ul className={ROWS} aria-label="Active sessions">
              {live.map(row)}
            </ul>
          )}
          {ended.length > 0 && (
            <>
              <SecH spaced>
                <h2>Recently ended</h2>
              </SecH>
              <ul className={ROWS} aria-label="Ended sessions">
                {ended.map(row)}
              </ul>
            </>
          )}
          <LogFoot>
            Source and host are hints read from process names and paths. Any process running as you can imitate them.
          </LogFoot>
        </>
      )}
    </section>
  );
}

const mono = (v: string) => <span className="font-mono text-xs break-all">{v}</span>;
const uniq = (xs: string[]) => [...new Set(xs)];

export function Keys({ st }: ScreenProps) {
  const tokens = useLoad(api.tokenList, []);
  const live = st?.leases.filter((l) => l.state === "active") ?? [];
  const seen = [...(st?.leases ?? []), ...(tokens.data ?? [])];
  // Until the user picks, follow the first live session's project and environment.
  const [pickedProject, setProject] = useState<string | null>(null);
  const [pickedEnv, setEnv] = useState<string | null>(null);
  const project = pickedProject ?? live[0]?.project ?? "default";
  const env = pickedEnv ?? live[0]?.env ?? "development";
  const users = live.filter((l) => l.project === project && l.env === env && l.scopes.includes("run"));
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const names = useLoad(() => api.keyNames(project, env), [project, env]);
  const put = async (key: string) => {
    setErr("");
    setNote("");
    try {
      const r = await api.putSecretSecure(project, env, key);
      setNote(r === "submitted" ? `Key ${key} saved.` : `Key ${key}: cancelled, nothing changed.`);
      if (key === name.trim()) setName("");
    } catch (x) {
      setErr(msg(x));
    }
    await names.load();
  };
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    void put(name.trim());
  };
  return (
    <section aria-label="Keys">
      <PageHeader
        title="Keys"
        lede="Key names only. Values go in and out through a native Locksmith prompt, never this window."
      />
      <div className="mb-4 flex flex-wrap items-end gap-4">
        <Field className="w-56">
          <FieldLabel htmlFor="k-project">Project</FieldLabel>
          <Input
            id="k-project"
            list="dl-projects"
            value={project}
            onChange={(e) => setProject(e.target.value)}
            spellCheck={false}
          />
        </Field>
        <Field className="w-56">
          <FieldLabel htmlFor="k-env">Environment</FieldLabel>
          <Input id="k-env" list="dl-envs" value={env} onChange={(e) => setEnv(e.target.value)} spellCheck={false} />
        </Field>
        <datalist id="dl-projects">
          {uniq(seen.map((x) => x.project)).map((v) => (
            <option key={v} value={v} />
          ))}
        </datalist>
        <datalist id="dl-envs">
          {uniq(seen.map((x) => x.env)).map((v) => (
            <option key={v} value={v} />
          ))}
        </datalist>
        {users.length > 0 && (
          <p className="mb-2 flex items-center gap-2.5 text-[13px]">
            <LiveDot aria-hidden="true" />
            <span>
              Usable now by{" "}
              {users.map((l, i) => (
                <Fragment key={l.id}>
                  {i > 0 && ", "}
                  <span className="font-mono text-xs">{l.id}</span> ({agent(l.command)})
                </Fragment>
              ))}
              <span className="text-muted-foreground">
                {" "}
                · sessions on {project} / {env} with <InlineCode>run</InlineCode> scope
              </span>
            </span>
          </p>
        )}
      </div>
      {names.alert}
      {err && <Alert>{err}</Alert>}
      {!names.data && !names.err ? (
        <Loading what="key names" />
      ) : names.data?.length === 0 ? (
        <Empty title={`No keys in ${project} / ${env} yet.`}>Add the first one below.</Empty>
      ) : (
        names.data && (
          <ul className={`${ROWS} mb-5`} aria-label={`Key names in ${project} / ${env}`}>
            {names.data.map((n) => (
              <li key={n} className="flex items-center gap-3.5 px-4 py-2.5">
                <KeyRound className="size-4 flex-none text-muted-foreground" />
                <span className="mr-auto font-mono text-[13px] font-semibold">{n}</span>
                <Button type="button" variant="outline" size="sm" aria-label={`Rotate ${n}`} onClick={() => put(n)}>
                  <RotateCw />
                  Rotate
                </Button>
              </li>
            ))}
          </ul>
        )
      )}

      <Card>
        <CardContent>
          <form className="flex flex-wrap items-end gap-4" onSubmit={submit} aria-labelledby="h-add">
            <div className="mr-auto">
              <h2 id="h-add" className="text-base font-semibold">
                Add or rotate a key
              </h2>
              <p className="text-[13px] text-muted-foreground">
                The value is typed into a native Locksmith prompt, never into this window.
              </p>
            </div>
            <Field className="w-64">
              <FieldLabel htmlFor="k-name">Key name</FieldLabel>
              <Input
                id="k-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                spellCheck={false}
                placeholder="e.g. NPM_TOKEN"
              />
            </Field>
            <Button type="submit" disabled={!name.trim()}>
              <Plus />
              Add or rotate key
            </Button>
          </form>
        </CardContent>
      </Card>
      <p aria-live="polite" className="mt-3 min-h-5 font-semibold text-(--live-text)">
        {note}
      </p>
    </section>
  );
}

export function Tokens({ st }: ScreenProps) {
  const t = useLoad(api.tokenList, []);
  const [err, setErr] = useState("");
  const scopes = (lease: string) => st?.leases.find((l) => l.id === lease && l.state === "active")?.scopes;
  const revokeToken = async (x: HttpTokenInfo) => {
    setErr("");
    try {
      await api.tokenRevoke(x.prefix);
    } catch (e) {
      setErr(msg(e));
    }
    await t.load();
  };
  return (
    <section aria-label="Tokens">
      <PageHeader
        title="Tokens"
        lede={
          <>
            Opaque <InlineCode>lsk_</InlineCode> tokens stand in for a key on one host. Only the prefix is shown.
          </>
        }
      />
      {t.alert}
      {err && <Alert>{err}</Alert>}
      {!t.data && !t.err ? (
        <Loading what="tokens" />
      ) : t.data?.length === 0 ? (
        <Empty title="No live tokens.">
          Inside a session, mint one with <InlineCode>smith token issue &lt;KEY&gt; --provider &lt;name&gt;</InlineCode>
        </Empty>
      ) : (
        t.data && (
          <div className={STACK}>
            {t.data.map((x) => {
              const sc = scopes(x.lease);
              return (
                <Card key={x.prefix} role="article" aria-label={`Token ${x.prefix}`}>
                  <CardContent className="grid grid-cols-[16px_minmax(160px,1fr)_minmax(160px,1fr)_minmax(180px,1.1fr)_auto] items-center gap-3.5">
                    <Ticket className="size-4 text-muted-foreground" aria-hidden="true" />
                    <div className={WHO}>
                      <b className="font-mono text-xs">{x.prefix}</b>
                      <span className="font-mono text-xs" title={x.key}>
                        {x.key}
                      </span>
                    </div>
                    <div className={WHO}>
                      <b className="flex-wrap">
                        {x.hosts.map((h) => (
                          <span key={h} className="font-mono text-xs">
                            {h}
                          </span>
                        ))}
                      </b>
                      <span>
                        <span className="font-mono text-xs">{x.placement}</span> · {stamp(x.created_at).slice(5, 16)}
                      </span>
                    </div>
                    <div className={WHO}>
                      {sc ? <Scopes scopes={sc} /> : <b className="text-muted-foreground">Session ended</b>}
                      <span title={`${x.project} / ${x.env} · ${x.lease}`}>
                        {x.project} / {x.env} · <span className="font-mono text-xs">{x.lease}</span>
                      </span>
                    </div>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      aria-label={`Revoke token ${x.prefix}`}
                      onClick={() => revokeToken(x)}
                    >
                      Revoke
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )
      )}
    </section>
  );
}

// Only commands that exist in crates/smith-cli (git_cmd.rs, http_cmd.rs, run_cmd.rs, db_cmd.rs).
const RELAYS: {
  key: keyof Pick<RelayInfo, "git_port" | "http_port" | "aws_port"> | null;
  name: string;
  icon: string;
  Glyph: LucideIcon;
  setup: string[];
}[] = [
  { key: "git_port", name: "Git forwarder", icon: "git", Glyph: GitBranch, setup: ["smith git setup"] },
  {
    key: "http_port",
    name: "HTTP relay",
    icon: "http",
    Glyph: Globe,
    setup: ["smith token issue <KEY> --provider <name>", "smith http status"],
  },
  {
    key: "aws_port",
    name: "AWS SigV4 relay",
    icon: "aws",
    Glyph: Cloud,
    setup: ["smith run --aws <profile> -- <command>"],
  },
  { key: null, name: "Database relay", icon: "db", Glyph: Database, setup: ["smith db connect <name> -- <command>"] },
];

export function Relays(_: ScreenProps) {
  const r = useLoad(api.relayInfo, []);
  const info = r.data;
  return (
    <section aria-label="Relays">
      <PageHeader
        title="Relays"
        lede="Each relay signs or forwards requests on an agent's behalf; the key stays in Locksmith."
      />
      {r.alert}
      {!info && !r.err ? (
        <Loading what="relays" />
      ) : (
        info && (
          <>
            <div className="grid grid-cols-2 gap-3">
              {RELAYS.map((x) => {
                const port = x.key && info[x.key];
                const up = !x.key || port != null;
                return (
                  <Card key={x.name} role="article" aria-labelledby={`relay-${x.icon}`}>
                    <CardContent className="flex flex-col gap-2.5">
                      <div className="flex items-center gap-3">
                        <x.Glyph className="size-4 text-muted-foreground" aria-hidden="true" />
                        <h2 id={`relay-${x.icon}`} className="mr-auto text-[15px] font-semibold">
                          {x.name}
                        </h2>
                        <Pill tone={up ? "live" : undefined}>
                          {!x.key ? (
                            "Per target"
                          ) : port == null ? (
                            "Not running"
                          ) : (
                            <>
                              Port <span className="font-mono text-xs">{port}</span>
                            </>
                          )}
                        </Pill>
                      </div>
                      <div className="flex flex-col items-start gap-1.5">
                        {x.setup.map((c) => (
                          <InlineCode cmd key={c}>
                            {c}
                          </InlineCode>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
            <SecH spaced>
              <h2>Explicit-proxy CA hosts</h2>
              <SecCount>{info.ca_hosts.length}</SecCount>
            </SecH>
            {info.ca_hosts.length === 0 ? (
              <Empty title="No hosts use the Locksmith CA." />
            ) : (
              <ul className="m-0 flex list-none flex-wrap gap-1 p-0">
                {info.ca_hosts.map((h) => (
                  <li key={h}>
                    <ScopeChip icon={<Globe />}>{h}</ScopeChip>
                  </li>
                ))}
              </ul>
            )}
          </>
        )
      )}
    </section>
  );
}

export function Audit(_: ScreenProps) {
  const ev = useLoad(() => api.auditList(200), []);
  const [filter, setFilter] = useState("");
  const [ver, setVer] = useState<AuditVerifyView | null>(null);
  const [err, setErr] = useState("");
  const q = filter.trim().toLowerCase();
  const rows = [...(ev.data ?? [])].reverse().filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q));
  const verify = async () => {
    setErr("");
    try {
      setVer(await api.auditVerify());
    } catch (e) {
      setErr(msg(e));
    }
  };
  return (
    <section aria-label="Audit">
      <PageHeader title="Audit" lede="Every access, block and change, newest first, in a hash-chained ledger.">
        <Input
          type="search"
          aria-label="Filter"
          className="w-80"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          spellCheck={false}
          placeholder="Filter by action, key, host or session"
        />
        <Button type="button" variant="outline" onClick={verify}>
          <ShieldCheck />
          Verify ledger
        </Button>
      </PageHeader>
      <div aria-live="assertive">
        {ver &&
          (ver.broken_at === null ? (
            <KitAlert role={undefined} className="mb-4">
              <ShieldCheck />
              <AlertDescription>Ledger intact: {ver.events} events checked, hash chain unbroken.</AlertDescription>
            </KitAlert>
          ) : (
            <KitAlert role={undefined} variant="destructive" className="mb-4">
              <ShieldAlert />
              <AlertDescription>
                Ledger BROKEN at seq {ver.broken_at}. {ver.detail}
              </AlertDescription>
            </KitAlert>
          ))}
      </div>
      {ev.alert}
      {err && <Alert>{err}</Alert>}
      {!ev.data && !ev.err ? (
        <Loading what="the ledger" />
      ) : rows.length === 0 ? (
        <Empty
          kind={q ? "no-results" : "first-use"}
          title={q ? "No events match this filter." : "Nothing in the ledger yet."}
        />
      ) : (
        <Table>
          <TableCaption className="sr-only">Audit events, newest first</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead className="text-right">Seq</TableHead>
              <TableHead>Time</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Decision</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Rule</TableHead>
              <TableHead>Session</TableHead>
              <TableHead>Actor</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((e) => (
              <TableRow key={e.seq} data-bad={isBad(e)}>
                <TableCell className="text-right font-mono text-xs text-muted-foreground">{e.seq}</TableCell>
                <TableCell className="font-mono text-xs whitespace-nowrap">{stamp(e.ts)}</TableCell>
                <TableCell className="font-semibold">{e.action}</TableCell>
                <TableCell>
                  <span className="text-xs font-semibold tracking-wide text-muted-foreground">{e.decision}</span>
                </TableCell>
                <TableCell className="font-mono text-xs min-w-[200px] break-words">
                  {breakable(e.target ?? "")}
                </TableCell>
                <TableCell className="font-mono text-xs">{e.policy_rule}</TableCell>
                <TableCell className="font-mono text-xs">{e.session_id ?? ""}</TableCell>
                <TableCell className="font-mono text-xs" title={e.actor_exe}>
                  {e.actor_exe.split("/").pop()}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  );
}

/** Agents and their grants, from the control plane. Create shows the enrollment secret once. */
export function Agents(_: ScreenProps) {
  const [cfg, setCfg] = useState({ url: api.controlPlane.url(), org: api.controlPlane.org() });
  const [client, setClient] = useState(api.agentsClient);
  const [agents, setAgents] = useState<api.Agent[] | null>(null);
  const [grants, setGrants] = useState<Record<string, api.AgentGrant[]>>({});
  const [err, setErr] = useState("");
  // Component state only: never stored or logged, gone when dismissed.
  const [secret, setSecret] = useState<{ agent: string; value: string } | null>(null);
  const [name, setName] = useState("");
  const [secretId, setSecretId] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    if (!client) return;
    try {
      const list = await client.listAgents();
      const g = await Promise.all(list.map((a) => client.listGrants(a.id)));
      setAgents(list);
      setGrants(Object.fromEntries(list.map((a, i) => [a.id, g[i]!])));
    } catch (e) {
      setErr(msg(e));
    }
  }, [client]);
  useEffect(() => {
    void load();
  }, [load]);

  const run = async (f: () => Promise<void>) => {
    setErr("");
    try {
      await f();
    } catch (e) {
      setErr(msg(e));
    }
    await load();
  };

  return (
    <section aria-label="Agents">
      <PageHeader
        title="Agents"
        lede="Agents use secrets through the gateway without ever holding them. Grants say which secrets an agent may relay."
      />
      <form
        className={ROW}
        aria-label="Control plane"
        onSubmit={(e) => {
          e.preventDefault();
          api.controlPlane.save(cfg.url, cfg.org);
          setAgents(null);
          setClient(api.agentsClient());
        }}
      >
        <Input
          aria-label="Control plane URL"
          placeholder="Control plane URL"
          value={cfg.url}
          onChange={(e) => setCfg({ ...cfg, url: e.target.value.trim() })}
        />
        <Input
          aria-label="Org id"
          placeholder="Org id"
          value={cfg.org}
          onChange={(e) => setCfg({ ...cfg, org: e.target.value.trim() })}
        />
        <Button type="submit" variant="outline" size="sm">
          Connect
        </Button>
      </form>
      {err && <Alert>{err}</Alert>}
      {!client ? (
        <Empty title="Enter an org id to list agents." />
      ) : (
        <>
          {secret && (
            <Card className="mb-4" role="region" aria-label="Enrollment secret">
              <CardContent className="flex flex-col items-start gap-2">
                <p>Enrollment secret for {secret.agent}. It is shown once and cannot be retrieved again.</p>
                <InlineCode cmd data-testid="enrollment-secret">
                  {secret.value}
                </InlineCode>
                <Button type="button" variant="outline" size="sm" onClick={() => setSecret(null)}>
                  Dismiss
                </Button>
              </CardContent>
            </Card>
          )}
          <form
            className={ROW}
            aria-label="Create agent"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                const r = await client.createAgent({ name, description: "" });
                setSecret({ agent: r.agent.name, value: r.enrollment_secret });
                setName("");
              });
            }}
          >
            <Input
              aria-label="Agent name"
              placeholder="Agent name"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <Button type="submit" size="sm">
              Create agent
            </Button>
          </form>
          {!agents ? (
            <Loading what="agents" />
          ) : agents.length === 0 ? (
            <Empty title="No agents yet." />
          ) : (
            <div className={STACK}>
              {agents.map((a) => (
                <Card key={a.id} role="article" aria-label={`Agent ${a.name}`}>
                  <CardContent className="flex flex-col items-start gap-2.5">
                    <div className={WHO}>
                      <b>{a.name}</b>
                      <span className="font-mono text-xs">{a.id}</span>
                    </div>
                    <ul>
                      {(grants[a.id] ?? []).map((g) => (
                        <li key={g.id}>
                          <span className="font-mono text-xs">{g.secret_name}</span> ({g.mode}){" "}
                          {g.expires_at ? `expires ${g.expires_at}` : "no expiry"}
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="text-(--destructive-text)"
                            aria-label={`Revoke ${g.secret_name} for ${a.name}`}
                            onClick={() => void run(() => client.revokeGrant(a.id, g.id))}
                          >
                            Revoke
                          </Button>
                        </li>
                      ))}
                    </ul>
                    <form
                      className="flex flex-wrap items-center gap-2 *:data-[slot=input]:w-56"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void run(async () => {
                          await client.createGrant(a.id, {
                            secret_id: secretId[a.id] ?? "",
                            mode: "relay",
                            expires_at: null,
                          });
                          setSecretId({ ...secretId, [a.id]: "" });
                        });
                      }}
                    >
                      <Input
                        aria-label={`Secret id for ${a.name}`}
                        placeholder="Secret id"
                        required
                        value={secretId[a.id] ?? ""}
                        onChange={(e) => setSecretId({ ...secretId, [a.id]: e.target.value.trim() })}
                      />
                      <Button type="submit" variant="outline" size="sm">
                        Grant
                      </Button>
                    </form>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      aria-label={`Delete ${a.name}`}
                      onClick={() => void run(() => client.deleteAgent(a.id))}
                    >
                      Delete agent
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}

/** Trust policies that let a CI job or cluster workload swap its own OIDC token for an agent token. No secret anywhere. */
export function WorkloadIdentities(_: ScreenProps) {
  const client = api.agentsClient();
  const [items, setItems] = useState<api.WorkloadIdentity[] | null>(null);
  const [err, setErr] = useState("");
  const [confirming, setConfirming] = useState<string | null>(null);
  const [preset, setPreset] = useState<api.WorkloadPreset>("github");
  const [f, setF] = useState({
    name: "",
    agentId: "",
    audience: "",
    issuer: "",
    repository: "",
    ref: "",
    environment: "",
    namespace: "",
    serviceaccount: "",
  });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  const load = useCallback(async () => {
    if (!client) return;
    try {
      setItems(await client.listWorkloadIdentities());
    } catch (e) {
      setErr(msg(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  const body = buildWorkloadIdentity({ ...f, preset });
  const run = async (fn: () => Promise<unknown>) => {
    setErr("");
    try {
      await fn();
    } catch (e) {
      setErr(msg(e));
    }
    await load();
  };

  return (
    <section aria-label="Workload identities">
      <PageHeader
        title="Workload identities"
        lede="A CI job or cluster workload exchanges its own OIDC token for a short-lived agent token. Nothing secret is entered or shown here."
      />
      {err && <Alert>{err}</Alert>}
      {!client ? (
        <Empty title="Connect a control plane and org id on the Agents screen first." />
      ) : (
        <>
          <form
            className={ROW}
            aria-label="Create workload identity"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                await client.createWorkloadIdentity(body);
                setF({ ...f, name: "", repository: "", ref: "", environment: "", namespace: "", serviceaccount: "" });
              });
            }}
          >
            <Select value={preset} onValueChange={(v) => setPreset(v as api.WorkloadPreset)}>
              <SelectTrigger aria-label="Issuer preset">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="github">GitHub Actions</SelectItem>
                <SelectItem value="kubernetes">Kubernetes</SelectItem>
              </SelectContent>
            </Select>
            <Input aria-label="Policy name" placeholder="Policy name" required value={f.name} onChange={set("name")} />
            <Input
              aria-label="Agent id"
              placeholder="Agent id"
              required
              value={f.agentId}
              onChange={(e) => setF({ ...f, agentId: e.target.value.trim() })}
            />
            <Input
              aria-label="Audience"
              placeholder="Audience"
              required
              value={f.audience}
              onChange={set("audience")}
            />
            {preset === "github" ? (
              <>
                <Input
                  aria-label="Repository (owner/repo)"
                  placeholder="Repository (owner/repo)"
                  required
                  value={f.repository}
                  onChange={set("repository")}
                />
                <Input aria-label="Ref (optional)" placeholder="Ref (optional)" value={f.ref} onChange={set("ref")} />
                <Input
                  aria-label="Environment (optional)"
                  placeholder="Environment (optional)"
                  value={f.environment}
                  onChange={set("environment")}
                />
              </>
            ) : (
              <>
                <Input
                  aria-label="Issuer URL"
                  placeholder="Issuer URL"
                  type="url"
                  required
                  value={f.issuer}
                  onChange={set("issuer")}
                />
                <Input
                  aria-label="Namespace"
                  placeholder="Namespace"
                  required
                  value={f.namespace}
                  onChange={set("namespace")}
                />
                <Input
                  aria-label="Service account"
                  placeholder="Service account"
                  required
                  value={f.serviceaccount}
                  onChange={set("serviceaccount")}
                />
              </>
            )}
            {hasPrefixCondition(body.conditions) && (
              <Alert className="mb-0 basis-full" data-testid="prefix-warning">
                A condition ends in * and matches every value with that prefix. Prefer exact values.
              </Alert>
            )}
            <Button type="submit" size="sm">
              Create workload identity
            </Button>
          </form>
          {!items ? (
            <Loading what="workload identities" />
          ) : items.length === 0 ? (
            <Empty title="No workload identities yet." />
          ) : (
            <div className={STACK}>
              {items.map((w) => (
                <Card key={w.id} role="article" aria-label={`Workload identity ${w.name}`}>
                  <CardContent className="flex flex-col items-start gap-2.5">
                    <div className={WHO}>
                      <b>{w.name}</b>
                      <span className="font-mono text-xs">
                        {w.issuer_kind} {w.issuer}
                      </span>
                    </div>
                    <p>
                      Handle: <InlineCode className="font-mono">{w.handle}</InlineCode> (not a secret) · audience{" "}
                      {w.audience} · agent <span className="font-mono text-xs">{w.agent_id}</span> · last used{" "}
                      {w.last_used_at ?? "never"}
                    </p>
                    <ul>
                      {w.conditions.map((c) => (
                        <li key={`${c.claim}=${c.pattern}`}>
                          <span className="font-mono text-xs">
                            {c.claim} = {c.pattern}
                          </span>
                          {isPrefixPattern(c) ? " (prefix match)" : ""}
                        </li>
                      ))}
                    </ul>
                    {hasPrefixCondition(w.conditions) && (
                      <Alert role={undefined} className="mb-0">
                        This policy uses a prefix (*) condition.
                      </Alert>
                    )}
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="text-(--destructive-text)"
                      onClick={() => setConfirming(w.id)}
                    >
                      Delete {w.name}
                    </Button>
                    <ConfirmDialog
                      open={confirming === w.id}
                      danger
                      title={`Delete ${w.name}?`}
                      confirmLabel={`Confirm delete ${w.name}`}
                      onClose={() => setConfirming(null)}
                      onConfirm={() => void run(() => client.deleteWorkloadIdentity(w.id))}
                    />
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}

/** The org's control-plane audit ledger (events plus chain status), read-only. */

export function OrgAudit(_: ScreenProps) {
  const client = api.agentsClient();
  const [status, setStatus] = useState<api.AuditStatus | null>(null);
  const [events, setEvents] = useState<api.OrgAuditEvent[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const inflight = useRef(false);
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState<AuditOutcomeFilter>("all");

  useEffect(() => {
    if (!client) return;
    client.auditStatus().then(setStatus, (e) => setErr(msg(e)));
    client.listAuditEvents().then(
      (p) => {
        setEvents(p.items);
        setNext(p.next ?? null);
      },
      (e) => setErr(msg(e)),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const more = () => {
    if (!client || inflight.current || !next) return;
    inflight.current = true;
    setLoadingMore(true);
    client
      .listAuditEvents({ cursor: next })
      .then(
        (p) => {
          setEvents((cur) => [...(cur ?? []), ...p.items]);
          setNext(p.next ?? null);
          setErr("");
        },
        (e) => setErr(msg(e)),
      )
      .finally(() => {
        inflight.current = false;
        setLoadingMore(false);
      });
  };
  const v = status?.latest_verify;

  return (
    <section aria-label="Org audit">
      <PageHeader
        title="Org audit"
        lede="The control plane's hash-chained ledger of relays and changes, newest first."
      />
      {err && <Alert>{err}</Alert>}
      {!client ? (
        <Empty title="Connect a control plane on the Agents screen to see its audit ledger." />
      ) : (
        <>
          {status && (
            <Card className="mb-4" role="region" aria-label="Chain status">
              <CardContent>
                <p>
                  Head seq {status.head_seq}. Latest checkpoint:{" "}
                  {status.latest_checkpoint
                    ? `seq ${status.latest_checkpoint.seq} at ${status.latest_checkpoint.at}`
                    : "none yet"}
                  .
                </p>
                <p data-testid="verify-result">
                  {!v
                    ? "Not verified yet."
                    : v.ok
                      ? `Verified OK at ${v.finished_at}.`
                      : `Verification FAILED at ${v.finished_at}${v.broken_seq != null ? `, first broken seq ${v.broken_seq}` : ""}.`}
                </p>
              </CardContent>
            </Card>
          )}
          <Field orientation="horizontal" className="mb-4 w-fit">
            <FieldLabel>Outcome</FieldLabel>
            <Select value={filter} onValueChange={(v) => setFilter(v as AuditOutcomeFilter)}>
              <SelectTrigger aria-label="Outcome filter">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="denied">Denied</SelectItem>
                <SelectItem value="redaction_failed">Redaction failed</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {!events ? (
            <Loading what="the org ledger" />
          ) : events.length === 0 ? (
            <Empty title="Nothing in the ledger yet." />
          ) : !events.some((e) => auditOutcomeMatches(e, filter)) ? (
            <Empty kind="no-results" title={`No matching events${next ? " loaded yet" : ""}.`} />
          ) : (
            <Table>
              <TableCaption className="sr-only">Org audit events, newest first</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-right">Seq</TableHead>
                  <TableHead>Time</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Outcome</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events
                  .filter((e) => auditOutcomeMatches(e, filter))
                  .map((e) => (
                    <TableRow key={e.id}>
                      <TableCell className="text-right font-mono text-xs text-muted-foreground">{e.seq}</TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">{e.at}</TableCell>
                      <TableCell className="font-semibold">{e.kind}</TableCell>
                      <TableCell className="font-mono text-xs">{e.actor}</TableCell>
                      <TableCell className="font-mono text-xs min-w-[200px] break-words">
                        {breakable(e.target ?? "")}
                      </TableCell>
                      <TableCell>{e.outcome}</TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          )}
          {next && (
            <Button type="button" variant="outline" size="sm" disabled={loadingMore} onClick={more}>
              Load more
            </Button>
          )}
        </>
      )}
    </section>
  );
}

/** Control-plane counts for the Overview, best effort: a failed count shows "n/a", never an error. */
function useCpCounts() {
  const [c, setC] = useState<{ projects?: number; agents?: number } | null>(null);
  useEffect(() => {
    const client = api.agentsClient();
    if (!client) return;
    let live = true;
    void Promise.allSettled([
      (async () => (await client.listProjects()).length)(),
      (async () => (await client.listAgents()).length)(),
    ]).then(([p, a]) => {
      if (live)
        setC({
          projects: p.status === "fulfilled" ? p.value : undefined,
          agents: a.status === "fulfilled" ? a.value : undefined,
        });
    });
    return () => {
      live = false;
    };
  }, []);
  return c;
}

/** Control-plane errors in words: 403 and 409 say what to do, anything else shows its message. */
const cpErr = (e: unknown) =>
  e instanceof ApiError && e.status === 403
    ? "Not allowed: your role cannot do this in this org."
    : e instanceof ApiError && e.status === 409
      ? `Conflict: ${e.message || "that name is already taken, or the item still has contents"}.`
      : msg(e);

const NoClient = ({ what }: { what: string }) => (
  <Empty title={`Connect a control plane on the Agents screen to see ${what}.`} />
);

/** Row actions shared by projects and environments: rename, and delete with a confirm step. */
function RowActions({
  name,
  onRename,
  onDelete,
}: {
  name: string;
  onRename: (n: string) => Promise<unknown>;
  onDelete: () => Promise<unknown>;
}) {
  const [mode, setMode] = useState<"" | "edit" | "confirm">("");
  const [value, setValue] = useState(name);
  if (mode === "edit") {
    return (
      <form
        className="inline-flex items-center gap-2 *:data-[slot=input]:w-56"
        onSubmit={(e) => {
          e.preventDefault();
          void onRename(value).then(
            () => setMode(""),
            () => {},
          );
        }}
      >
        <Input aria-label={`New name for ${name}`} required value={value} onChange={(e) => setValue(e.target.value)} />
        <Button type="submit" variant="outline" size="sm">
          Save
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={() => setMode("")}>
          Cancel
        </Button>
      </form>
    );
  }
  return (
    <>
      <Button type="button" variant="outline" size="sm" onClick={() => setMode("edit")}>
        Rename {name}
      </Button>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="text-(--destructive-text)"
        onClick={() => setMode("confirm")}
      >
        Delete {name}
      </Button>
      <ConfirmDialog
        open={mode === "confirm"}
        danger
        title={`Delete ${name}?`}
        confirmLabel="Confirm delete"
        onClose={() => setMode("")}
        // A rejection is already shown by the list; the dialog closes either way.
        onConfirm={() => void onDelete().catch(() => {})}
      />
    </>
  );
}

function CreateForm({ label, onCreate }: { label: string; onCreate: (name: string) => Promise<unknown> }) {
  const [name, setName] = useState("");
  return (
    <form
      className={ROW}
      aria-label={`Create ${label}`}
      onSubmit={(e) => {
        e.preventDefault();
        void onCreate(name).then(
          () => setName(""),
          () => {},
        );
      }}
    >
      <Input
        aria-label={`${label} name`}
        placeholder={`${label} name`}
        required
        value={name}
        onChange={(e) => setName(e.target.value)}
      />
      <Button type="submit" size="sm">
        Create {label}
      </Button>
    </form>
  );
}

/** Loads a control-plane list, reloads after each mutation, and keeps the error from the last failure. */
function useCpList<T>(fn: () => Promise<T[]>, deps: unknown[]) {
  const [items, setItems] = useState<T[] | null>(null);
  const [err, setErr] = useState("");
  const load = useCallback(async () => {
    try {
      setItems(await fn());
    } catch (e) {
      setErr(cpErr(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    setItems(null);
    setErr("");
    void load();
  }, [load]);
  /** Runs a mutation; a rejection is shown and rethrown-free so forms keep their input. */
  const run = async (f: () => Promise<unknown>) => {
    setErr("");
    try {
      await f();
    } catch (e) {
      setErr(cpErr(e));
      throw e;
    }
    await load();
  };
  /** A failed first load leaves items unset, so the screen shows the error and a Retry, never the empty message. */
  const failed = items === null && err !== "";
  const retry = () => {
    setErr("");
    void load();
  };
  return { items, err, run, failed, retry };
}

function ListWait({ what, l }: { what: string; l: { failed: boolean; retry: () => void } }) {
  return l.failed ? (
    <Button type="button" variant="outline" size="sm" onClick={l.retry}>
      Retry
    </Button>
  ) : (
    <Loading what={what} />
  );
}

/** Projects, and the environments of the selected project, from the control plane. */
export function Projects(_: ScreenProps) {
  const client = api.agentsClient();
  if (!client)
    return (
      <section aria-label="Projects">
        <PageHeader title="Projects" />
        <NoClient what="projects" />
      </section>
    );
  return <ProjectsView client={client} />;
}

function ProjectsView({ client }: { client: Client }) {
  const [sel, setSel] = useState<Project | null>(null);
  const ps = useCpList(() => client.listProjects(), [client]);
  const es = useCpList<Environment>(
    () => (sel ? client.listEnvironments(sel.id) : Promise.resolve([])),
    [client, sel?.id],
  );
  return (
    <section aria-label="Projects">
      <PageHeader title="Projects" lede="Projects hold environments, and environments hold secrets." />
      {ps.err && <Alert>{ps.err}</Alert>}
      <CreateForm label="project" onCreate={(n) => ps.run(() => client.createProject({ name: n }))} />
      {!ps.items ? (
        <ListWait what="projects" l={ps} />
      ) : ps.items.length === 0 ? (
        <Empty title="No projects yet." />
      ) : (
        <ul className={ROWS}>
          {ps.items.map((p) => (
            <li key={p.id} className="flex flex-wrap items-center gap-2 px-4 py-2 *:first:mr-auto">
              <Button
                type="button"
                variant="link"
                className="h-auto p-0"
                aria-pressed={sel?.id === p.id}
                onClick={() => setSel(p)}
              >
                {p.name}
              </Button>
              <RowActions
                name={p.name}
                onRename={(name) => ps.run(() => client.updateProject(p.id, { name }))}
                onDelete={() =>
                  ps.run(async () => {
                    await client.deleteProject(p.id);
                    if (sel?.id === p.id) setSel(null);
                  })
                }
              />
            </li>
          ))}
        </ul>
      )}
      {sel && (
        <section aria-label={`Environments of ${sel.name}`}>
          <SecH spaced>
            <h2>Environments of {sel.name}</h2>
          </SecH>
          {es.err && <Alert>{es.err}</Alert>}
          <CreateForm
            label="environment"
            onCreate={(n) => es.run(() => client.createEnvironment(sel.id, { name: n }))}
          />
          {!es.items ? (
            <ListWait what="environments" l={es} />
          ) : es.items.length === 0 ? (
            <Empty title="No environments yet." />
          ) : (
            <ul className={ROWS}>
              {es.items.map((e) => (
                <li key={e.id} className="flex flex-wrap items-center gap-2 px-4 py-2 *:first:mr-auto">
                  <span>{e.name}</span>
                  <RowActions
                    name={e.name}
                    onRename={(name) => es.run(() => client.updateEnvironment(sel.id, e.id, { name }))}
                    onDelete={() => es.run(() => client.deleteEnvironment(sel.id, e.id))}
                  />
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </section>
  );
}

/** Secret metadata from the control plane: names, descriptions, version counts. Never a value or key material. */
export function Secrets(_: ScreenProps) {
  const client = api.agentsClient();
  if (!client)
    return (
      <section aria-label="Secrets">
        <PageHeader title="Secrets" />
        <NoClient what="secret metadata" />
      </section>
    );
  return <SecretsView client={client} />;
}

function SecretsView({ client }: { client: Client }) {
  const [pid, setPid] = useState("");
  const [eid, setEid] = useState("");
  const [open, setOpen] = useState<Secret | null>(null);
  const ps = useCpList(() => client.listProjects(), [client]);
  const project = pid || ps.items?.[0]?.id || "";
  const es = useCpList<Environment>(
    () => (project ? client.listEnvironments(project) : Promise.resolve([])),
    [client, project],
  );
  const env = eid || es.items?.[0]?.id || "";
  const ss = useCpList<Secret>(
    () => (project && env ? client.listSecrets(project, env) : Promise.resolve([])),
    [client, project, env],
  );
  return (
    <section aria-label="Secrets">
      <PageHeader title="Secrets" lede="Metadata only. Secret values never leave the vault and are not shown here." />
      {(ps.err || es.err || ss.err) && <Alert>{ps.err || es.err || ss.err}</Alert>}
      {!ps.items ? (
        <ListWait what="projects" l={ps} />
      ) : ps.items.length === 0 ? (
        <Empty title="No projects yet, so no secrets." />
      ) : (
        <>
          <Field orientation="horizontal" className="mb-3 w-fit">
            <FieldLabel>Project</FieldLabel>
            <Select
              value={project}
              onValueChange={(v) => {
                setPid(v);
                setEid("");
                setOpen(null);
              }}
            >
              <SelectTrigger aria-label="Project">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ps.items.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {es.items && es.items.length === 0 ? (
            <Empty title="No environments in this project." />
          ) : (
            es.items && (
              <Field orientation="horizontal" className="mb-3 w-fit">
                <FieldLabel>Environment</FieldLabel>
                <Select
                  value={env}
                  onValueChange={(v) => {
                    setEid(v);
                    setOpen(null);
                  }}
                >
                  <SelectTrigger aria-label="Environment">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {es.items.map((x) => (
                      <SelectItem key={x.id} value={x.id}>
                        {x.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            )
          )}
          {env &&
            (!ss.items ? (
              <ListWait what="secrets" l={ss} />
            ) : ss.items.length === 0 ? (
              <Empty title="No secrets in this environment." />
            ) : (
              <ul className={ROWS}>
                {ss.items.map((s) => (
                  <li key={s.id} className="px-4 py-2">
                    <Button type="button" variant="link" className="h-auto p-0" onClick={() => setOpen(s)}>
                      {s.name}
                    </Button>{" "}
                    ({plural(s.version_count, "version")})
                  </li>
                ))}
              </ul>
            ))}
          {open && <SecretDetail client={client} secret={open} onClose={() => setOpen(null)} />}
        </>
      )}
    </section>
  );
}

function SecretDetail({ client, secret, onClose }: { client: Client; secret: Secret; onClose: () => void }) {
  const { project_id: p, environment_id: e, id } = secret;
  const s = useLoad(() => client.getSecret(p, e, id), [p, e, id]);
  const v = useLoad<SecretVersion[]>(() => client.listSecretVersions(p, e, id), [p, e, id]);
  const d = s.data ?? secret;
  return (
    <Card className="mt-4" role="region" aria-label={`Secret ${secret.name}`}>
      <CardContent className="flex flex-col items-start gap-2">
        <b>{d.name}</b>
        {d.description && <p>{d.description}</p>}
        <p className="text-muted-foreground text-[13px]">Updated {d.updated_at}</p>
        {s.alert}
        {v.alert}
        {!v.data && !v.err ? (
          <Loading what="versions" />
        ) : (
          v.data &&
          (v.data.length === 0 ? (
            <Quiet>No versions yet.</Quiet>
          ) : (
            <Table>
              <TableCaption className="sr-only">Versions of {secret.name}</TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-right">Version</TableHead>
                  <TableHead>Key</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {v.data.map((x) => (
                  <TableRow key={x.version}>
                    <TableCell className="text-right font-mono text-xs">{x.version}</TableCell>
                    <TableCell className="font-mono text-xs">{x.key_id}</TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{x.created_at}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ))
        )}
        <Button type="button" variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
      </CardContent>
    </Card>
  );
}

const layerName = (l: string) => (l === "hub" ? "Hub (people)" : "Gateway (agents)");

/** One switch per MCP tool, grouped by layer; saved through the control plane. */
export function McpTools(_: ScreenProps) {
  const client = api.agentsClient();
  const [tools, setTools] = useState<api.McpToolSetting[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!client) return;
    let live = true;
    client.listMcpTools().then(
      (t) => live && setTools(t),
      (e) => live && setErr(msg(e)),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const toggle = async (t: api.McpToolSetting, enabled: boolean) => {
    if (!client) return;
    setErr("");
    try {
      const u = await client.setMcpTool(t.layer, t.tool, enabled);
      setTools((cur) => cur?.map((x) => (x.layer === u.layer && x.tool === u.tool ? u : x)) ?? cur);
    } catch (e) {
      setErr(msg(e));
    }
  };
  return (
    <section aria-label="MCP tools">
      <PageHeader title="MCP tools" lede="Which tools the Hub and the Gateway offer to MCP clients." />
      {err && <Alert>{err}</Alert>}
      {!client ? (
        <Empty title="Connect a control plane on the Agents screen to manage MCP tools." />
      ) : !tools ? (
        err ? null : (
          <Loading what="MCP tools" />
        )
      ) : tools.length === 0 ? (
        <Empty title="No MCP tools." />
      ) : (
        (["hub", "agent"] as const).map((layer) => {
          const rows = tools.filter((t) => t.layer === layer);
          if (rows.length === 0) return null;
          return (
            <Card key={layer} className="mb-4" role="group" aria-label={`${layerName(layer)} tools`}>
              <CardContent>
                <h2 className="mb-3 text-base font-semibold">{layerName(layer)}</h2>
                {rows.map((t) => (
                  <SettingRow
                    key={t.tool}
                    title={t.tool}
                    about={`${t.description} ${t.default_enabled ? "On by default" : "Off by default"}${t.overridden ? ", changed" : ""}`}
                  >
                    <Switch
                      aria-label={`${t.tool} (${layer})`}
                      checked={t.enabled}
                      onCheckedChange={(on) => void toggle(t, on)}
                    />
                  </SettingRow>
                ))}
              </CardContent>
            </Card>
          );
        })
      )}
    </section>
  );
}

/** MCP clients that have signed in, with revoke. */
export function McpClients(_: ScreenProps) {
  const client = api.agentsClient();
  const [clients, setClients] = useState<api.McpClient[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!client) return;
    let live = true;
    client.listMcpClients().then(
      (c) => live && setClients(c),
      (e) => live && setErr(msg(e)),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const revoke = async (c: api.McpClient) => {
    if (!client) return;
    setErr("");
    try {
      const u = await client.revokeMcpClient(c.id);
      setClients((cur) => cur?.map((x) => (x.id === u.id ? u : x)) ?? cur);
    } catch (e) {
      setErr(msg(e));
    }
  };
  const label = (c: api.McpClient) => c.client_name || c.client_id;
  return (
    <section aria-label="MCP clients">
      <PageHeader title="MCP clients" lede="Apps that signed in over MCP. Revoking one refuses its next call." />
      {err && <Alert>{err}</Alert>}
      {!client ? (
        <Empty title="Connect a control plane on the Agents screen to see MCP clients." />
      ) : !clients ? (
        err ? null : (
          <Loading what="MCP clients" />
        )
      ) : clients.length === 0 ? (
        <Empty title="No MCP clients have signed in yet." />
      ) : (
        <Table>
          <TableCaption className="sr-only">MCP clients</TableCaption>
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
                <TableCell className="font-semibold">{label(c)}</TableCell>
                <TableCell>{layerName(c.layer)}</TableCell>
                <TableCell className="font-mono text-xs">{c.principal}</TableCell>
                <TableCell className="font-mono text-xs whitespace-nowrap">{c.last_seen_at}</TableCell>
                <TableCell>{c.revoked_at ? `Revoked ${c.revoked_at}` : "Active"}</TableCell>
                <TableCell>
                  {!c.revoked_at && (
                    <Button type="button" variant="outline" size="sm" onClick={() => void revoke(c)}>
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

const BINDING_KIND: Record<string, string> = { http: "HTTP", git: "Git", pg: "Postgres", aws: "AWS", mcp: "MCP" };

/** Gateway bindings, non-secret fields only (never a password or template). */
export function Bindings(_: ScreenProps) {
  const client = api.agentsClient();
  const [items, setItems] = useState<api.BindingSummary[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!client) return;
    let live = true;
    client.listBindings().then(
      (b) => live && setItems(b),
      (e) => live && setErr(msg(e)),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <section aria-label="Bindings">
      <PageHeader
        title="Bindings"
        lede="What the gateway can reach for agents. Secrets and passwords are never shown."
      />
      {err && <Alert>{err}</Alert>}
      {!client ? (
        <Empty title="Connect a control plane on the Agents screen to see bindings." />
      ) : !items ? (
        err ? null : (
          <Loading what="bindings" />
        )
      ) : items.length === 0 ? (
        <Empty title="The gateway has not published any bindings yet." />
      ) : (
        <Table>
          <TableCaption className="sr-only">Bindings</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Kind</TableHead>
              <TableHead>Details</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((b) => (
              <TableRow key={`${b.kind}:${b.name}`}>
                <TableCell className="font-semibold">{b.name}</TableCell>
                <TableCell>{BINDING_KIND[b.kind] ?? b.kind}</TableCell>
                <TableCell className="font-mono text-xs">
                  {bindingDetails(b)
                    .map(([l, v]) => `${l}: ${v}`)
                    .join(" · ")}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  );
}
