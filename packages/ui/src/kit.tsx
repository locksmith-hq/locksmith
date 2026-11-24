// Shared kit components and helpers for the web console and its mockup. No data, nothing talks to a server.
import { useSyncExternalStore } from "react";
import { Icon, type IconName } from "./brand";

/** Page-load time in epoch seconds; "ago" and "in" labels are relative to it. */
export const NOW = Math.floor(Date.now() / 1000);

/** Every page gets the open project (inside a Secret Management project) and a way to show a note in the top bar. */
/** `sub` is whatever follows the page in the address, e.g. the id of the item whose detail view is open. */
export interface PageProps {
  project?: string;
  sub?: string;
  say: (note: string) => void;
}
export type Pages = Record<string, React.ComponentType<PageProps>>;

export const MIN = 60,
  HOUR = 3600,
  DAY = 86400;
export const plural = (n: number, w: string) => `${n} ${n === 1 ? w : `${w}s`}`;
/** "3m ago", "2d ago"; `null` reads "never". */
export const ago = (ts: number | null) => {
  if (ts === null) return "never";
  const s = NOW - ts;
  return s < 60
    ? "just now"
    : s < HOUR
      ? `${Math.floor(s / 60)}m ago`
      : s < DAY
        ? `${Math.floor(s / HOUR)}h ago`
        : `${Math.floor(s / DAY)}d ago`;
};
/** "in 5h", "in 12d"; `null` reads "never". */
export const inTime = (ts: number | null) => {
  if (ts === null) return "never";
  const s = ts - NOW;
  return s <= 0
    ? "now"
    : s < HOUR
      ? `in ${Math.ceil(s / 60)}m`
      : s < DAY
        ? `in ${Math.ceil(s / HOUR)}h`
        : `in ${Math.ceil(s / DAY)}d`;
};

/** Page title, one-line explanation, and the page's main action(s) on the right. */
export const Head = ({
  title,
  sub,
  children,
}: {
  title: string;
  sub?: React.ReactNode;
  children?: React.ReactNode;
}) => (
  <div className="screen-head">
    <div>
      <h1>{title}</h1>
      {sub && <p className="lede">{sub}</p>}
    </div>
    {children}
  </div>
);

/** Empty state that says what is missing and what to do about it. */
export const Empty = ({ icon, children }: { icon: IconName; children: React.ReactNode }) => (
  <div className="state empty">
    <span className="state-ic">
      <Icon name={icon} />
    </span>
    <div>{children}</div>
  </div>
);

/** A switch drawn from a checkbox (styles in settings.css). */
export const Switch = ({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (on: boolean) => void;
}) => (
  <input
    type="checkbox"
    className="switch"
    role="switch"
    aria-label={label}
    checked={checked}
    onChange={(e) => onChange(e.target.checked)}
  />
);

/**
 * Data shared by several pages. Lives outside React, so it survives moving between pages (each page
 * remounts on navigation). `const useCerts = createStore(SEED)`, then `const [certs, setCerts] = useCerts()`.
 */
export function createStore<T>(initial: T) {
  let state = initial;
  const subs = new Set<() => void>();
  const set = (next: T | ((s: T) => T)) => {
    state = typeof next === "function" ? (next as (s: T) => T)(state) : next;
    subs.forEach((f) => f());
  };
  const subscribe = (f: () => void) => {
    subs.add(f);
    return () => {
      subs.delete(f);
    };
  };
  return () => [useSyncExternalStore(subscribe, () => state), set] as const;
}

/** Trail above a detail page: `<Crumbs trail={[["Certificates", "#/app/certs/certificates"], ["api.acme.example"]]} />`. */
export const Crumbs = ({ trail }: { trail: [label: string, href?: string][] }) => (
  <nav className="crumbs" aria-label="Breadcrumb">
    {trail.map(([label, href], i) => (
      <span key={label} style={{ display: "contents" }}>
        {i > 0 && <span aria-hidden="true">/</span>}
        {href ? <a href={href}>{label}</a> : <span>{label}</span>}
      </span>
    ))}
  </nav>
);
