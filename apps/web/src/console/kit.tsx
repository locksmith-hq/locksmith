// The console's page helpers. Its shared parts (page head, empty state, switch, breadcrumb, icons, marks) are
// thin adapters over the design system, so the console's pages keep their own short call shapes while
// everything on screen is a kit component. Sample data comes from ./data.
import { Children, createContext, useContext, useSyncExternalStore } from "react";
import { Loader } from "@locksmith-hq/ui/loader";
import type { ComponentType, ReactNode } from "react";
import { cn } from "cn";
import {
  Activity,
  AppWindow,
  FolderKanban,
  Layers,
  ArrowRight,
  Ban,
  Bot,
  CircleHelp,
  Clock,
  Cloud,
  Code,
  Database,
  FileText,
  GitBranch,
  Globe,
  KeyRound,
  KeySquare,
  LayoutGrid,
  Lock,
  LockOpen,
  Monitor,
  Moon,
  Plus,
  Power,
  Repeat,
  RotateCw,
  Search,
  Shield,
  Sparkles,
  Sun,
  Terminal,
  TriangleAlert,
  Unlink,
  X,
  type LucideIcon,
} from "lucide-react";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@locksmith-hq/ui/breadcrumb";
import { EmptyState } from "@locksmith-hq/ui/empty-state";
import { Mark } from "@locksmith-hq/ui/mark";
import { PageHeader } from "@locksmith-hq/ui/page-header";
import { Switch as KitSwitch } from "@locksmith-hq/ui/switch";

export { agents, members, projects, secrets } from "./data";
export { DAY, HOUR, MIN, NOW, ago, inTime, plural } from "./time";

// The console names its icons by what they stand for; each maps to one lucide icon.
const ICONS = {
  run: Terminal,
  git: GitBranch,
  http: Globe,
  db: Database,
  aws: Cloud,
  lock: Lock,
  unlock: LockOpen,
  x: X,
  block: Ban,
  arrow: ArrowRight,
  key: KeyRound,
  token: KeySquare,
  shield: Shield,
  broken: Unlink,
  clock: Clock,
  grid: LayoutGrid,
  relay: Repeat,
  doc: FileText,
  plus: Plus,
  rotate: RotateCw,
  power: Power,
  alert: TriangleAlert,
  search: Search,
  sun: Sun,
  moon: Moon,
  sessions: Activity,
  s_terminal: Terminal,
  s_window: AppWindow,
  s_layers: Layers,
  s_folder: FolderKanban,
  s_code: Code,
  s_spark: Sparkles,
  s_claude: Bot,
  s_unknown: CircleHelp,
  monitor: Monitor,
} satisfies Record<string, LucideIcon>;
export type IconName = keyof typeof ICONS;
export function Icon({ name, className }: { name: IconName; className?: string }) {
  const Glyph = ICONS[name];
  return <Glyph className={cn("i", className)} aria-hidden="true" />;
}

/** The sidebar mark; `open` turns its outer ring and withdraws the bolts when the vault unlocks. */
export const Logo = ({ size = 26, open = false }: { size?: number; open?: boolean }) => (
  <span className="logo">
    <Mark small open={open} size={size} />
  </span>
);

/** Every page gets the open project (inside a Secret Management project) and a way to show a note in the top bar. */
/** `sub` is whatever follows the page in the address, e.g. the id of the item whose detail view is open. */
export interface PageProps {
  project?: string;
  sub?: string;
  say: (note: string) => void;
}
export type Pages = Record<string, ComponentType<PageProps>>;

/** Page title, one-line explanation, and the page's main action(s) on the right. */
export const Head = ({ title, sub, children }: { title: string; sub?: ReactNode; children?: ReactNode }) => (
  <PageHeader title={title} lede={sub}>
    {children}
  </PageHeader>
);

/**
 * Empty state that says what is missing and what to do about it, on the kit's EmptyState. The first sentence
 * is the title and the rest the description. A search icon means nothing matched; anything else, nothing yet.
 */
export const Empty = ({ icon, children }: { icon: IconName; children: ReactNode }) => {
  const [first, ...rest] = Children.toArray(children);
  const cut = typeof first === "string" ? first.indexOf(". ") : -1;
  return (
    <EmptyState
      size="compact"
      kind={icon === "search" ? "no-results" : "first-use"}
      title={cut < 0 ? first : (first as string).slice(0, cut + 1)}
    >
      {cut < 0 ? (rest.length ? rest : null) : [(first as string).slice(cut + 2), ...rest]}
    </EmptyState>
  );
};

/** The kit's switch has a keyhole on its bolt. Only a switch about a secret or a password keeps it (`keyed`). */
export const Switch = ({
  label,
  checked,
  disabled,
  keyed = false,
  onChange,
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  keyed?: boolean;
  onChange: (on: boolean) => void;
}) => (
  <KitSwitch
    aria-label={label}
    checked={checked}
    disabled={disabled}
    data-plain={keyed ? undefined : ""}
    onCheckedChange={onChange}
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
  <Breadcrumb className="mb-3.5">
    <BreadcrumbList>
      {trail.map(([label, href], i) => (
        <BreadcrumbItem key={label}>
          {i > 0 && <BreadcrumbSeparator />}
          {href ? <BreadcrumbLink href={href}>{label}</BreadcrumbLink> : <BreadcrumbPage>{label}</BreadcrumbPage>}
        </BreadcrumbItem>
      ))}
    </BreadcrumbList>
  </Breadcrumb>
);

/** True while the console waits on a tab of the page already open. Set by the Console. */
export const TabBusy = createContext(false);

// Goes right under a page's tabs. While that tab's content is on its way it shows the loader and hides what
// follows it (console.css), so the page's heading and tabs stay where they are.
export function TabLoader() {
  return useContext(TabBusy) ? (
    <div className="tab-busy">
      <Loader />
    </div>
  ) : null;
}
