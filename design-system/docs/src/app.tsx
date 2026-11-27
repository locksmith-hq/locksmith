// The Locksmith kit's site: a page per package, with a live demo and its API.
import { Ideas } from "./ideas";
import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { ChevronDown } from "lucide-react";
import "./site.css";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@locksmith-hq/breadcrumb";
import { Button } from "@locksmith-hq/button";
import { Input } from "@locksmith-hq/input";
import { Kbd } from "@locksmith-hq/kbd";
import { Link } from "@locksmith-hq/link";
import { Loader } from "@locksmith-hq/loader";
import { Mark } from "@locksmith-hq/mark";
import { PageHeader } from "@locksmith-hq/page-header";
import { Pill } from "@locksmith-hq/pill";
import { ScopeChip } from "@locksmith-hq/scope-chip";
import { Toaster } from "@locksmith-hq/sonner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/table";
import { Tabs, TabsList, TabsTrigger } from "@locksmith-hq/tabs";
import { ToggleGroup, ToggleGroupItem } from "@locksmith-hq/toggle-group";
import { TooltipProvider } from "@locksmith-hq/tooltip";
import { Wordmark } from "@locksmith-hq/wordmark";
import API from "./api.json";
import { DEMOS, code } from "./demos";

type Prop = { name: string; type: string; required: boolean; default: string | null; description: string };
type Api = {
  package: string;
  shadcn: boolean;
  exports: string[];
  variants: Record<string, string[]>;
  props: Record<string, Prop[]>;
};
const api = API as unknown as Record<string, Api>;

// Foundations first, then components in categories like Atlassian's. Every package has its own page at #/name.
const GROUPS: [string, string[]][] = [
  ["Foundations", ["mark", "wordmark", "colors", "icons", "type", "motion"]],
  [
    "Forms and input",
    [
      "button",
      "button-group",
      "kebab-button",
      "field",
      "label",
      "input",
      "input-group",
      "textarea",
      "number-field",
      "password-field",
      "tags-input",
      "select",
      "combobox",
      "checkbox",
      "radio-group",
      "switch",
      "toggle",
      "toggle-group",
      "date-picker",
      "date-range-picker",
      "calendar",
      "file-upload",
    ],
  ],
  [
    "Data display",
    [
      "table",
      "data-table",
      "chart",
      "filter-bar",
      "action-bar",
      "facts",
      "stat",
      "meter",
      "timeline",
      "code-block",
      "avatar",
      "kbd",
      "copyable-id",
      "copy-button",
      "secret",
    ],
  ],
  ["Labels and status", ["badge", "chip", "pill", "scope-chip", "live-dot"]],
  ["Loading", ["loader", "spinner", "tumblers", "progress", "skeleton"]],
  ["Signature", ["relay-path", "combination", "hold-to-confirm", "slide-to-unlock", "lease-timer"]],
  ["Messaging", ["alert", "sonner", "empty", "empty-state"]],
  ["Overlays", ["dialog", "alert-dialog", "confirm-dialog", "sheet", "popover", "dropdown-menu", "command", "tooltip"]],
  ["Navigation", ["sidebar", "tabs", "breadcrumb", "pagination", "stepper", "link"]],
  ["Layout and surfaces", ["page-header", "card", "accordion", "collapsible", "separator", "setting-row"]],
];
const [[, FOUNDATIONS], ...COMPONENT_GROUPS] = GROUPS as [[string, string[]], ...[string, string[]][]];
const ORDER = GROUPS.flatMap(([, names]) => names);
const href = (name: string) => `#/${name}`;
// "date-range-picker" reads "DateRangePicker", as the component is named in code.
const title = (name: string) =>
  name
    .split("-")
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join("");

// The page is the hash: "#/button" is a component page, anything else is the overview.
function usePage(): string {
  const read = () => decodeURIComponent(location.hash.replace(/^#\/?/, ""));
  const [page, set] = useState(read);
  useEffect(() => {
    const on = () => {
      set(read());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return page;
}

const TYPE: [string, string, string][] = [
  ["type-display", "Display 34/40", "Keys for agents, kept by people"],
  ["type-title", "Title 26/32", "Secrets"],
  ["type-code-title", "Code title 22/28", "STRIPE_SECRET_KEY"],
  ["type-body", "Body 14/20", "Sealed in payments / production. Three agents hold a grant."],
  ["type-mono", "Mono 12", "agt_01JD8Q9X4M7T2K5N8B3V6C0Z1Y"],
];
const NOTES: Record<string, string> = {
  type: "Chakra Petch for reading. Azeret Mono for anything a machine issued: keys, ids, scopes.",
  motion:
    "Three speeds and one rule: things you touch answer fast, things that arrive take a little longer, and whatever locks into place lands with a small overshoot.",
};
function Foundation({ name }: { name: string }) {
  const [run, again] = useState(0);
  if (name === "type")
    return (
      <div className="type-spec">
        {TYPE.map(([cls, label, sample]) => (
          <div key={cls} style={{ display: "contents" }}>
            <span className="muted">{label}</span>
            <p className={cls}>{sample}</p>
          </div>
        ))}
      </div>
    );
  return (
    <div className="demo-col">
      <div className="motion" key={run}>
        {[
          ["fast", "120ms", "Hover, press, tooltips"],
          ["base", "180ms", "Switches, tabs, menus"],
          ["slow", "240ms", "Dialogs, sheets, toasts"],
        ].map(([lane, ms, use]) => (
          <div key={lane} style={{ display: "contents" }}>
            <span className="font-mono text-xs">{ms}</span>
            <div className="motion-track">
              <i style={{ animationDuration: `var(--duration-${lane})` }} />
            </div>
            <span className="muted">{use}</span>
          </div>
        ))}
      </div>
      <div>
        <Button size="sm" variant="outline" onClick={() => again(run + 1)}>
          Play again
        </Button>
      </div>
    </div>
  );
}

// `code` in a description becomes <code>.
const prose = (t: string) => t.split("`").map((part, i) => (i % 2 ? <code key={i}>{part}</code> : part));

// The API of one package, from api.json: how to install it, what it exports, its variants, and its documented props.
function ApiSection({ name }: { name: string }) {
  const a = api[name];
  if (!a) return null;
  const parts = a.exports.filter((e) => /^[A-Z]/.test(e));
  const variants = Object.entries(a.variants);
  return (
    <section className="api" aria-label="API">
      <h2>Install</h2>
      {code(`npm install ${a.package} @locksmith-hq/styles`)}
      {code(`import { ${parts.slice(0, 4).join(", ")}${parts.length > 4 ? ", ..." : ""} } from "${a.package}";`, "tsx")}
      {a.shadcn ? (
        <p className="muted">
          This is shadcn/ui's {title(name)} with the Locksmith look applied by the theme. Its parts take the props of
          the element or primitive they render, plus <code>className</code>. Full reference:{" "}
          <Link href={`https://ui.shadcn.com/docs/components/${name}`} external>
            shadcn/ui {title(name)}
          </Link>
        </p>
      ) : null}
      {parts.length > 1 ? (
        <>
          <h2>Parts</h2>
          <p className="api-parts">
            {parts.map((p) => (
              <code key={p}>{p}</code>
            ))}
          </p>
        </>
      ) : null}
      {variants.length ? (
        <>
          <h2>Variants</h2>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Prop</TableHead>
                <TableHead>Values</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {variants.map(([prop, values]) => (
                <TableRow key={prop}>
                  <TableCell className="font-mono text-xs">{prop}</TableCell>
                  <TableCell className="api-parts">
                    {values.map((v) => (
                      <code key={v}>{v}</code>
                    ))}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      ) : null}
      {Object.entries(a.props).map(([comp, props]) => (
        <div key={comp} className="api-props">
          <h2>{Object.keys(a.props).length > 1 ? `${comp} props` : "Props"}</h2>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Prop</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Default</TableHead>
                <TableHead>Description</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {props.map((p) => (
                <TableRow key={p.name}>
                  <TableCell className="font-mono text-xs">
                    {p.name}
                    {p.required ? <span className="api-req"> required</span> : null}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{p.type}</TableCell>
                  <TableCell className="font-mono text-xs">{p.default ?? <span className="muted">–</span>}</TableCell>
                  <TableCell>{prose(p.description)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ))}
    </section>
  );
}

function ComponentPage({ name }: { name: string }) {
  const group = GROUPS.find(([, names]) => names.includes(name))![0];
  const at = ORDER.indexOf(name),
    prev = ORDER[at - 1],
    next = ORDER[at + 1];
  const [note, demo] = DEMOS[name] ?? [NOTES[name] ?? "", <Foundation name={name} />];
  return (
    <article className="page">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="#/">Kit</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>{group}</BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>{title(name)}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>
      <header className="demo-intro">
        <h1>{title(name)}</h1>
        <p>{note}</p>
      </header>
      <div className="stage">{demo}</div>
      <ApiSection name={name} />
      <nav className="pager" aria-label="More components">
        {prev ? (
          <a href={href(prev)}>
            <span className="muted">Previous</span>
            {title(prev)}
          </a>
        ) : (
          <span />
        )}
        {next ? (
          <a href={href(next)} data-next>
            <span className="muted">Next</span>
            {title(next)}
          </a>
        ) : null}
      </nav>
    </article>
  );
}

// The opening scene: one real Locksmith screen, built only from the kit.
function Scene() {
  const [tab, setTab] = useState("grants");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    setLoading(true);
    const t = setTimeout(() => setLoading(false), 1400);
    return () => clearTimeout(t);
  }, [tab]);
  return (
    <div className="scene" aria-label="Example: the grants on one secret">
      <PageHeader
        title="STRIPE_SECRET_KEY"
        lede="Sealed in payments / production. Three agents hold a grant; it rotates in 12 days."
      >
        <Button variant="outline">Rotate now</Button>
        <Button>Grant access</Button>
      </PageHeader>
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList variant="line">
          <TabsTrigger value="grants">Grants</TabsTrigger>
          <TabsTrigger value="versions">Versions</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
        </TabsList>
      </Tabs>
      <div className="scene-body">
        {loading ? (
          <Loader label={`Loading ${tab}`} />
        ) : tab === "grants" ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Agent</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>State</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {[
                ["deploy-bot", "charges:read", "live", "Live"],
                ["billing-sync", "refunds:write", "warning", "Ask first"],
                ["support-triage", "charges:read", "live", "Live"],
              ].map(([agent, scope, tone, state]) => (
                <TableRow key={agent}>
                  <TableCell className="font-medium">{agent}</TableCell>
                  <TableCell>
                    <ScopeChip>{scope}</ScopeChip>
                  </TableCell>
                  <TableCell>
                    <Pill tone={tone as "live" | "warning"}>{state}</Pill>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <p className="muted">
            {tab === "versions"
              ? "Four versions. The current one was sealed 12 days ago."
              : "Nothing in the last hour."}
          </p>
        )}
      </div>
    </div>
  );
}

function Overview() {
  return (
    <>
      <header className="demo-intro">
        <h1>The Locksmith kit</h1>
        <p>
          Parts for a product that keeps secrets, built on shadcn/ui. Things you press stand up and sink, things you
          fill are cut in, scopes hang on key tags, and every id wears its type as a tag.
        </p>
      </header>
      <Scene />
      <section className="api" aria-label="Use the kit">
        <h2>Use the kit</h2>
        <p className="muted">
          Every component is its own package on GitHub Packages. The kit needs React 19 and Tailwind CSS 4. Install the
          components you need with the styles, then set up your stylesheet once.
        </p>
        {code("npm install @locksmith-hq/button @locksmith-hq/styles tailwindcss tw-animate-css")}
        {code(
          '@import "tailwindcss";\n@import "tw-animate-css";\n@import "@locksmith-hq/styles";\n@source "../node_modules/@locksmith-hq";',
        )}
      </section>
      <div className="index">
        {GROUPS.map(([group, names]) => (
          <section key={group} aria-label={group}>
            <h2>{group}</h2>
            <ul>
              {names.map((n) => (
                <li key={n}>
                  <a href={href(n)}>{title(n)}</a>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </>
  );
}

// Light / dark: "System" follows the OS; the choice is kept in localStorage and applied as <html data-theme>
// (index.html applies it before first paint, so a reload does not flash the other theme).
type Theme = "System" | "Light" | "Dark";
function ThemeToggle() {
  const [theme, set] = useState<Theme>(() => {
    try {
      return (localStorage.getItem("ls-theme") as Theme) || "System";
    } catch {
      return "System"; // storage blocked
    }
  });
  function apply(t: Theme) {
    set(t);
    if (t === "System") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t.toLowerCase();
    try {
      localStorage.setItem("ls-theme", t);
    } catch {
      /* storage blocked: the choice lasts this visit */
    }
  }
  return (
    <ToggleGroup
      type="single"
      className="demo-theme"
      aria-label="Theme"
      value={theme}
      onValueChange={(v) => v && apply(v as Theme)}
    >
      {(["System", "Light", "Dark"] as const).map((t) => (
        <ToggleGroupItem key={t} value={t}>
          {t}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}

// Get started and Foundations stay flat; component categories fold. Which ones are open is kept in
// localStorage, the current page's category opens on arrival, and a filter (focused with "/") opens every match.
function SiteNav({ page, known }: { page: string; known: boolean }) {
  const [query, setQuery] = useState("");
  const [hover, setHover] = useState(false);
  const [opened, setOpened] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem("ls-nav-open") || "[]");
    } catch {
      return [];
    }
  });
  const save = (next: string[]) => {
    setOpened(next);
    try {
      localStorage.setItem("ls-nav-open", JSON.stringify(next));
    } catch {
      /* storage blocked */
    }
  };
  useEffect(() => {
    const g = COMPONENT_GROUPS.find(([, names]) => names.includes(page))?.[0];
    if (g && !opened.includes(g)) save([...opened, g]);
  }, [page]);
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (e.key !== "/" || (e.target as Element).closest("input, textarea, select, [contenteditable]")) return;
      e.preventDefault();
      document.querySelector<HTMLInputElement>(".demo-filter input")?.focus();
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, []);
  const q = query.trim().toLowerCase();
  const match = (n: string) => title(n).toLowerCase().includes(q);
  const link = (n: string) => (
    <a key={n} href={href(n)} aria-current={n === page ? "page" : undefined}>
      {title(n)}
    </a>
  );
  const foundations = FOUNDATIONS.filter(match);
  const groups = COMPONENT_GROUPS.map(([g, names]) => [g, names.filter(match)] as const).filter(
    ([, names]) => names.length,
  );
  const showOverview = !q || "overview".includes(q);
  return (
    <nav className="demo-nav" aria-label="Components">
      <a className="demo-brand" href="#/" onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
        <Mark small size={26} open={hover} />
        <Wordmark />
      </a>
      <ThemeToggle />
      <div className="demo-filter">
        <Input aria-label="Filter components" placeholder="Filter" onChange={(e) => setQuery(e.target.value)} />
        <Kbd>/</Kbd>
      </div>
      {showOverview && (
        <div className="demo-group">
          <h2>Get started</h2>
          <a href="#/" aria-current={known || page === "ideas" ? undefined : "page"}>
            Overview
          </a>
          <a href="#/ideas" aria-current={page === "ideas" ? "page" : undefined}>
            Ideas
          </a>
        </div>
      )}
      {foundations.length > 0 && (
        <div className="demo-group">
          <h2>Foundations</h2>
          {foundations.map(link)}
        </div>
      )}
      {groups.length > 0 && <div className="demo-divider">Components</div>}
      {groups.map(([g, names]) => (
        <details key={g} className="demo-group demo-fold" open={!!q || opened.includes(g)}>
          {/* controlled: React owns open, so the summary toggles state instead of the element */}
          <summary
            onClick={(e) => {
              e.preventDefault();
              if (!q) save(opened.includes(g) ? opened.filter((x) => x !== g) : [...opened, g]);
            }}
          >
            <ChevronDown />
            <span>{g}</span>
            <span className="demo-count">{names.length}</span>
          </summary>
          <div className="demo-fold-items">{names.map(link)}</div>
        </details>
      ))}
      {!showOverview && !foundations.length && !groups.length && (
        <p className="demo-none">No components match “{query.trim()}”.</p>
      )}
    </nav>
  );
}

// Every demo on one page, for reviewing the look in one pass. Not in the navigation: open #/gallery.
function Gallery() {
  return (
    <div className="gallery">
      {ORDER.filter((n) => DEMOS[n]).map((n) => (
        <section key={n}>
          <h2>
            <a href={href(n)}>{title(n)}</a>
          </h2>
          {DEMOS[n][1]}
        </section>
      ))}
    </div>
  );
}

function App() {
  const page = usePage();
  const known = ORDER.includes(page);
  useEffect(() => {
    document.title = known ? `${title(page)} · Locksmith kit` : "Locksmith kit";
  }, [page]);
  return (
    <TooltipProvider>
      <div className="demo">
        <SiteNav page={page} known={known} />
        {/* keyed by page, so a demo's state and animations start fresh on each visit */}
        <main key={page}>
          {known ? (
            <ComponentPage name={page} />
          ) : page === "gallery" ? (
            <Gallery />
          ) : page === "ideas" ? (
            <Ideas />
          ) : (
            <Overview />
          )}
        </main>
      </div>
      <Toaster />
    </TooltipProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
