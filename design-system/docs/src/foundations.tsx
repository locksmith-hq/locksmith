// Foundation pages that are not components: every colour token, and every icon the kit can draw.
import { useEffect, useMemo, useState } from "react";
import { icons } from "lucide-react";
import { Button } from "@locksmith-hq/ui/button";
import { Input } from "@locksmith-hq/ui/input";

const COLORS: [string, string, string[]][] = [
  [
    "Primary",
    "The strongest neutral: the darkest button and the text on it.",
    ["primary", "primary-hover", "primary-foreground"],
  ],
  ["Secondary", "A quiet fill for a second-rank button or a raised row.", ["secondary", "secondary-foreground"]],
  [
    "Accent and muted",
    "The faintest fills: a hovered row, a chip, a quiet panel.",
    ["accent", "accent-foreground", "muted", "muted-foreground", "chip-text"],
  ],
  [
    "Brand",
    "Teal is Locksmith: the main action, the key tooth, a thrown bolt.",
    ["brand", "brand-hover", "brand-text", "brand-weak", "brand-border", "brand-foreground"],
  ],
  ["Agent", "Violet means an agent did it or is doing it.", ["agent", "agent-text", "agent-weak", "agent-border"]],
  [
    "Surfaces",
    "What things sit on, from the page up to a floating plate.",
    ["background", "card", "card-foreground", "popover", "popover-foreground", "track"],
  ],
  ["Text", "Body text and supporting text.", ["foreground", "muted-foreground"]],
  ["Lines and ring", "Hairlines, the stronger edge of a control, and the focus ring.", ["border", "input", "ring"]],
  [
    "Success",
    "Green: connected, approved, working. Live and success are the same colours.",
    ["success", "success-text", "success-weak", "live", "live-text", "live-weak", "live-border", "live-track"],
  ],
  ["Info", "Blue: something to know, nothing to do.", ["info", "info-text", "info-weak", "info-border"]],
  [
    "Warning",
    "Amber: needs someone soon.",
    ["warning", "warning-text", "warning-weak", "warning-chip", "warning-border"],
  ],
  [
    "Destructive",
    "Red: refused, revoked, cannot be undone.",
    ["destructive", "destructive-text", "destructive-weak", "destructive-border", "destructive-foreground"],
  ],
  [
    "Sidebar",
    "The navigation rail and what is on it.",
    [
      "sidebar",
      "sidebar-foreground",
      "sidebar-primary",
      "sidebar-primary-foreground",
      "sidebar-accent",
      "sidebar-accent-foreground",
      "sidebar-border",
      "sidebar-ring",
    ],
  ],
  ["Charts", "Five series colours, in the order to use them.", ["chart-1", "chart-2", "chart-3", "chart-4", "chart-5"]],
];
const STATES: [string, string][] = [
  ["state-hover", "Under the pointer, or the highlighted row of a menu"],
  ["state-active", "While pressed"],
  ["state-selected", "Chosen: a selected row or option"],
  ["state-disabled-background", "A control that is off"],
  ["state-disabled-foreground", "Text on a control that is off"],
  ["state-disabled-border", "Edge of a control that is off"],
  ["state-focus", "The focus ring"],
];

// Re-renders when the theme changes, so the values shown are the ones in force.
function useTheme() {
  const [, tick] = useState(0);
  useEffect(() => {
    const again = () => tick((n) => n + 1);
    const seen = new MutationObserver(again);
    seen.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const dark = matchMedia("(prefers-color-scheme: dark)");
    dark.addEventListener("change", again);
    return () => {
      seen.disconnect();
      dark.removeEventListener("change", again);
    };
  }, []);
}

// The colour a token resolves to right now, as a hex code (with its opacity when it is see-through). The
// browser paints it on a 1px canvas, so any CSS colour works, color-mix() included.
let ink: CanvasRenderingContext2D | null | undefined;
function code(token: string): string {
  ink ??= document.createElement("canvas").getContext("2d", { willReadFrequently: true });
  const probe = document.createElement("i");
  probe.style.color = `var(--${token})`;
  document.body.append(probe);
  const color = getComputedStyle(probe).color;
  probe.remove();
  if (!ink) return color;
  ink.clearRect(0, 0, 1, 1);
  ink.fillStyle = color;
  ink.fillRect(0, 0, 1, 1);
  const [r, g, b, a] = ink.getImageData(0, 0, 1, 1).data;
  if (!a) return "transparent";
  const hex = [r, g, b].map((v) => (v ?? 0).toString(16).padStart(2, "0")).join("");
  return `#${hex.toUpperCase()}${a < 255 ? ` at ${Math.round((a / 255) * 100)}%` : ""}`;
}

function Swatch({ token, note }: { token: string; note?: string }) {
  const value = code(token);
  return (
    <button
      type="button"
      className="swatch"
      title="Copy the variable"
      onClick={() => navigator.clipboard?.writeText(`var(--${token})`).catch(() => {})}
    >
      <i style={{ background: `var(--${token})` }} />
      <b>--{token}</b>
      <span>
        {value}
        {note ? ` · ${note}` : ""}
      </span>
    </button>
  );
}

export function ColorsPage() {
  useTheme();
  return (
    <div className="colors">
      <section>
        <h3>States</h3>
        <p>
          One set for every control, so hover, pressed, selected and disabled look the same everywhere. As Tailwind
          classes: bg-state-hover, bg-state-active, bg-state-selected, bg-state-disabled,
          text-state-disabled-foreground.
        </p>
        <div className="state-row">
          {[
            ["Rest", "transparent"],
            ["Hover", "var(--state-hover)"],
            ["Pressed", "var(--state-active)"],
            ["Selected", "var(--state-selected)"],
          ].map(([name, bg]) => (
            <span key={name} style={{ background: bg }}>
              {name}
            </span>
          ))}
          <span className="off">Disabled</span>
          <span style={{ outline: "2px solid var(--state-focus)", outlineOffset: 2 }}>Focus</span>
        </div>
        <div className="state-row live">
          <Button variant="ghost">Ghost: hover and press me</Button>
          <Button variant="outline">Outline</Button>
          <Button disabled>Disabled</Button>
          <Button variant="outline" disabled>
            Disabled
          </Button>
          <Input className="w-40" disabled placeholder="Disabled input" />
        </div>
        <div className="swatches">
          {STATES.map(([t, note]) => (
            <Swatch key={t} token={t} note={note} />
          ))}
        </div>
      </section>
      {COLORS.map(([name, about, tokens]) => (
        <section key={name}>
          <h3>{name}</h3>
          <p>{about}</p>
          <div className="swatches">
            {tokens.map((t) => (
              <Swatch key={t} token={t} />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

const NAMES = Object.keys(icons) as (keyof typeof icons)[];
const PAGE = 240;

export function IconsPage() {
  const [q, setQ] = useState("");
  const [shown, setShown] = useState(PAGE);
  const [copied, setCopied] = useState("");
  const found = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    return NAMES.filter((n) => words.every((w) => n.toLowerCase().includes(w)));
  }, [q]);
  return (
    <div className="icons">
      <div className="icons-bar">
        <Input
          className="w-72"
          type="search"
          aria-label="Find an icon"
          placeholder="Find an icon: key, lock, shield"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setShown(PAGE);
          }}
        />
        <span aria-live="polite">
          {found.length} of {NAMES.length} icons{copied ? `. Copied ${copied}` : ""}
        </span>
      </div>
      <div className="icons-grid">
        {found.slice(0, shown).map((name) => {
          const Icon = icons[name];
          return (
            <button
              key={name}
              type="button"
              title={`Copy <${name} />`}
              onClick={() => {
                navigator.clipboard?.writeText(`<${name} />`).catch(() => {});
                setCopied(name);
              }}
            >
              <Icon />
              <span>{name}</span>
            </button>
          );
        })}
      </div>
      {found.length > shown ? (
        <Button variant="outline" onClick={() => setShown(shown + PAGE)}>
          Show {Math.min(PAGE, found.length - shown)} more
        </Button>
      ) : null}
      {found.length === 0 ? <p className="ls-muted">No icon has that name.</p> : null}
    </div>
  );
}
