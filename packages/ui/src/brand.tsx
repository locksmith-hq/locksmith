// Drawn parts: the logo slot (its dial follows the vault state) and the icon set (one 16px grid, 1.6 stroke).

// The Locksmith mark: a round vault dial. Outer ring in six segments, six bolts that start on a
// segmented inner ring and are thrown out through the outer ring's gaps, a keyhole hub. Unlocking
// turns the outer ring 30 degrees (closing its gaps) and withdraws the bolts. Geometry matches
// packages/ui/brand/gen.py.
const C = 60;
function ring(r: number, n: number, gap: number, off: number) {
  const pt = (a: number) => [C + r * Math.cos((a * Math.PI) / 180), C + r * Math.sin((a * Math.PI) / 180)].map((v) => v.toFixed(2)).join(" ");
  let d = "";
  for (let i = 0; i < n; i++) {
    const a0 = off + (i * 360) / n + gap / 2, a1 = off + ((i + 1) * 360) / n - gap / 2;
    d += `M${pt(a0)}A${r} ${r} 0 0 1 ${pt(a1)}`;
  }
  return d;
}
const OUTER = ring(42, 6, 20, -90), OUTER_SMALL = ring(40, 6, 30, -90), INNER = ring(25, 6, 22, -60);

export function VaultMark({ open = false, small = false, size }: { open?: boolean; small?: boolean; size?: number }) {
  const [w, rIn, rOut] = small ? [10, 26, 53] : [7, 25, 52];
  return (
    <svg className="vault-mark" data-open={open} width={size} height={size} viewBox="0 0 120 120" aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth={w}>
        <path className="vm-ring" d={small ? OUTER_SMALL : OUTER} />
        {!small && <path d={INNER} />}
        {[0, 1, 2, 3, 4, 5].map((i) => (
          <g key={i} transform={`rotate(${-90 + i * 60} 60 60)`}>
            <line className="vm-bolt" x1={C + rIn} y1={C} x2={C + rOut} y2={C} style={{ transformOrigin: `${C + rIn}px ${C}px` }} />
          </g>
        ))}
      </g>
      <g fill="currentColor"><circle cx="60" cy="56" r="8.5" /><path d="M55.5 59L53 74H67L64.5 59Z" /></g>
    </svg>
  );
}

/** The sidebar mark; `open` turns its outer ring and withdraws the bolts when the vault unlocks. */
export function Logo({ size = 26, open = false }: { size?: number; open?: boolean }) {
  return <span className="logo"><VaultMark small open={open} size={size} /></span>;
}

/** The wordmark: lowercase "locksmith" set in Unbounded 500. */
export function Wordmark() {
  return <span className="wordmark" aria-label="Locksmith">locksmith</span>;
}

const PATHS = {
  run: <path d="M3.5 4.5L7 8l-3.5 3.5M8.5 12h4" />,
  git: <><circle cx="5" cy="4" r="1.5" /><circle cx="5" cy="12" r="1.5" /><circle cx="11" cy="6" r="1.5" /><path d="M5 5.5v5M11 7.5c0 2-2 2.5-6 3" /></>,
  http: <><circle cx="8" cy="8" r="5.5" /><path d="M2.5 8h11M8 2.5c1.7 1.6 2.5 3.4 2.5 5.5S9.7 11.9 8 13.5M8 2.5C6.3 4.1 5.5 5.9 5.5 8s.8 3.9 2.5 5.5" /></>,
  db: <><ellipse cx="8" cy="4.5" rx="4.5" ry="2" /><path d="M3.5 4.5v7c0 1.1 2 2 4.5 2s4.5-.9 4.5-2v-7M3.5 8c0 1.1 2 2 4.5 2s4.5-.9 4.5-2" /></>,
  aws: <path d="M4.5 12h7a2.5 2.5 0 0 0 .4-5A3.5 3.5 0 0 0 5.2 6.3 2.9 2.9 0 0 0 4.5 12z" />,
  lock: <><rect x="3" y="7" width="10" height="7" rx="1.75" /><path d="M5.25 7V5a2.75 2.75 0 0 1 5.5 0v2" /></>,
  unlock: <><rect x="3" y="7" width="10" height="7" rx="1.75" /><path d="M5.25 7V5a2.75 2.75 0 0 1 5.35-.9" /></>,
  x: <><circle cx="8" cy="8" r="5.75" /><path d="M6 6l4 4M10 6l-4 4" /></>,
  block: <><circle cx="8" cy="8" r="5.75" /><path d="M4 12L12 4" /></>,
  arrow: <path d="M3 8h9.5M9 4.5L12.5 8 9 11.5" />,
  key: <><circle cx="5" cy="11" r="2.75" /><path d="M7 9l6.5-6.5M11 4.5l1.75 1.75M9.5 6l1.25 1.25" /></>,
  token: <path d="M2.5 5.5a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v1.25a1.25 1.25 0 0 0 0 2.5v1.25a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1V9.25a1.25 1.25 0 0 0 0-2.5z" />,
  shield: <><path d="M8 1.75l5 2v4c0 3-2.2 5.3-5 6.5-2.8-1.2-5-3.5-5-6.5v-4z" /><path d="M5.75 8.25l1.6 1.6 3-3.1" /></>,
  broken: <><path d="M8 1.75l5 2v4c0 3-2.2 5.3-5 6.5-2.8-1.2-5-3.5-5-6.5v-4z" /><path d="M8 5v3.5M8 10.75v.25" /></>,
  clock: <><circle cx="8" cy="8" r="5.75" /><path d="M8 5v3.25l2 1.25" /></>,
  grid: <><rect x="2.5" y="2.5" width="4.5" height="4.5" rx="1" /><rect x="9" y="2.5" width="4.5" height="4.5" rx="1" /><rect x="2.5" y="9" width="4.5" height="4.5" rx="1" /><rect x="9" y="9" width="4.5" height="4.5" rx="1" /></>,
  relay: <path d="M2.5 5.5h10M10 3l2.5 2.5L10 8M13.5 10.5h-10M6 8l-2.5 2.5L6 13" />,
  doc: <><path d="M4 2.5h5.5L12 5v8.5H4z" /><path d="M6 7.5h4M6 10h4" /></>,
  plus: <path d="M8 3.5v9M3.5 8h9" />,
  rotate: <path d="M12.5 8a4.5 4.5 0 1 1-1.3-3.2M12.5 3v2.5H10" />,
  power: <><path d="M8 2.5V8" /><path d="M5 4.2a5 5 0 1 0 6 0" /></>,
  alert: <><path d="M8 2.5l6 10.5H2z" /><path d="M8 6.5v3M8 11.25v.25" /></>,
  search: <><circle cx="7" cy="7" r="4.25" /><path d="M10.25 10.25L13.5 13.5" /></>,
  sun: <><circle cx="8" cy="8" r="2.75" /><path d="M8 1.75v1.5M8 12.75v1.5M1.75 8h1.5M12.75 8h1.5M3.6 3.6l1 1M11.4 11.4l1 1M3.6 12.4l1-1M11.4 4.6l1-1" /></>,
  moon: <path d="M12.75 9.5A5.25 5.25 0 0 1 6.5 3.25a5.25 5.25 0 1 0 6.25 6.25z" />,
  sessions: <><circle cx="8" cy="5.5" r="2.5" /><path d="M3 13.5c.4-2.6 2.3-4 5-4s4.6 1.4 5 4" /></>,
  // Source glyphs: simple generic shapes, one per client family, no third-party logos.
  s_terminal: <><rect x="2" y="3" width="12" height="10" rx="1.75" /><path d="M5 6.5L7 8.25 5 10M8.5 10.25H11" /></>,
  s_window: <><rect x="2" y="3" width="12" height="10" rx="1.75" /><path d="M2 6h12" /></>,
  s_code: <path d="M5.5 4.5L2.5 8l3 3.5M10.5 4.5l3 3.5-3 3.5" />,
  s_spark: <path d="M8 2.5l1.4 4.1 4.1 1.4-4.1 1.4L8 13.5l-1.4-4.1L2.5 8l4.1-1.4z" />,
  // Stand-in for the Claude mark (eight radiating strokes), drawn here because the official asset cannot be fetched.
  // It can be replaced by the official Anthropic/Claude asset under their brand guidelines. Colored via .src-claude.
  s_claude: <path d="M8 1.75v3.5M8 10.75v3.5M1.75 8h3.5M10.75 8h3.5M3.6 3.6l2.3 2.3M10.1 10.1l2.3 2.3M12.4 3.6l-2.3 2.3M5.9 10.1l-2.3 2.3" />,
  s_unknown: <><circle cx="8" cy="8" r="5.75" /><path d="M6.25 6.4a1.9 1.9 0 0 1 3.5.8c0 1.2-1.75 1.4-1.75 2.5M8 11.5v.25" /></>,
  monitor: <><rect x="2" y="3" width="12" height="8" rx="1.5" /><path d="M6 13.5h4" /></>,
} as const;
export type IconName = keyof typeof PATHS;

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg className={className ? `i ${className}` : "i"} viewBox="0 0 16 16" aria-hidden="true">{PATHS[name]}</svg>
  );
}
