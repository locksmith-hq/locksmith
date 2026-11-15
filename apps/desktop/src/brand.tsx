// Drawn parts: the shear-line mark (packages/ui/brand), the cylinder plug and the key-cut blade.
import { useId } from "react";

/** Geometry of packages/ui/brand/locksmith-mark.svg (open) and locksmith-mark-locked.svg. */
export function Mark({ locked = false, size = 24 }: { locked?: boolean; size?: number }) {
  const id = useId();
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="currentColor" aria-hidden="true" className="mark">
      {locked ? (
        <>
          <rect x="6" y="6" width="52" height="52" rx="16" fill="none" stroke="currentColor" strokeWidth="6" />
          <rect x="17" y="14" width="8" height="18" rx="2" /><rect x="28" y="14" width="8" height="9" rx="2" /><rect x="39" y="14" width="8" height="14" rx="2" />
          <rect x="17" y="37" width="8" height="12" rx="2" /><rect x="28" y="28" width="8" height="14" rx="2" /><rect x="39" y="33" width="8" height="13" rx="2" />
        </>
      ) : (
        <>
          <mask id={id}><rect width="64" height="64" fill="#fff" /><rect y="27" width="64" height="5" fill="#000" /></mask>
          <rect x="6" y="6" width="52" height="52" rx="16" fill="none" stroke="currentColor" strokeWidth="6" mask={`url(#${id})`} />
          <rect x="17" y="14" width="8" height="13" rx="2" /><rect x="28" y="14" width="8" height="13" rx="2" /><rect x="39" y="14" width="8" height="13" rx="2" />
          <rect x="17" y="32" width="8" height="17" rx="2" /><rect x="28" y="32" width="8" height="10" rx="2" /><rect x="39" y="32" width="8" height="14" rx="2" />
        </>
      )}
    </svg>
  );
}

/** The cylinder face seen end-on: the keyway turns a quarter when the vault is open. */
export function Plug({ open }: { open: boolean }) {
  return (
    <svg className="plug" data-open={open} width="48" height="48" viewBox="0 0 48 48" aria-hidden="true">
      <circle cx="24" cy="24" r="21.5" className="plug-housing" />
      <circle cx="24" cy="24" r="14.5" className="plug-core" />
      <path d="M24 2.5v5M24 40.5v5M2.5 24h5M40.5 24h5" className="plug-tick" />
      <g className="plug-turn">
        <rect x="22.5" y="12.5" width="3" height="23" rx="1" className="plug-slot" />
        <circle cx="24" cy="16" r="1.75" className="plug-pin" />
        <circle cx="24" cy="24" r="1.75" className="plug-pin" />
        <circle cx="24" cy="32" r="1.75" className="plug-pin" />
      </g>
    </svg>
  );
}

export const SCOPES = ["run", "git", "http", "db", "aws"] as const;
/** Blade drawing, in px at 1:1 so every edge lands on the pixel grid. */
export const CUT = { width: 136, height: 30, pitch: 24, first: 20 } as const;
const pinX = (i: number) => CUT.first + i * CUT.pitch;

/** Bottom edge of the blade, tip at the right: each pin position is cut deep when granted. */
function bladePath(granted: boolean[]) {
  const top = 3.5, base = 24.5, deep = 11.5, shallow = 19.5;
  let d = `M8.5 ${top}H${CUT.width - 10.5}L${CUT.width - 2.5} ${(top + base) / 2}L${CUT.width - 10.5} ${base}`;
  for (let i = SCOPES.length - 1; i >= 0; i--) {
    const x = pinX(i) + 0.5, y = granted[i] ? deep : shallow;
    d += `H${x + 7}L${x + 4} ${y}H${x - 4}L${x - 7} ${base}`;
  }
  return `${d}H8.5Z`;
}

const granted = (scopes: readonly string[]) => SCOPES.filter((s) => scopes.includes(s));

/** The key cut for one session: scopes as cut depths. */
export function KeyCut({ scopes }: { scopes: readonly string[] }) {
  const g = SCOPES.map((s) => scopes.includes(s));
  const on = granted(scopes);
  return (
    <svg
      className="keycut" role="img" width={CUT.width} height={CUT.height}
      viewBox={`0 0 ${CUT.width} ${CUT.height}`}
      aria-label={on.length ? `Scopes granted: ${on.join(", ")}` : "No scopes granted"}
    >
      <path d={bladePath(g)} className="keycut-blade" />
      {/* Granted: a brass pin sits in the cut. Not granted: a hollow pin, present but not cut for. */}
      {g.map((cut, i) => <rect key={i} x={pinX(i) - 2} y={5} width={5} height={4} rx={1} className={cut ? "keycut-pin" : "keycut-pin-empty"} />)}
    </svg>
  );
}

/** Column heading for KeyCut: the scope names over their pin positions. */
export function KeyCutLegend() {
  return (
    <span className="keycut-legend" style={{ width: CUT.width }}>
      Key cut
      <span aria-hidden="true">
        {SCOPES.map((s, i) => <span key={s} style={{ left: pinX(i) + 0.5 }}>{s}</span>)}
      </span>
    </span>
  );
}
