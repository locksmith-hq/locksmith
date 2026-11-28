import type { ComponentProps } from "react";
import { cn } from "cn";

// The Locksmith mark: a round vault dial. Outer ring in six segments, six bolts thrown out through its gaps,
// a keyhole hub. The bolts are in the brand colour; the ring and hub take the text colour. `open` turns the
// ring 30 degrees and withdraws the bolts. `small` is the bolder cut for
// 16-42px. Geometry matches packages/ui/brand/gen.py.
const C = 60;

function ring(r: number, n: number, gap: number, off: number) {
  const pt = (a: number) =>
    [C + r * Math.cos((a * Math.PI) / 180), C + r * Math.sin((a * Math.PI) / 180)].map((v) => v.toFixed(2)).join(" ");
  let d = "";
  for (let i = 0; i < n; i++) {
    const a0 = off + (i * 360) / n + gap / 2,
      a1 = off + ((i + 1) * 360) / n - gap / 2;
    d += `M${pt(a0)}A${r} ${r} 0 0 1 ${pt(a1)}`;
  }
  return d;
}

const OUTER = ring(42, 6, 20, -90),
  OUTER_SMALL = ring(40, 6, 30, -90),
  INNER = ring(25, 6, 22, -60);

export interface MarkProps extends Omit<ComponentProps<"svg">, "children"> {
  /** Draws the unlocked mark: the ring turns a sixth of a turn and the bolts withdraw. */
  open?: boolean;
  /** The bolder cut, for sizes from 16 to 42 pixels. */
  small?: boolean;
  /** Draws the bolts in the text colour too: for a mark that carries a state colour, or sits inline in text. */
  mono?: boolean;
  /**
   * Width and height in pixels.
   * @default 32
   */
  size?: number;
}

export function Mark({ open = false, small = false, mono = false, size = 32, className, ...props }: MarkProps) {
  const [w, rIn, rOut] = small ? [10, 26, 53] : [7, 25, 52];
  return (
    <svg
      data-slot="mark"
      className={cn("ls-vault-mark", className)}
      data-open={open}
      data-mono={mono || undefined}
      width={size}
      height={size}
      viewBox="0 0 120 120"
      aria-hidden="true"
      {...props}
    >
      <g fill="none" stroke="currentColor" strokeWidth={w}>
        <path className="ls-vm-ring" d={small ? OUTER_SMALL : OUTER} />
        {!small && <path d={INNER} />}
        {[0, 1, 2, 3, 4, 5].map((i) => (
          <g key={i} transform={`rotate(${-90 + i * 60} 60 60)`}>
            <line
              className="ls-vm-bolt"
              x1={C + rIn}
              y1={C}
              x2={C + rOut}
              y2={C}
              style={{ transformOrigin: `${C + rIn}px ${C}px` }}
            />
          </g>
        ))}
      </g>
      <g fill="currentColor">
        <circle cx="60" cy="56" r="8.5" />
        <path d="M55.5 59L53 74H67L64.5 59Z" />
      </g>
    </svg>
  );
}
