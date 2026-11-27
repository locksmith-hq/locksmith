import { useEffect, useState } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { motion, useReducedMotion } from "motion/react";
import { lease } from "./lease.js";

export interface LeaseTimerProps extends Omit<ComponentProps<"span">, "children"> {
  /** When the lease ends: a `Date`, or milliseconds since 1970. */
  expiresAt: Date | number;
  /** The whole length of the lease in milliseconds, so the ring knows what "full" is. */
  total: number;
  /**
   * What is leased, for screen readers: "Database credential".
   * @default "Lease"
   */
  label?: string;
  /**
   * Width and height of the ring in pixels.
   * @default 20
   */
  size?: number;
  /** Called once, when the lease runs out while the timer is on screen. */
  onExpire?: () => void;
}

// The six segments of the dial ring, clockwise from the top (the Mark's small cut).
const SEGMENTS = [
  "M70.35 21.36A40 40 0 0 1 88.28 31.72",
  "M98.64 49.65A40 40 0 0 1 98.64 70.35",
  "M88.28 88.28A40 40 0 0 1 70.35 98.64",
  "M49.65 98.64A40 40 0 0 1 31.72 88.28",
  "M21.36 70.35A40 40 0 0 1 21.36 49.65",
  "M31.72 31.72A40 40 0 0 1 49.65 21.36",
];

// How long a short-lived credential has left: the dial ring drains a segment at a time, clockwise, next to
// the time. It turns amber in the last third and red in the last sixth. It ticks once a second.
export function LeaseTimer({
  expiresAt,
  total,
  label = "Lease",
  size = 20,
  onExpire,
  className,
  ...props
}: LeaseTimerProps) {
  const end = +expiresAt;
  const [now, setNow] = useState(() => Date.now());
  const still = useReducedMotion();
  const { left, text } = lease(now, end, total);
  const over = now >= end;
  useEffect(() => {
    if (over) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [over]);
  useEffect(() => {
    if (over) onExpire?.();
    // onExpire is left out on purpose: a new callback identity must not fire it again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [over]);
  return (
    <span
      data-slot="lease-timer"
      data-tone={over ? "expired" : left <= 1 / 6 ? "danger" : left <= 1 / 3 ? "warning" : undefined}
      className={cn("lease-timer", className)}
      role="timer"
      aria-label={`${label}: ${over ? "expired" : `${text} left`}`}
      {...props}
    >
      <svg width={size} height={size} viewBox="0 0 120 120" fill="none" strokeWidth={14} aria-hidden="true">
        {SEGMENTS.map((d, i) => {
          // Segment i holds the lease between i/6 and (i+1)/6; the lease drains from the last segment back.
          const fill = Math.min(1, Math.max(0, left * 6 - (5 - i)));
          return (
            <g key={i}>
              <path d={d} className="lease-track" />
              <motion.path
                d={d}
                className="lease-fill"
                initial={false}
                animate={{ pathLength: fill, opacity: fill > 0 ? 1 : 0 }}
                transition={still ? { duration: 0 } : { duration: 0.9, ease: "linear" }}
              />
            </g>
          );
        })}
      </svg>
      <span aria-hidden="true">{text}</span>
    </span>
  );
}
