"use client";

import * as React from "react";
import { cn } from "cn";
import { Progress as ProgressPrimitive } from "radix-ui";

function Progress({ className, value, ...props }: React.ComponentProps<typeof ProgressPrimitive.Root>) {
  return (
    <ProgressPrimitive.Root
      data-slot="progress"
      // Not in shadcn's source: without the value, screen readers get no reading and the bar is always indeterminate.
      value={value}
      className={cn("relative flex h-1 w-full items-center overflow-x-hidden rounded-full bg-muted", className)}
      {...props}
    >
      <ProgressPrimitive.Indicator
        data-slot="progress-indicator"
        className="size-full flex-1 bg-primary transition-all"
        style={{ transform: `translateX(-${100 - (value || 0)}%)` }}
      />
    </ProgressPrimitive.Root>
  );
}

export interface ProgressRowProps extends Omit<React.ComponentProps<"div">, "children"> {
  /** What is being done: "Rotating keys". */
  label: string;
  /** How far it has got, from 0 to 100. Leave it out while the length is not known. */
  value?: number;
  /** A line under the bar: "8 of 25 keys", or what went wrong. */
  detail?: React.ReactNode;
  /** Colours the bar and the reading: amber or red when the work needs someone. */
  tone?: "warning" | "danger";
}

// Not from shadcn. A Progress with its label above and a mono reading at the right: the percentage while it
// runs, "Done" at 100 and "Working" while the length is unknown.
function ProgressRow({ label, value, detail, tone, className, ...props }: ProgressRowProps) {
  const done = value !== undefined && value >= 100;
  return (
    <div
      data-slot="progress-row"
      data-tone={tone}
      data-done={done || undefined}
      className={cn("progress-row", className)}
      {...props}
    >
      <span className="progress-row-head">
        <span>{label}</span>
        <span className="progress-row-reading">
          {value === undefined ? "Working" : done ? "Done" : `${Math.round(value)}%`}
        </span>
      </span>
      <Progress value={value} aria-label={label} data-tone={tone} />
      {detail ? <span className="progress-row-detail">{detail}</span> : null}
    </div>
  );
}

// The six segments of the dial ring, clockwise from the top.
const SEGMENTS = [
  "M70.35 21.36A40 40 0 0 1 88.28 31.72",
  "M98.64 49.65A40 40 0 0 1 98.64 70.35",
  "M88.28 88.28A40 40 0 0 1 70.35 98.64",
  "M49.65 98.64A40 40 0 0 1 31.72 88.28",
  "M21.36 70.35A40 40 0 0 1 21.36 49.65",
  "M31.72 31.72A40 40 0 0 1 49.65 21.36",
];

export interface ProgressRingProps extends Omit<React.ComponentProps<"svg">, "children"> {
  /** How far the work has got, from 0 to 100. Leave it out while the length is not known, and the ring turns. */
  value?: number;
  /**
   * Width and height in pixels.
   * @default 20
   */
  size?: number;
  /**
   * What is in progress, for screen readers.
   * @default "Progress"
   */
  label?: string;
  /** Colours the ring: amber or red when the work needs someone, green for something live. */
  tone?: "warning" | "danger" | "live";
}

// Not from shadcn. Progress where a bar does not fit, such as a table cell, a tab or a button: the dial ring,
// filling clockwise a segment at a time.
function ProgressRing({ value, size = 20, label = "Progress", tone, className, ...props }: ProgressRingProps) {
  const done = Math.min(100, Math.max(0, value ?? 0)) / 100;
  return (
    <svg
      data-slot="progress-ring"
      data-tone={tone}
      data-state={value === undefined ? "indeterminate" : done >= 1 ? "complete" : "loading"}
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value === undefined ? undefined : Math.round(done * 100)}
      width={size}
      height={size}
      viewBox="0 0 120 120"
      fill="none"
      strokeWidth={14}
      className={cn("progress-ring", className)}
      {...props}
    >
      {SEGMENTS.map((d, i) => {
        const fill = value === undefined ? (i < 2 ? 1 : 0) : Math.min(1, Math.max(0, done * 6 - i));
        return (
          <g key={i}>
            <path d={d} className="progress-ring-track" />
            {fill > 0 ? (
              <path d={d} className="progress-ring-fill" pathLength={1} strokeDasharray={`${fill} 1`} />
            ) : null}
          </g>
        );
      })}
    </svg>
  );
}

export { Progress, ProgressRow, ProgressRing };
