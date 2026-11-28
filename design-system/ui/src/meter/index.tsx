import type { ComponentProps } from "react";
import { cn } from "cn";

export interface MeterProps extends Omit<ComponentProps<"div">, "children"> {
  /** What is measured. */
  label: string;
  /** The amount used. */
  value: number;
  /** The limit. */
  max: number;
  /** Text after each number, such as `GB`. */
  unit?: string;
}

// Usage against a limit, read like a depth gauge: ten notches, amber from 80%, red when the limit is reached.
export function Meter({ label, value, max, unit = "", className, ...props }: MeterProps) {
  const r = max > 0 ? value / max : 0;
  return (
    <div
      data-slot="meter"
      className={cn("ls-meter", className)}
      data-tone={r >= 1 ? "danger" : r >= 0.8 ? "warning" : undefined}
      {...props}
    >
      <div className="ls-meter-head">
        <span>{label}</span>
        <span className="ls-mono">
          {value}
          {unit} / {max}
          {unit}
        </span>
      </div>
      <div
        className="ls-meter-track"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={value}
      >
        <span style={{ width: `${Math.min(Math.max(r, 0), 1) * 100}%` }} />
      </div>
    </div>
  );
}
