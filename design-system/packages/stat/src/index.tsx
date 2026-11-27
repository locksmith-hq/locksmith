import type { ComponentProps, ReactNode } from "react";
import { cn } from "cn";
import { ArrowDownRight, ArrowUpRight } from "lucide-react";

export interface StatProps extends Omit<ComponentProps<"div">, "children"> {
  /** What is counted. */
  label: string;
  /** The count, shown in mono. */
  value: ReactNode;
  /** A short unit after the value: "ms", "%", "/ 50". */
  unit?: string;
  /** A line under the value. */
  note?: ReactNode;
  /** Colours the readout: amber or red when the count needs someone, green when it reports something live. */
  tone?: "warning" | "danger" | "live";
  /**
   * How the count moved. `value` is the text ("12%"), `direction` the arrow, and `good` colours it: green when
   * the move is welcome, red when it is not, grey when left out.
   */
  trend?: { value: string; direction: "up" | "down"; good?: boolean };
  /** Recent values, oldest first, drawn as a small line under the count. Needs at least two. */
  spark?: number[];
}

// The points of the sparkline, in a 100 by 28 box with the newest value at the right.
function line(values: number[]): string {
  const lo = Math.min(...values),
    hi = Math.max(...values);
  return values
    .map(
      (v, i) => `${((i / (values.length - 1)) * 100).toFixed(1)},${(25 - ((v - lo) / (hi - lo || 1)) * 22).toFixed(1)}`,
    )
    .join(" ");
}

// One count as an instrument readout: a lamp and a label, the number in mono, and optionally how it moved
// and its recent history. The corner marks and the lamp take the tone.
export function Stat({ label, value, unit, note, tone, trend, spark, className, ...props }: StatProps) {
  const points = spark && spark.length > 1 ? line(spark) : null;
  return (
    <div data-slot="stat" className={cn("stat", className)} data-tone={tone} {...props}>
      <span className="stat-label">{label}</span>
      <span className="stat-row">
        <span className="stat-value">{value}</span>
        {unit ? <span className="stat-unit">{unit}</span> : null}
        {trend ? (
          <span className="stat-trend" data-good={trend.good}>
            {trend.direction === "up" ? <ArrowUpRight /> : <ArrowDownRight />}
            <span className="sr-only">{trend.direction === "up" ? "Up" : "Down"} </span>
            {trend.value}
          </span>
        ) : null}
      </span>
      {points ? (
        <svg className="stat-spark" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true">
          <polygon points={`0,28 ${points} 100,28`} />
          <polyline points={points} />
        </svg>
      ) : null}
      {note ? <span className="stat-note">{note}</span> : null}
    </div>
  );
}
