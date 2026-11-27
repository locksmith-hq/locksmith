import type { ComponentProps } from "react";
import { cn } from "cn";

export interface TumblersProps extends Omit<ComponentProps<"span">, "children"> {
  /**
   * Text for screen readers; it is not shown.
   * @default "Working"
   */
  label?: string;
}

// Five pin tumblers that rise to the shear line one by one, then drop: a wait with no known length that is
// about access (signing in, unlocking, checking a grant), where the dial would be too heavy.
export function Tumblers({ label = "Working", className, ...props }: TumblersProps) {
  return (
    <span data-slot="tumblers" className={cn("tumblers", className)} role="status" {...props}>
      {[0, 1, 2, 3, 4].map((i) => (
        <i key={i} style={{ animationDelay: `${i * 110}ms` }} />
      ))}
      <span className="sr-only">{label}</span>
    </span>
  );
}
