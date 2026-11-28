import type { ComponentProps } from "react";
import { cn } from "cn";
import { LiveDot } from "../live-dot";

export interface PillProps extends ComponentProps<"span"> {
  /** `live` adds the live dot; `warning` and `danger` colour the lamp. Without a tone the pill is idle. */
  tone?: "live" | "warning" | "danger";
}

// A status: an indicator lamp on a small plate. Use shadcn's Badge for labels that are not a state.
export function Pill({ tone, className, children, ...props }: PillProps) {
  return (
    <span
      data-slot="pill"
      className={cn("ls-pill", className)}
      data-up={tone === "live" ? "true" : undefined}
      data-tone={tone === "warning" || tone === "danger" ? tone : undefined}
      {...props}
    >
      {tone === "live" ? <LiveDot /> : null}
      {children}
    </span>
  );
}
