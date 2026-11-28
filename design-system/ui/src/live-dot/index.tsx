import type { ComponentProps } from "react";
import { cn } from "cn";

export interface LiveDotProps extends Omit<ComponentProps<"span">, "children"> {
  /**
   * The slow halo pulse. Set `false` for a still dot.
   * @default true
   */
  pulse?: boolean;
  /** Accessible name. Without it the dot is decorative. */
  label?: string;
}

export function LiveDot({ pulse = true, label, className, ...props }: LiveDotProps) {
  return (
    <span
      data-slot="live-dot"
      className={cn("ls-live-dot", pulse && "ls-pulse", className)}
      role={label ? "img" : undefined}
      aria-label={label}
      {...props}
    />
  );
}
