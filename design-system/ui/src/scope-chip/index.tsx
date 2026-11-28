import type { ComponentProps, ReactNode } from "react";
import { cn } from "cn";
import { KeyRound } from "lucide-react";

export interface ScopeChipProps extends ComponentProps<"span"> {
  /** Icon on the tag. Defaults to a key. */
  icon?: ReactNode;
}

// A key tag for one permission an agent holds, such as `repo:read`.
export function ScopeChip({ icon, className, children, ...props }: ScopeChipProps) {
  return (
    <span data-slot="scope-chip" className={cn("ls-scope", className)} {...props}>
      {icon ?? <KeyRound />}
      {children}
    </span>
  );
}
