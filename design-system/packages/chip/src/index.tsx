import type { ComponentProps } from "react";
import { cn } from "cn";
import { X } from "lucide-react";

export interface ChipProps extends ComponentProps<"span"> {
  /** Adds a remove button and is called when it is pressed. */
  onRemove?: () => void;
}

// One picked value. The small cross removes it.
export function Chip({ onRemove, className, children, ...props }: ChipProps) {
  return (
    <span data-slot="chip" className={cn("chip", className)} {...props}>
      {children}
      {onRemove ? (
        <button
          type="button"
          aria-label={`Remove ${typeof children === "string" ? children : ""}`.trim()}
          onClick={onRemove}
        >
          <X />
        </button>
      ) : null}
    </span>
  );
}
