import type { ComponentProps } from "react";
import { cn } from "cn";
import { X } from "lucide-react";
import { useLabels } from "../labels";

export interface ChipProps extends ComponentProps<"span"> {
  /** Adds a remove button and is called when it is pressed. */
  onRemove?: () => void;
}

// One picked value. The small cross removes it.
export function Chip({ onRemove, className, children, ...props }: ChipProps) {
  const t = useLabels();
  return (
    <span data-slot="chip" className={cn("ls-chip", className)} {...props}>
      {children}
      {onRemove ? (
        <button type="button" aria-label={t.remove(typeof children === "string" ? children : "")} onClick={onRemove}>
          <X />
        </button>
      ) : null}
    </span>
  );
}
