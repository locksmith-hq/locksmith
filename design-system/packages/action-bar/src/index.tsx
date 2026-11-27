import type { ComponentProps } from "react";
import { cn } from "cn";
import { Button } from "@locksmith-hq/button";

export interface ActionBarProps extends ComponentProps<"div"> {
  /** How many things are selected. The bar is not rendered at 0. */
  count: number;
  /** Called when the person clears the selection. */
  onClear: () => void;
  /**
   * What the selected things are, for the accessible name: "agents", "secrets".
   * @default "items"
   */
  noun?: string;
}

// Appears when rows are selected: how many, what can be done to all of them (the children), and a way out.
export function ActionBar({ count, onClear, noun = "items", className, children, ...props }: ActionBarProps) {
  if (count <= 0) return null;
  return (
    <div
      data-slot="action-bar"
      className={cn("action-bar", className)}
      role="toolbar"
      aria-label={`Actions for selected ${noun}`}
      {...props}
    >
      <span className="action-count" role="status">
        <b>{count}</b> selected
      </span>
      {children}
      <Button variant="ghost" size="sm" onClick={onClear}>
        Clear
      </Button>
    </div>
  );
}
