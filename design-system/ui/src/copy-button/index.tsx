import { useState } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { Check, Copy } from "lucide-react";
import { useLabels } from "../labels";

export interface CopyButtonProps extends Omit<ComponentProps<"button">, "children" | "value"> {
  /** The text copied to the clipboard. */
  value: string;
  /**
   * What is being copied. It completes the accessible name, as in "Copy id".
   * @default "id"
   */
  label?: string;
}

export function CopyButton({ value, label = "id", className, onClick, ...props }: CopyButtonProps) {
  const t = useLabels();
  const [done, set] = useState(false);
  return (
    <button
      type="button"
      data-slot="copy-button"
      aria-label={done ? t.copied : t.copy(label)}
      className={cn("ls-copy-button", done && "ls-done", className)}
      onClick={(e) => {
        // the clipboard is missing on insecure origins and can be blocked in frames; the tick still shows
        navigator.clipboard?.writeText(value).catch(() => {});
        set(true);
        setTimeout(() => set(false), 1400);
        onClick?.(e);
      }}
      {...props}
    >
      {done ? <Check /> : <Copy />}
    </button>
  );
}
