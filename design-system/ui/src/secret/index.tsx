import { useState } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { Lock, LockOpen } from "lucide-react";
import { CopyButton } from "../copy-button";
import { useLabels } from "../labels";

export interface SecretProps extends Omit<ComponentProps<"span">, "children"> {
  /** The secret. It is in the page only while revealed; hidden, twelve asterisks are shown whatever its length, so the length does not leak. */
  value: string;
  /**
   * What the value is, for the copy button's accessible name.
   * @default "value"
   */
  label?: string;
}

// A secret value: sealed (always twelve asterisks, so the length does not leak) until it is unlocked.
export function Secret({ value, label = "value", className, ...props }: SecretProps) {
  const t = useLabels();
  const [shown, show] = useState(false);
  return (
    <span data-slot="secret" className={cn("ls-copyid ls-secret", className)} {...props}>
      {shown ? (
        <span>{value}</span>
      ) : (
        <span className="ls-sealed" role="img" aria-label={t.hiddenValue}>
          ************
        </span>
      )}
      <button
        type="button"
        className="ls-copy-button"
        aria-pressed={shown}
        aria-label={shown ? t.hideValue : t.revealValue}
        onClick={() => show(!shown)}
      >
        {shown ? <LockOpen /> : <Lock />}
      </button>
      <CopyButton value={value} label={label} />
    </span>
  );
}
