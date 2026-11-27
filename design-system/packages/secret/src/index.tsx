import { useState } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { Lock, LockOpen } from "lucide-react";
import { CopyButton } from "@locksmith-hq/copy-button";

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
  const [shown, show] = useState(false);
  return (
    <span data-slot="secret" className={cn("copyid secret", className)} {...props}>
      {shown ? (
        <span>{value}</span>
      ) : (
        <span className="sealed" role="img" aria-label="Hidden value">
          ************
        </span>
      )}
      <button
        type="button"
        className="copy-button"
        aria-pressed={shown}
        aria-label={shown ? "Hide value" : "Reveal value"}
        onClick={() => show(!shown)}
      >
        {shown ? <LockOpen /> : <Lock />}
      </button>
      <CopyButton value={value} label={label} />
    </span>
  );
}
