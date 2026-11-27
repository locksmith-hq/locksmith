import type { ComponentProps } from "react";
import { cn } from "cn";
import { CopyButton } from "@locksmith-hq/copy-button";

export interface CopyableIdProps extends Omit<ComponentProps<"span">, "children"> {
  /** The id. A type prefix up to the first underscore (`agt_`, `sec_`) is shown as a small tag. The whole value is copied. */
  value: string;
  /** What the id is, for the copy button's accessible name. */
  label?: string;
}

export function CopyableId({ value, label, className, ...props }: CopyableIdProps) {
  const at = value.indexOf("_"); // an id without a type prefix shows whole, with no tag
  return (
    <span data-slot="copyable-id" className={cn("copyid", className)} {...props}>
      {at > 0 ? <span className="copyid-tag">{value.slice(0, at)}</span> : null}
      <span title={value}>{value.slice(at > 0 ? at + 1 : 0)}</span>
      <CopyButton value={value} label={label} />
    </span>
  );
}
