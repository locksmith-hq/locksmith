import { Fragment } from "react";
import type { ComponentProps, ReactNode } from "react";
import { cn } from "cn";

export interface FactsProps extends Omit<ComponentProps<"dl">, "children"> {
  /** The label and value pairs. */
  items: { label: string; value: ReactNode }[];
}

// What is known about one thing, as label and value.
export function Facts({ items, className, ...props }: FactsProps) {
  return (
    <dl data-slot="facts" className={cn("facts", className)} {...props}>
      {(items || []).map((f, i) => (
        <Fragment key={i}>
          <dt>{f.label}</dt>
          <dd>{f.value}</dd>
        </Fragment>
      ))}
    </dl>
  );
}
