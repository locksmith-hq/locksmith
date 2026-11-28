import type { ComponentProps } from "react";
import { cn } from "cn";

export interface LinkProps extends ComponentProps<"a"> {
  /** Opens in a new tab, shows an arrow, and tells screen readers so. Use for links that leave the product. */
  external?: boolean;
}

export function Link({ external, className, children, ...props }: LinkProps) {
  return (
    <a
      data-slot="link"
      className={cn("ls-link", className)}
      data-external={external || undefined}
      {...(external ? { target: "_blank", rel: "noreferrer" } : {})}
      {...props}
    >
      {children}
      {external ? <span className="sr-only"> (opens in a new tab)</span> : null}
    </a>
  );
}
