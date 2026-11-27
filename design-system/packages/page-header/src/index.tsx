import type { ComponentProps, ReactNode } from "react";
import { cn } from "cn";

export interface PageHeaderProps extends Omit<ComponentProps<"div">, "title"> {
  /** The page's `h1`. */
  title: string;
  /** One line under the title that says what the page holds. */
  lede?: ReactNode;
}

// One per screen: what this is, and its main actions (the children) on the right.
export function PageHeader({ title, lede, className, children, ...props }: PageHeaderProps) {
  return (
    <div data-slot="page-header" className={cn("screen-head", className)} {...props}>
      <div>
        <h1>{title}</h1>
        {lede ? <p className="lede">{lede}</p> : null}
      </div>
      {children}
    </div>
  );
}
