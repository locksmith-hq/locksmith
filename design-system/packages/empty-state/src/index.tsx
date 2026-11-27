import type { ComponentProps, ReactNode } from "react";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@locksmith-hq/empty";
import { Mark } from "@locksmith-hq/mark";

export interface EmptyStateProps extends Omit<ComponentProps<"div">, "title"> {
  /**
   * Why the slot is empty. `first-use`: nothing was created yet. `no-results`: a filter or search matched
   * nothing. `no-access`: the person lacks the grant. `error`: the load failed.
   * @default "first-use"
   */
  kind?: "first-use" | "no-results" | "no-access" | "error";
  /** What is missing, in a few words: "No agents yet". */
  title: ReactNode;
  /** One sentence on what to do next. */
  children?: ReactNode;
  /** The next step, usually one Button. */
  action?: ReactNode;
  /**
   * `compact` drops the border and shrinks the picture, for inside a table or a card.
   * @default "default"
   */
  size?: "default" | "compact";
}

// The four reasons a slot is empty, on shadcn's Empty. The mark is the picture: open for a slot that can be
// filled, locked for one that cannot. A failed load is announced to screen readers.
export function EmptyState({
  kind = "first-use",
  title,
  children,
  action,
  size = "default",
  ...props
}: EmptyStateProps) {
  const locked = kind === "no-access" || kind === "error";
  return (
    <Empty data-kind={kind} data-size={size} role={kind === "error" ? "alert" : undefined} {...props}>
      <EmptyHeader>
        <EmptyMedia>
          <Mark open={!locked} small={size === "compact"} size={size === "compact" ? 28 : 48} />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {children ? <EmptyDescription>{children}</EmptyDescription> : null}
      </EmptyHeader>
      {action ? <EmptyContent>{action}</EmptyContent> : null}
    </Empty>
  );
}
