import type { ComponentProps, ReactNode } from "react";

/** App-level layout built from Tailwind utilities; controls and tokens come from @locksmith-hq/ui. */
const join = (...c: (string | false | undefined)[]) => c.filter(Boolean).join(" ");

/** Inline code; `cmd` puts a command to copy into a terminal on its own line. */
export const InlineCode = ({ cmd, className, ...p }: ComponentProps<"code"> & { cmd?: boolean }) => (
  <code
    className={join(
      "rounded-sm bg-muted px-[5px] py-px text-[length:var(--font-size-xs)] text-(--chip-text)",
      cmd && "block w-fit max-w-full border px-2.5 py-1.5 [overflow-wrap:anywhere]",
      className,
    )}
    {...p}
  />
);

/** Section heading with an optional count (`SecCount`) and a link or button on the right. */
export const SecH = ({ spaced, tight, children }: { spaced?: boolean; tight?: boolean; children: ReactNode }) => (
  <div
    className={join(
      "flex items-baseline gap-2.5 [&>button]:ml-auto [&>h2]:m-0 [&>h2]:text-[length:var(--font-size-lg)] [&>h2]:leading-[22px] [&>h2]:font-semibold",
      tight ? "mb-1.5 px-2.5" : "mb-3",
      spaced && "mt-8",
    )}
  >
    {children}
  </div>
);
export const SecCount = ({ children }: { children: ReactNode }) => (
  <span className="text-[length:var(--font-size-sm)] text-muted-foreground">{children}</span>
);

/** A quiet line under a heading. */
export const Quiet = ({ className, ...p }: ComponentProps<"p">) => (
  <p className={join("m-0 border-t px-2.5 py-3 text-muted-foreground", className)} {...p} />
);

/** A note under a list, with an optional leading icon; `bad` turns it into a warning. */
export const LogFoot = ({ bad, className, ...p }: ComponentProps<"p"> & { bad?: boolean }) => (
  <p
    className={join(
      "mt-2.5 mb-0 flex items-center gap-2 px-2.5 text-[length:var(--font-size-xs)] [&>svg]:size-3.5",
      bad
        ? "font-semibold text-(--destructive-text) [&>svg]:text-(--destructive-text)"
        : "text-muted-foreground [&>svg]:text-(--live-text)",
      className,
    )}
    {...p}
  />
);

/** A bordered list of rows. */
export const ROWS = "m-0 list-none rounded-[var(--radius-xl)] border bg-card p-0 [&>li+li]:border-t";

/** Name over detail lines, for a card cell. */
export const WHO =
  "min-w-0 [&>b]:flex [&>b]:items-center [&>b]:gap-2 [&>b]:font-semibold [&>span]:mt-0.5 [&>span]:block [&>span]:truncate [&>span]:text-[length:var(--font-size-sm)] [&>span]:leading-[18px] [&>span]:text-muted-foreground";
