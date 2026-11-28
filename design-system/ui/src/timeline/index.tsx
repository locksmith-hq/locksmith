import type { ComponentProps, ReactNode } from "react";
import { cn } from "cn";
import { Badge } from "../badge";

export interface TimelineProps extends Omit<ComponentProps<"ol">, "children"> {
  /** The events, newest first. `when` is the time text, `by: "agent"` adds the agent badge, `tone` colours the lamp and `children` is the detail line. */
  items: { title: ReactNode; when: string; by?: "agent"; tone?: "live" | "warning" | "danger"; children?: ReactNode }[];
}

// What happened, newest first, on a rail of lamps: the Pill's lamp for the tone, violet for anything an agent did.
export function Timeline({ items, className, ...props }: TimelineProps) {
  return (
    <ol data-slot="timeline" className={cn("ls-timeline", className)} {...props}>
      {(items || []).map((it, i) => (
        <li key={i} data-tone={it.tone} data-by={it.by}>
          <div className="ls-timeline-head">
            <span>
              {it.title}
              {it.by ? (
                <>
                  {" "}
                  <Badge data-by="agent">by agent</Badge>
                </>
              ) : null}
            </span>
            <time>{it.when}</time>
          </div>
          {it.children ? <div className="ls-muted">{it.children}</div> : null}
        </li>
      ))}
    </ol>
  );
}
