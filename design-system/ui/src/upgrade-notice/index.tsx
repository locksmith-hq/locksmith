import type { ComponentProps, ReactNode } from "react";
import { EmptyState } from "../empty-state";
import { PlanBadge } from "../plan-badge";

export interface UpgradeNoticeProps extends Omit<ComponentProps<typeof EmptyState>, "kind" | "title"> {
  /** The plan that includes the feature: "Team", "Enterprise". */
  plan: string;
  /** What the person cannot use yet, in a few words: "Secret rotation". */
  title: ReactNode;
  /** One or two sentences on what the feature does, so the person can judge whether they want it. */
  children?: ReactNode;
  /** The way forward, usually one Button: see plans in the cloud, add a licence when self-hosted. */
  action?: ReactNode;
}

// Stands where a page or a section would be when the organization's plan does not include it. It says what
// the feature is and which plan has it, and offers one next step. It never hides that the feature exists.
export function UpgradeNotice({ plan, title, ...props }: UpgradeNoticeProps) {
  return (
    <EmptyState
      kind="no-access"
      data-upgrade={plan}
      title={
        <span className="inline-flex flex-wrap items-center justify-center gap-2">
          {title}
          <PlanBadge plan={plan} />
        </span>
      }
      {...props}
    />
  );
}
