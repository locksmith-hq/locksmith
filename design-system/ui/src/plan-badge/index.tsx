import type { ComponentProps } from "react";
import { Lock } from "lucide-react";
import { Badge } from "../badge";

export interface PlanBadgeProps extends Omit<ComponentProps<typeof Badge>, "children"> {
  /** The plan that includes the feature, as the person knows it: "Team", "Enterprise". */
  plan: string;
}

// Marks something the current plan does not include, by naming the plan that does: on a navigation item, a
// tab, a setting row or a card. It is a Badge with a lock, so it reads as "locked: Team" to screen readers.
export function PlanBadge({ plan, ...props }: PlanBadgeProps) {
  return (
    <Badge variant="outline" data-plan={plan} {...props}>
      <Lock aria-hidden="true" />
      <span className="sr-only">Needs the </span>
      {plan}
      <span className="sr-only"> plan</span>
    </Badge>
  );
}
