// The seam for what is not open source. The console in this repository is the free product. Paid pages and the
// billing page live in the private locksmith-cloud repository; its build copies them into ./paid (git-ignored
// here), and each file there calls registerPaid. Nothing in this repository may import from ./paid: the open
// build must work with the folder empty, and then every paid page shows its upgrade notice.
import type { ComponentType } from "react";
import type { Plan, PlanId } from "./plans";

export interface Paid {
  /** Pages by the same key the open pages use ("secrets/rotation"), plus "members/groups" and "notifications/channels". */
  // Each page declares its own props; the place that renders it passes what that page takes.
  pages: Record<string, ComponentType<any>>; // eslint-disable-line @typescript-eslint/no-explicit-any
  /** The usage and billing page. Without it the console has no billing link: a self-hosted install has no bill. */
  billing?: ComponentType<{ ws: number; name: string; plan: PlanId; setPlan: (p: PlanId) => void }>;
  /** The plan catalog with its limits. Without it nothing is limited, as when self-hosted. */
  plans?: Plan[];
}

export const paid: Paid = { pages: {} };

export function registerPaid(more: Partial<Paid>) {
  Object.assign(paid.pages, more.pages);
  if (more.billing) paid.billing = more.billing;
  if (more.plans) paid.plans = more.plans;
}
