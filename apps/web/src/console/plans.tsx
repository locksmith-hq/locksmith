// Which plan each feature needs, and the lock that stands in for a feature the workspace's plan lacks. The
// prices and limits (the plan catalog) are not here: they come from the billing module, which is not open
// source (see paid.ts). Without it nothing is limited, as in a self-hosted install.
import { createContext, useContext } from "react";
import { Button } from "@locksmith-hq/ui/button";
import { PlanBadge } from "@locksmith-hq/ui/plan-badge";
import { UpgradeNotice } from "@locksmith-hq/ui/upgrade-notice";
import { paid } from "./paid";

export type PlanId = "Free" | "Team" | "Enterprise";

export interface Plan {
  id: PlanId;
  /** Price per month in dollars: per seat when `perSeat`. Null is "by quote". */
  monthly: number | null;
  /** The monthly price when billed yearly. */
  yearly: number | null;
  perSeat?: boolean;
  minSeats?: number;
  who: string;
  /** Null is unlimited. */
  users: number | null;
  projects: number | null;
  agents: number | null;
  identities: number | null;
  requests: number | null;
  auditDays: number | null;
  /** What going over an included amount costs, where the plan allows it. */
  overage?: string;
  features: string[];
}

const RANK: Record<PlanId, number> = { Free: 0, Team: 1, Enterprise: 2 };

/** What is not in every plan: the plan that has it, its name, and one line on what it does. */
export const FEATURES = {
  groups: {
    plan: "Team",
    title: "Groups and project roles",
    about: "Give access to a group once instead of person by person, and choose what each role may do in a project.",
  },
  approvals: {
    plan: "Team",
    title: "Approvals from other people",
    about:
      "Send an agent's or a teammate's request to another person or a group to approve. Approving your own agent's requests is in every plan.",
  },
  rotation: {
    plan: "Team",
    title: "Secret rotation",
    about: "Replace a secret on a schedule, everywhere it is used, without anyone handling the new value.",
  },
  channels: {
    plan: "Team",
    title: "Email, Slack and webhook notifications",
    about: "Send notifications where your team already looks. The in-app inbox is in every plan.",
  },
  sso: {
    plan: "Team",
    title: "Single sign-on",
    about: "People sign in through your identity provider, with OIDC or SAML.",
  },
  dynamic: {
    plan: "Enterprise",
    title: "Dynamic secrets",
    about: "Credentials made for one session and gone when it ends, so there is no standing secret to leak.",
  },
  scim: {
    plan: "Enterprise",
    title: "User provisioning",
    about: "Your identity provider adds and removes people through SCIM.",
  },
  customRoles: {
    plan: "Enterprise",
    title: "Custom roles",
    about: "Define your own roles from the full list of permissions.",
  },
  streaming: {
    plan: "Enterprise",
    title: "Audit streaming",
    about: "Send every audit event to your own SIEM as it happens. Audit file export is in every plan.",
  },
} as const satisfies Record<string, { plan: PlanId; title: string; about: string }>;
export type Feature = keyof typeof FEATURES;

/** True when `plan` does not include the feature. */
export const lacks = (plan: PlanId, feature: Feature) => RANK[plan] < RANK[FEATURES[feature].plan];

/** A plan's limits on users and projects. Null is unlimited, which is also the answer with no catalog. */
export const planOf = (plan: PlanId): Pick<Plan, "users" | "projects"> =>
  paid.plans?.find((p) => p.id === plan) ?? { users: null, projects: null };

/** The plan of the workspace on screen. */
export const PlanContext = createContext<PlanId>("Free");

/** True when the workspace's plan does not include the feature. */
export function useLocked(feature: Feature) {
  return lacks(useContext(PlanContext), feature);
}

/** The plan's name with a lock, shown only while the feature is locked. */
export function GateBadge({ feature }: { feature: Feature }) {
  return useLocked(feature) ? <PlanBadge plan={FEATURES[feature].plan} /> : null;
}

/** The notice that stands in place of a locked page or section. */
export function Locked({ feature, size }: { feature: Feature; size?: "default" | "compact" }) {
  const f = FEATURES[feature];
  return (
    <UpgradeNotice
      size={size}
      plan={f.plan}
      title={f.title}
      action={
        f.plan === "Enterprise" || !paid.billing ? (
          <Button asChild variant="outline">
            <a href="mailto:sales@locksmith.example">Talk to us</a>
          </Button>
        ) : (
          <Button asChild>
            <a href="#/billing">See plans</a>
          </Button>
        )
      }
    >
      {f.about}
    </UpgradeNotice>
  );
}

/** The feature a console address needs, if it is not in every plan. */
export function gateOf(route: string[]): Feature | undefined {
  const [page, , tab] = route;
  if (page === "secrets" && tab === "rotation") return "rotation";
  if (page === "secrets" && tab === "dynamic") return "dynamic";
  if (page === "secrets" && tab === "approvals") return "approvals";
  return undefined;
}
