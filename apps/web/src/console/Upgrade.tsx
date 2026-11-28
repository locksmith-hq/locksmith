// The Upgrade page of the open console: what each plan adds, and the way to the next one. It shows no prices:
// the plan catalog is in the billing module (see paid.ts). With that module the button goes to its page; without
// it the console, which runs on sample data, just moves the workspace to the plan.
import { Badge } from "@locksmith-hq/ui/badge";
import { Button } from "@locksmith-hq/ui/button";
import { Card } from "@locksmith-hq/ui/card";
import { Head } from "./kit";
import { paid } from "./paid";
import { FEATURES, type PlanId } from "./plans";

const PLANS: { id: PlanId; who: string }[] = [
  { id: "Free", who: "One person or a small project, with everything needed to keep secrets from agents." },
  {
    id: "Team",
    who: "Teams that share projects: groups, approvals from other people and notifications where you work.",
  },
  { id: "Enterprise", who: "Companies with an identity provider, audit pipelines and their own roles." },
];
const ORDER: PlanId[] = ["Free", "Team", "Enterprise"];

export function Upgrade({ name, plan, setPlan }: { name: string; plan: PlanId; setPlan: (p: PlanId) => void }) {
  return (
    <section>
      <Head title="Upgrade" sub={`${name} is on the ${plan} plan. What the other plans add:`} />
      <div className="plans">
        {PLANS.map((p) => {
          const adds = Object.values(FEATURES).filter((f) => f.plan === p.id);
          const current = p.id === plan;
          const above = ORDER.indexOf(p.id) > ORDER.indexOf(plan);
          return (
            <Card key={p.id} className="panel plan" data-current={current || undefined}>
              <div className="plan-head">
                <h2>
                  {p.id} {current && <Badge>Current plan</Badge>}
                </h2>
                {above &&
                  (p.id === "Enterprise" ? (
                    <Button asChild variant="outline">
                      <a href="mailto:sales@locksmith.example">Talk to us</a>
                    </Button>
                  ) : paid.billing ? (
                    <Button asChild>
                      <a href="#/billing">Upgrade to {p.id}</a>
                    </Button>
                  ) : (
                    <Button type="button" onClick={() => setPlan(p.id)}>
                      Upgrade to {p.id}
                    </Button>
                  ))}
              </div>
              <p className="muted">{p.who}</p>
              {adds.length > 0 && (
                <ul className="plan-adds">
                  {adds.map((f) => (
                    <li key={f.title}>{f.title}</li>
                  ))}
                </ul>
              )}
            </Card>
          );
        })}
      </div>
    </section>
  );
}
