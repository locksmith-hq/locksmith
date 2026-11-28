// The billing page of the open console: the plan the workspace is on and how it pays. Without prices, invoices
// and usage: those are the billing module's (see paid.ts), which replaces this page when a build has it.
import { Badge } from "@locksmith-hq/ui/badge";
import { Button } from "@locksmith-hq/ui/button";
import { Card } from "@locksmith-hq/ui/card";
import { Head } from "./kit";
import { FEATURES, type PlanId } from "./plans";

// Sample data: the console is not connected to a payment provider.
const CARD = { brand: "Visa", last4: "4242", expires: "08/2028", email: "billing@acme.example" };

export function PlanAndBilling({
  name,
  plan,
}: {
  ws: number;
  name: string;
  plan: PlanId;
  setPlan: (p: PlanId) => void;
}) {
  const paying = plan !== "Free";
  const adds = Object.values(FEATURES).filter((f) => f.plan === plan);
  return (
    <section>
      <Head title="Plan and billing" sub={`The plan ${name} is on, and how it pays.`} />
      <Card className="panel">
        <h2>
          Current plan <Badge>{plan}</Badge>
        </h2>
        {adds.length > 0 ? (
          <>
            <p className="muted">What {plan} adds to Free:</p>
            <ul className="plain">
              {adds.map((f) => (
                <li key={f.title}>{f.title}</li>
              ))}
            </ul>
          </>
        ) : (
          <p className="muted">Everything in the open product, with no limits on what you keep.</p>
        )}
        {plan !== "Enterprise" && (
          <Button asChild style={{ marginTop: 12 }}>
            <a href="#/upgrade">Upgrade</a>
          </Button>
        )}
      </Card>
      <Card className="panel">
        <h2>Payment method</h2>
        {paying ? (
          <ul className="plain">
            <li>
              <span>
                {CARD.brand} ending {CARD.last4}
              </span>
              <span className="muted">Expires {CARD.expires}</span>
            </li>
            <li>
              <span>Invoices go to</span>
              <span className="muted">{CARD.email}</span>
            </li>
          </ul>
        ) : (
          <p className="muted">No payment method. You add one when you upgrade.</p>
        )}
      </Card>
    </section>
  );
}
