// Usage and billing for one workspace (mockup, sample data). Prices are placeholders, not decided pricing.
import { useState } from "react";
import "./billing.css";

/** `null` in a limit means "no limit". A per-seat plan's user limit is the number of seats bought. */
interface Plan {
  id: string;
  monthly: number | null;
  yearly: number | null;
  perSeat?: boolean;
  who: string;
  users: number | null;
  projects: number | null;
  requests: number | null;
  features: string[];
}
const PLANS: Plan[] = [
  {
    id: "Free",
    monthly: 0,
    yearly: 0,
    who: "One person, or a few people trying it out",
    users: 3,
    projects: 1,
    requests: 10_000,
    features: ["Agent Gateway and Secret Management", "Audit ledger kept 30 days", "Community support"],
  },
  {
    id: "Team",
    monthly: 49,
    yearly: 39,
    who: "A small team at one fixed price",
    users: 10,
    projects: 10,
    requests: 250_000,
    features: [
      "Everything in Free",
      "Groups, project roles and approvals",
      "Audit ledger kept 1 year",
      "Email support",
    ],
  },
  {
    id: "Business",
    monthly: 12,
    yearly: 10,
    perSeat: true,
    who: "Pay per seat and grow one person at a time",
    users: null,
    projects: null,
    requests: 1_000_000,
    features: ["Everything in Team", "Single sign-on", "Add or remove seats any time"],
  },
  {
    id: "Enterprise",
    monthly: null,
    yearly: null,
    who: "Organizations with compliance needs",
    users: null,
    projects: null,
    requests: null,
    features: [
      "Everything in Business",
      "Custom roles and user provisioning",
      "Your own encryption key",
      "Audit export to your own tools",
      "Dedicated region and support",
    ],
  },
];
// Users, projects, gateway requests: one row per workspace (personal, organization). Agents are never counted or billed.
const USAGE = [
  [1, 1, 1_240],
  [5, 3, 18_420],
];
const METERS = ["Users", "Projects", "Gateway requests this month"];
const INVOICES = [
  { id: "INV-0011", date: "1 Nov 2026", what: "Team, monthly", total: "$49.00" },
  { id: "INV-0010", date: "1 Oct 2026", what: "Team, monthly", total: "$49.00" },
  { id: "INV-0009", date: "1 Sep 2026", what: "Team, monthly", total: "$49.00" },
];
const n = (v: number) => v.toLocaleString("en-US");

export function Billing({
  ws,
  name,
  plan,
  setPlan,
}: {
  ws: number;
  name: string;
  plan: string;
  setPlan: (p: string) => void;
}) {
  const used = USAGE[ws]!;
  const [yearly, setYearly] = useState(false);
  const [choosing, setChoosing] = useState<string | null>(null);
  const [seats, setSeats] = useState(used[0]!); // seats bought on a per-seat plan
  const [draft, setDraft] = useState(seats);
  const now = PLANS.find((p) => p.id === plan)!;
  const price = (p: Plan) => (yearly ? p.yearly : p.monthly);
  const unit = (p: Plan) => (price(p) === 0 ? " forever" : p.perSeat ? " per seat / month" : " / month");
  const limits = (p: Plan) => [p.perSeat ? seats : p.users, p.projects, p.requests];
  const next = PLANS.find((p) => p.id === choosing);
  const total = next && price(next) !== null ? price(next)! * (next.perSeat ? draft : 1) * (yearly ? 12 : 1) : 0;
  const tooFew = !!next?.perSeat && draft < used[0]!;
  return (
    <section className="hub">
      <div className="screen-head">
        <div>
          <h1>Usage and billing</h1>
          <p className="lede">The subscription for {name}. Each workspace has its own plan and its own bill.</p>
        </div>
      </div>

      <div className="panel sub">
        <div>
          <h2>{now.id} plan</h2>
          <p className="muted">
            {now.monthly === 0
              ? "No charge. Nothing to renew."
              : now.monthly === null
                ? "Billed by contract."
                : now.perSeat
                  ? `${seats} seats at $${now.monthly} each, $${n(now.monthly * seats)} a month. Renews 1 Dec 2026.`
                  : `$${now.monthly} a month for up to ${now.users} users. Renews 1 Dec 2026.`}
          </p>
        </div>
        {now.perSeat && (
          <button
            type="button"
            className="btn"
            onClick={() => {
              setDraft(seats);
              setChoosing(now.id);
            }}
          >
            Change seats
          </button>
        )}
        <a
          className="btn"
          href="#plans"
          onClick={(e) => {
            e.preventDefault();
            document.getElementById("plans")?.scrollIntoView({ behavior: "smooth" });
          }}
        >
          Change plan
        </a>
      </div>
      <p className="hint">
        If a payment ever fails, your secrets stay readable and exportable. We never lock you out of your own data over
        a bill.
      </p>

      <div className="sec-h spaced">
        <h2>Usage</h2>
        <span className="n">against the {now.id} plan</span>
      </div>
      <div className="meters">
        {METERS.map((label, i) => {
          const max = limits(now)[i];
          const pct = max ? Math.min(100, (used[i]! / max) * 100) : 0;
          return (
            <div key={label} className="meter" data-high={pct >= 80 || undefined}>
              <span>{i === 0 && now.perSeat ? "Seats in use" : label}</span>
              <b>
                {n(used[i]!)}
                <small> of {max ? n(max) : "unlimited"}</small>
              </b>
              <span className="track" role="img" aria-label={max ? `${Math.round(pct)}% used` : "No limit"}>
                <i style={{ width: `${pct}%` }} />
              </span>
              {max != null && used[i]! > max && (
                <small className="over">Over the limit. Nothing is blocked, but please change plan.</small>
              )}
            </div>
          );
        })}
      </div>

      <div className="sec-h spaced" id="plans">
        <h2>Plans</h2>
        <fieldset className="seg inline" style={{ marginLeft: "auto" }}>
          <legend className="sr-only">Billing period</legend>
          <label>
            <input type="radio" name="period" checked={!yearly} onChange={() => setYearly(false)} />
            Monthly
          </label>
          <label>
            <input type="radio" name="period" checked={yearly} onChange={() => setYearly(true)} />
            Yearly
          </label>
        </fieldset>
      </div>
      <div className="hub-grid plans">
        {PLANS.map((p) => (
          <div key={p.id} className="plan" data-on={p.id === plan || undefined}>
            <h3>
              {p.id}
              {p.id === plan && <span className="badge">Current plan</span>}
            </h3>
            <p className="price">
              {price(p) === null ? (
                "Custom"
              ) : (
                <>
                  ${price(p)}
                  <small>{unit(p)}</small>
                </>
              )}
            </p>
            <p className="muted">{p.who}</p>
            <ul>
              <li>
                {p.perSeat ? "As many users as seats you buy" : p.users ? `${p.users} users` : "Any number of users"}
              </li>
              <li>
                {p.projects ? `${p.projects} ${p.projects === 1 ? "project" : "projects"}` : "Any number of projects"}
              </li>
              <li>{p.requests ? `${n(p.requests)} gateway requests a month` : "Gateway requests by contract"}</li>
              <li>Any number of agents</li>
              {p.features.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
            {p.id === plan ? (
              <button type="button" className="btn" disabled>
                You are on this plan
              </button>
            ) : p.monthly === null ? (
              <a className="btn" href="mailto:sales@locksmith.example">
                Talk to us
              </a>
            ) : (
              <button
                type="button"
                className="btn primary"
                onClick={() => {
                  setDraft(Math.max(seats, used[0]!));
                  setChoosing(p.id);
                }}
              >
                {p.monthly === 0 ? "Move to Free" : `Subscribe to ${p.id}`}
              </button>
            )}
          </div>
        ))}
      </div>
      <p className="hint">Prices on this page are placeholders. Self-hosting Locksmith is free and open source.</p>

      {next && (
        <form
          className="panel form enroll"
          onSubmit={(e) => {
            e.preventDefault();
            if (tooFew) return;
            if (next.perSeat) setSeats(draft);
            if (next.id !== plan) setPlan(next.id);
            setChoosing(null);
          }}
          aria-label="Confirm subscription"
        >
          <h2>
            {next.monthly === 0
              ? `Move ${name} to Free`
              : next.id === plan
                ? `Change seats for ${name}`
                : `Subscribe ${name} to ${next.id}`}
          </h2>
          {next.perSeat && (
            <label className="field seats">
              Seats
              <span className="stepper">
                <button
                  type="button"
                  className="btn sm"
                  aria-label="One seat fewer"
                  onClick={() => setDraft((d) => Math.max(1, d - 1))}
                >
                  −
                </button>
                <input
                  type="number"
                  min={1}
                  value={draft}
                  onChange={(e) => setDraft(Math.max(1, Number(e.target.value) || 1))}
                />
                <button
                  type="button"
                  className="btn sm"
                  aria-label="One seat more"
                  onClick={() => setDraft((d) => d + 1)}
                >
                  +
                </button>
              </span>
            </label>
          )}
          {next.monthly === 0 ? (
            <p className="muted">
              The paid subscription ends at the close of this billing period. Limits drop to 3 users and 1 project;
              nothing is deleted.
            </p>
          ) : next.perSeat ? (
            <p className="muted">
              {draft} seats at ${price(next)} each, billed {yearly ? "once a year" : "every month"}:{" "}
              <b className="strong">
                ${n(total)} {yearly ? "a year" : "a month"}
              </b>
              . {name} has {used[0]} users today.
            </p>
          ) : (
            <p className="muted">
              One fixed price for up to {next.users} users, billed {yearly ? "once a year" : "every month"}:{" "}
              <b className="strong">
                ${n(total)} {yearly ? "a year" : "a month"}
              </b>
              .
            </p>
          )}
          {tooFew && (
            <p className="alert" role="alert" style={{ marginTop: 12 }}>
              You have {used[0]} users. Remove users first, or keep at least {used[0]} seats.
            </p>
          )}
          <div className="inline-form" style={{ marginTop: 14 }}>
            <button type="submit" className="btn primary" disabled={tooFew}>
              {next.monthly === 0 ? "Move to Free" : next.id === plan ? "Update seats" : "Continue to payment"}
            </button>
            <button type="button" className="btn quiet" onClick={() => setChoosing(null)}>
              Cancel
            </button>
          </div>
          {next.monthly !== 0 && (
            <p className="hint">Card details are entered on the payment provider's page, never in Locksmith.</p>
          )}
        </form>
      )}

      {plan === "Team" && (
        <>
          <div className="sec-h spaced">
            <h2>Invoices</h2>
          </div>
          <div className="table-wrap">
            <table className="grid">
              <thead>
                <tr>
                  <th>Invoice</th>
                  <th>Date</th>
                  <th>For</th>
                  <th className="num">Total</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {INVOICES.map((v) => (
                  <tr key={v.id}>
                    <td className="mono">{v.id}</td>
                    <td>{v.date}</td>
                    <td>{v.what}</td>
                    <td className="num">{v.total}</td>
                    <td className="num">
                      <button type="button" className="btn sm quiet">
                        Download
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}
