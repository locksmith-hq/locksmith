// Twenty component ideas for the Locksmith brand, as live sketches with an honest verdict on each.
// Prototypes for discussion only: none of this is in the kit. Open #/ideas.
import { useState } from "react";
import type { ReactNode } from "react";
import { motion } from "motion/react";
import { Bot, ChevronRight, Key, Link2, Siren, Unlink } from "lucide-react";
import { Button } from "@locksmith-hq/ui/button";
import { Mark } from "@locksmith-hq/ui/mark";
import "./ideas.css";

const spring = { type: "spring", stiffness: 320, damping: 24 } as const;
type Verdict = "build" | "sparingly" | "too much";
const VERDICT: Record<Verdict, string> = { build: "Build it", sparingly: "Use sparingly", "too much": "Too much" };

function Idea(p: { n: number; name: string; verdict: Verdict; what: string; take: string; children: ReactNode }) {
  return (
    <article className="idea" data-verdict={p.verdict}>
      <header>
        <span className="idea-n">{String(p.n).padStart(2, "0")}</span>
        <h2>{p.name}</h2>
        <span className="idea-verdict">{VERDICT[p.verdict]}</span>
      </header>
      <p className="idea-what">{p.what}</p>
      <div className="idea-stage">{p.children}</div>
      <p className="idea-take">{p.take}</p>
    </article>
  );
}

function KeyRing() {
  const [open, setOpen] = useState(false);
  const who = ["DO", "RM", "LF", "SI", "TL"];
  return (
    <div className="keyring" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>
      <span className="keyring-loop" />
      {who.map((w, i) => (
        <motion.span
          key={w}
          className="keyring-key"
          animate={{ x: open ? i * 38 : i * 12, rotate: open ? 0 : (i - 2) * 7 }}
          transition={spring}
        >
          {w}
        </motion.span>
      ))}
    </div>
  );
}

function VaultDoor() {
  const [open, setOpen] = useState(false);
  return (
    <div className="ls-vault">
      <div className="vault-inside">
        <b>DATABASE_URL</b>
        <span>postgres://app:example@db.internal/prod</span>
      </div>
      <motion.div
        className="vault-door left"
        animate={{ x: open ? "-100%" : 0 }}
        transition={{ ...spring, delay: open ? 0.45 : 0 }}
      />
      <motion.div
        className="vault-door right"
        animate={{ x: open ? "100%" : 0 }}
        transition={{ ...spring, delay: open ? 0.45 : 0 }}
      />
      <motion.button
        type="button"
        className="vault-lock"
        aria-label={open ? "Close the vault" : "Open the vault"}
        animate={{ opacity: open ? 0 : 1, scale: open ? 0.6 : 1 }}
        transition={{ delay: open ? 0.35 : 0.3 }}
        onClick={() => setOpen(true)}
      >
        <Mark open={open} size={44} />
      </motion.button>
      {open ? (
        <Button size="sm" variant="outline" className="vault-close" onClick={() => setOpen(false)}>
          Seal
        </Button>
      ) : null}
    </div>
  );
}

function DualControl() {
  const [a, setA] = useState(false);
  const [b, setB] = useState(false);
  const slot = (on: boolean, set: (v: boolean) => void, who: string) => (
    <button type="button" className="dual-slot" data-on={on || undefined} aria-pressed={on} onClick={() => set(!on)}>
      <motion.span animate={{ rotate: on ? 90 : 0 }} transition={spring}>
        <Key />
      </motion.span>
      <small>{who}</small>
    </button>
  );
  return (
    <div className="dual">
      {slot(a, setA, "Dana")}
      <div className="dual-bar" data-on={(a && b) || undefined}>
        <motion.i animate={{ scaleX: a && b ? 1 : a || b ? 0.5 : 0 }} transition={spring} />
        <span>{a && b ? "Released" : a || b ? "One more key" : "Two keys needed"}</span>
      </div>
      {slot(b, setB, "Ravi")}
    </div>
  );
}

function PolicySentence() {
  const slots: [string, string[]][] = [
    ["who", ["deploy-bot", "ci-runner", "support-agent"]],
    ["verb", ["read", "write", "rotate"]],
    ["what", ["stripe/charges", "github/repo", "aws/s3"]],
    ["ttl", ["1 hour", "8 hours", "15 minutes"]],
  ];
  const [pick, setPick] = useState([0, 0, 0, 0]);
  const slot = (i: number) => (
    <button
      type="button"
      className="policy-slot"
      data-kind={slots[i]![0]}
      onClick={() => setPick(pick.map((v, j) => (j === i ? (v + 1) % slots[i]![1].length : v)))}
    >
      <motion.span key={pick[i]} initial={{ y: 8, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={spring}>
        {slots[i]![1][pick[i]!]}
      </motion.span>
    </button>
  );
  return (
    <p className="policy">
      Allow {slot(0)} to {slot(1)} {slot(2)} for {slot(3)}.
    </p>
  );
}

function RelayPath() {
  const loop = { duration: 3.6, repeat: Infinity, ease: "easeInOut" } as const;
  return (
    <svg
      viewBox="0 0 320 96"
      className="relay"
      role="img"
      aria-label="An agent's request is relayed through Locksmith; the key stays in the vault."
    >
      <path d="M52 40H140M180 40H268" className="relay-line" />
      <motion.circle
        r="4"
        cy="40"
        className="relay-ask"
        animate={{ cx: [52, 140, 140, 52, 52], opacity: [1, 1, 0, 0, 1] }}
        transition={{ ...loop, times: [0, 0.3, 0.32, 0.9, 1] }}
      />
      <motion.circle
        r="4"
        cy="40"
        className="ls-relay-key"
        animate={{ cx: [180, 180, 268, 180, 180], opacity: [0, 1, 1, 0, 0] }}
        transition={{ ...loop, times: [0, 0.32, 0.6, 0.85, 1] }}
      />
      {[
        [32, "Agent", "relay-agent"],
        [160, "Locksmith", "relay-vault"],
        [288, "Stripe API", "relay-api"],
      ].map(([x, label, cls]) => (
        <g key={label} className={String(cls)}>
          <circle cx={x} cy="40" r="20" />
          <text x={x} y="82" textAnchor="middle">
            {label}
          </text>
        </g>
      ))}
      <path d="M160 31a5 5 0 0 1 2.2 9.5V49h-4.4v-8.5A5 5 0 0 1 160 31Z" className="relay-glyph" />
    </svg>
  );
}

function LedgerChain() {
  const [bad, setBad] = useState(false);
  const rows = [
    ["grant.created", "9f2c1a"],
    ["secret.read", "41be07"],
    ["grant.revoked", "c8d3e5"],
  ];
  return (
    <div className="ledger">
      {rows.map(([event, hash], i) => (
        <div key={hash} className="ledger-row" data-bad={(bad && i === 1) || undefined}>
          <span className="ledger-link">{bad && i === 1 ? <Unlink /> : <Link2 />}</span>
          <b>{event}</b>
          <code>{bad && i === 1 ? "??????" : hash}</code>
        </div>
      ))}
      <Button size="sm" variant="outline" onClick={() => setBad(!bad)}>
        {bad ? "Restore" : "Tamper with an entry"}
      </Button>
    </div>
  );
}

function PeekText() {
  const [peek, setPeek] = useState(false);
  return (
    <p className="peek">
      The recovery phrase is{" "}
      <button
        type="button"
        className="peek-bar"
        data-on={peek || undefined}
        aria-label="Hold to peek at the recovery phrase"
        onPointerDown={() => setPeek(true)}
        onPointerUp={() => setPeek(false)}
        onPointerLeave={() => setPeek(false)}
        onKeyDown={(e) => e.key === " " && setPeek(true)}
        onKeyUp={() => setPeek(false)}
      >
        amber-otter-violin-42
      </button>{" "}
      and is shown once.
    </p>
  );
}

function AccessLevel() {
  const names = ["None", "Read", "Write", "Admin"];
  const [level, setLevel] = useState(1);
  return (
    <div className="access" data-level={level}>
      <div className="access-bolts" role="radiogroup" aria-label="Access level">
        {[1, 2, 3].map((n) => (
          <button
            key={n}
            type="button"
            role="radio"
            aria-checked={level === n}
            aria-label={names[n]}
            onClick={() => setLevel(level === n ? n - 1 : n)}
          >
            <motion.i animate={{ scaleX: level >= n ? 1 : 0 }} transition={spring} />
          </button>
        ))}
      </div>
      <b>{names[level]}</b>
    </div>
  );
}

function StrengthLock() {
  const [v, setV] = useState("hunter2");
  const score = Math.min(4, Math.floor(v.length / 5) + (/\d/.test(v) ? 1 : 0) + (/[^a-z0-9]/i.test(v) ? 1 : 0));
  const label = ["Wide open", "Weak", "Fair", "Good", "Locked tight"][score]!;
  return (
    <div className="strength" data-score={score}>
      <svg viewBox="0 0 28 34" width="30" height="36" fill="none" strokeWidth="3" aria-hidden="true">
        <motion.path
          d="M8 16V10a6 6 0 0 1 12 0v6"
          animate={{ y: score >= 4 ? 0 : -(4 - score) * 1.6, rotate: score >= 4 ? 0 : (4 - score) * 4 }}
          transition={spring}
          style={{ transformOrigin: "20px 16px" }}
        />
        <rect x="4" y="16" width="20" height="15" rx="3" />
      </svg>
      <label>
        <input value={v} onChange={(e) => setV(e.target.value)} aria-label="Passphrase" spellCheck={false} />
        <span>{label}</span>
      </label>
    </div>
  );
}

function BreakGlass() {
  const [step, setStep] = useState(0);
  return (
    <div className="glass">
      <button type="button" className="glass-button" disabled={step !== 1} onClick={() => setStep(2)}>
        <Siren /> {step === 2 ? "Access opened, logged" : "Emergency access"}
      </button>
      <motion.button
        type="button"
        className="glass-cover"
        aria-label="Lift the cover"
        animate={{ rotateX: step ? -105 : 0, opacity: step ? 0.35 : 1 }}
        transition={spring}
        style={{ pointerEvents: step ? "none" : "auto" }}
        onClick={() => setStep(1)}
      >
        Lift to arm
      </motion.button>
      {step ? (
        <Button size="sm" variant="ghost" onClick={() => setStep(0)}>
          Reset
        </Button>
      ) : null}
    </div>
  );
}

function SafeDial() {
  const stops = ["5m", "15m", "1h", "8h", "24h", "7d"];
  const [i, setI] = useState(2);
  return (
    <div className="dial">
      <button
        type="button"
        role="slider"
        aria-label="Lease length"
        aria-valuemin={0}
        aria-valuemax={5}
        aria-valuenow={i}
        aria-valuetext={stops[i]}
        onClick={() => setI((i + 1) % 6)}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight" || e.key === "ArrowUp") setI(Math.min(5, i + 1));
          if (e.key === "ArrowLeft" || e.key === "ArrowDown") setI(Math.max(0, i - 1));
        }}
      >
        <motion.span className="dial-knob" animate={{ rotate: i * 60 }} transition={spring}>
          <i />
        </motion.span>
        <b>{stops[i]}</b>
      </button>
      {stops.map((s, n) => (
        <span key={s} className="dial-tick" data-on={n === i || undefined} style={{ rotate: `${n * 60}deg` }}>
          <em style={{ rotate: `${-n * 60}deg` }}>{s}</em>
        </span>
      ))}
    </div>
  );
}

function RotationRing() {
  const [turn, setTurn] = useState(0);
  const [day, setDay] = useState(22);
  return (
    <div className="rotation">
      <svg viewBox="0 0 64 64" width="72" height="72" fill="none" strokeWidth="6" aria-hidden="true">
        <circle cx="32" cy="32" r="26" className="rotation-track" />
        <motion.g
          animate={{ rotate: turn * 360 }}
          transition={{ duration: 0.9, ease: [0.3, 1.5, 0.6, 1] }}
          style={{ transformOrigin: "32px 32px" }}
        >
          <motion.circle
            cx="32"
            cy="32"
            r="26"
            className="rotation-fill"
            data-due={day >= 25 || undefined}
            strokeLinecap="round"
            transform="rotate(-90 32 32)"
            animate={{ pathLength: day / 30 }}
            transition={{ duration: 0.6 }}
          />
        </motion.g>
      </svg>
      <div>
        <b>Day {day} of 30</b>
        <span>{30 - day} days until this key rotates</span>
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            setTurn(turn + 1);
            setDay(0);
            setTimeout(() => setDay(22), 2200);
          }}
        >
          Rotate now
        </Button>
      </div>
    </div>
  );
}

function TimeWindow() {
  const windows: [string, number, number][] = [
    ["Business hours", 9, 18],
    ["Nights", 22, 30],
    ["Always", 0, 24],
  ];
  const [w, setW] = useState(0);
  const [, from, to] = windows[w]!;
  return (
    <div className="window">
      <svg viewBox="0 0 64 64" width="76" height="76" fill="none" aria-hidden="true">
        <circle cx="32" cy="32" r="24" strokeWidth="8" className="rotation-track" />
        <motion.circle
          cx="32"
          cy="32"
          r="24"
          strokeWidth="8"
          className="rotation-fill"
          initial={false}
          animate={{ pathLength: (to - from) / 24, rotate: -90 + from * 15 }}
          transition={spring}
          style={{ transformOrigin: "32px 32px" }}
        />
        <path d="M32 32V14" strokeWidth="2" className="window-hand" transform="rotate(157 32 32)" />
        <circle cx="32" cy="32" r="2.5" className="window-hub" />
      </svg>
      <div>
        <b>
          {String(from % 24).padStart(2, "0")}:00 to {String(to % 24).padStart(2, "0")}:00
        </b>
        <span>Outside these hours the grant is refused.</span>
        <Button size="sm" variant="outline" onClick={() => setW((w + 1) % 3)}>
          {windows[(w + 1) % 3]![0]}
        </Button>
      </div>
    </div>
  );
}

function SealStamp() {
  const [on, setOn] = useState(false);
  return (
    <div className="stamp">
      <div className="stamp-paper">
        <b>Grant request</b>
        <span>deploy-bot asks for stripe/charges, read, 1 hour</span>
        {on ? (
          <motion.span
            className="stamp-seal"
            initial={{ scale: 2.4, opacity: 0, rotate: -30 }}
            animate={{ scale: 1, opacity: 1, rotate: -12 }}
            transition={{ type: "spring", stiffness: 500, damping: 18 }}
          >
            <Mark small mono size={22} /> Approved
          </motion.span>
        ) : null}
      </div>
      <Button size="sm" variant={on ? "outline" : "default"} onClick={() => setOn(!on)}>
        {on ? "Undo" : "Approve"}
      </Button>
    </div>
  );
}

function GrantTicket() {
  const [gone, setGone] = useState(false);
  return (
    <div className="ticket-wrap">
      <div className="ticket" data-gone={gone || undefined}>
        <div className="ticket-main">
          <small>Grant</small>
          <b>stripe/charges</b>
          <span>read, for deploy-bot</span>
        </div>
        <motion.div
          className="ticket-stub"
          animate={gone ? { rotate: 14, y: 46, opacity: 0 } : { rotate: 0, y: 0, opacity: 1 }}
          transition={{ duration: 0.6, ease: "easeIn" }}
        >
          <small>Expires</small>
          <b>14:30</b>
        </motion.div>
      </div>
      <Button size="sm" variant="outline" onClick={() => setGone(!gone)}>
        {gone ? "Reissue" : "Expire it"}
      </Button>
    </div>
  );
}

function KeyTags() {
  return (
    <div className="tags">
      {["production", "staging", "development"].map((env) => (
        <motion.span
          key={env}
          className="tag"
          data-env={env}
          whileHover={{ rotate: [0, -7, 5, -3, 0] }}
          transition={{ duration: 0.7 }}
        >
          {env}
        </motion.span>
      ))}
    </div>
  );
}

function SecretDiff() {
  const changed = [3, 4, 11, 19];
  const [v, setV] = useState(4);
  return (
    <div className="sdiff">
      {[v - 1, v].map((ver, row) => (
        <div key={row} className="sdiff-row">
          <small>v{ver}</small>
          {Array.from({ length: 24 }, (_, i) => (
            <i key={i} data-change={changed.includes((i + v) % 24) ? (row ? "new" : "old") : undefined}>
              *
            </i>
          ))}
        </div>
      ))}
      <span>4 of 24 characters changed. Same length. No value shown.</span>
      <Button size="sm" variant="outline" onClick={() => setV(v + 1)}>
        Next version
      </Button>
    </div>
  );
}

function KeyTree() {
  const [open, setOpen] = useState<Record<string, boolean>>({ acme: true, api: true });
  const node = (id: string, label: string, kids?: ReactNode, leaf?: boolean) => (
    <li>
      <button
        type="button"
        data-leaf={leaf || undefined}
        aria-expanded={leaf ? undefined : !!open[id]}
        onClick={() => !leaf && setOpen({ ...open, [id]: !open[id] })}
      >
        {leaf ? <Key /> : <ChevronRight data-open={open[id] || undefined} />}
        {label}
      </button>
      {!leaf && open[id] ? <ul>{kids}</ul> : null}
    </li>
  );
  return (
    <ul className="tree">
      {node(
        "acme",
        "acme",
        <>
          {node(
            "api",
            "acme-api",
            <>
              {node(
                "prod",
                "production",
                <>
                  {node("k1", "STRIPE_KEY", null, true)}
                  {node("k2", "DATABASE_URL", null, true)}
                </>,
              )}
              {node("stg", "staging", <>{node("k3", "STRIPE_KEY", null, true)}</>)}
            </>,
          )}
          {node("web", "acme-web", <>{node("k4", "SESSION_SECRET", null, true)}</>)}
        </>,
      )}
    </ul>
  );
}

function AgentPresence() {
  const [busy, setBusy] = useState(true);
  return (
    <div className="presence-wrap">
      <button type="button" className="presence" data-busy={busy || undefined} onClick={() => setBusy(!busy)}>
        <span className="presence-dot">
          {busy ? (
            <motion.i
              animate={{ scale: [1, 2.4], opacity: [0.6, 0] }}
              transition={{ duration: 1.4, repeat: Infinity }}
            />
          ) : null}
          <Bot />
        </span>
        <b>deploy-bot</b>
        <span>{busy ? "using stripe/charges" : "idle, holds nothing"}</span>
      </button>
    </div>
  );
}

function KeyholeReveal() {
  const [open, setOpen] = useState(false);
  return (
    <button
      type="button"
      className="keyhole"
      data-open={open || undefined}
      onClick={() => setOpen(!open)}
      aria-label="Open the page through the keyhole"
    >
      <span className="keyhole-page">
        <b>Welcome to the vault</b>
        <span>Your agents work. The keys stay here.</span>
      </span>
    </button>
  );
}

export function Ideas() {
  return (
    <div className="ideas">
      <header className="ideas-head">
        <h1>Twenty ideas</h1>
        <p>
          Components no other kit has, sketched live so you can try them. Each has a verdict: <b>build it</b> (useful
          and good looking), <b>use sparingly</b> (fun, but it wears thin if it is everywhere) or <b>too much</b> (a
          gimmick inside a product). These are sketches, not kit components.
        </p>
      </header>
      <div className="ideas-grid">
        <Idea
          n={1}
          name="DualControl"
          verdict="build"
          what="Two people must each turn their key before something is released."
          take="Says 'two-person rule' with no words. Real security teams ask for this. Click both keys."
        >
          <DualControl />
        </Idea>
        <Idea
          n={2}
          name="PolicySentence"
          verdict="build"
          what="A grant written as a sentence, with each part a pick."
          take="The most useful one here: a policy anyone can read aloud. Click the coloured words."
        >
          <PolicySentence />
        </Idea>
        <Idea
          n={3}
          name="RelayPath"
          verdict="build"
          what="Shows a request going through Locksmith while the key stays in the vault."
          take="It is the product's whole promise in one picture. Good for onboarding and docs, not for every page."
        >
          <RelayPath />
        </Idea>
        <Idea
          n={4}
          name="LedgerChain"
          verdict="build"
          what="Audit entries joined by links; a changed entry breaks the chain."
          take="Makes 'tamper-evident' visible. Quiet until something is wrong, which is right."
        >
          <LedgerChain />
        </Idea>
        <Idea
          n={5}
          name="AccessLevel"
          verdict="build"
          what="How much access a grant gives, as bolts thrown. More bolts, warmer colour."
          take="Faster to scan in a table than the words read, write, admin. Click a bolt."
        >
          <AccessLevel />
        </Idea>
        <Idea
          n={6}
          name="PeekText"
          verdict="build"
          what="A redacted word in a sentence. Hold it to read; let go and it hides again."
          take="Safer than a reveal toggle, because nobody forgets to hide it again. Hold the bar."
        >
          <PeekText />
        </Idea>
        <Idea
          n={7}
          name="StrengthLock"
          verdict="build"
          what="Passphrase strength as a shackle that closes as the phrase gets stronger."
          take="Clearer than a coloured bar and still small. Type in the field."
        >
          <StrengthLock />
        </Idea>
        <Idea
          n={8}
          name="RotationRing"
          verdict="build"
          what="Where a key is in its rotation cycle, and a ring that turns when it rotates."
          take="Rotation is the thing people forget; this keeps it in view. Amber near the end."
        >
          <RotationRing />
        </Idea>
        <Idea
          n={9}
          name="TimeWindow"
          verdict="build"
          what="The hours a grant works, as an arc on a 24-hour ring."
          take="A time range is hard to read as text and obvious as an arc. The hand is now."
        >
          <TimeWindow />
        </Idea>
        <Idea
          n={10}
          name="SecretDiff"
          verdict="build"
          what="Compares two versions of a secret without showing either."
          take="Answers 'did it really change?' safely. Nothing else does this."
        >
          <SecretDiff />
        </Idea>
        <Idea
          n={11}
          name="KeyTree"
          verdict="build"
          what="Organization, project, environment and secret as a tree."
          take="Plain and useful. shadcn has no tree, and this product is a hierarchy."
        >
          <KeyTree />
        </Idea>
        <Idea
          n={12}
          name="AgentPresence"
          verdict="build"
          what="Shows an agent acting right now, and that it holds nothing itself."
          take="The violet pulse is the one place motion means 'live'. Click to toggle idle."
        >
          <AgentPresence />
        </Idea>
        <Idea
          n={13}
          name="KeyRing"
          verdict="sparingly"
          what="People or agents on one ring; hover and the keys fan out."
          take="Charming once, in a team or access list. As the default avatar stack it would get tiring."
        >
          <KeyRing />
        </Idea>
        <Idea
          n={14}
          name="VaultDoor"
          verdict="sparingly"
          what="A door over sensitive content: the bolts draw in, then it slides open."
          take="A real moment for the first unlock of a session. On every secret it would be slow and theatrical."
        >
          <VaultDoor />
        </Idea>
        <Idea
          n={15}
          name="SafeDial"
          verdict="sparingly"
          what="A safe dial that clicks between a few fixed choices."
          take="Beautiful and the most 'Locksmith' control here, but slower than a select. One per screen at most."
        >
          <SafeDial />
        </Idea>
        <Idea
          n={16}
          name="BreakGlass"
          verdict="sparingly"
          what="An emergency button under a cover you must lift first."
          take="Two deliberate steps for a rare, dangerous action. Only for real break-glass access."
        >
          <BreakGlass />
        </Idea>
        <Idea
          n={17}
          name="SealStamp"
          verdict="sparingly"
          what="An approval lands as a stamped seal."
          take="Satisfying on the one screen where you approve. Kitsch if every success gets a stamp."
        >
          <SealStamp />
        </Idea>
        <Idea
          n={18}
          name="GrantTicket"
          verdict="sparingly"
          what="A grant as a ticket; the expiry stub tears off when it runs out."
          take="Pretty for a single grant's detail view. A table of tickets would be noise."
        >
          <GrantTicket />
        </Idea>
        <Idea
          n={19}
          name="KeyTag"
          verdict="sparingly"
          what="Environment names as key tags that swing when touched."
          take="Cute, but Badge already does this job. Worth it only for environments."
        >
          <KeyTags />
        </Idea>
        <Idea
          n={20}
          name="KeyholeReveal"
          verdict="too much"
          what="The page opens out of a keyhole."
          take="Eye-catching for two seconds on a marketing site. Inside the product it is a gimmick that delays work."
        >
          <KeyholeReveal />
        </Idea>
      </div>
    </div>
  );
}
