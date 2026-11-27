import { useEffect, useRef, useState } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { AnimatePresence, motion, useInView, useReducedMotion } from "motion/react";
import { Bot, Check, Cloud, KeyRound } from "lucide-react";
import { Mark } from "@locksmith-hq/mark";

export interface RelayPathProps extends Omit<ComponentProps<"figure">, "children"> {
  /**
   * Name under the agent.
   * @default "Your agent"
   */
  agent?: string;
  /**
   * Name under the service the call goes to.
   * @default "Stripe API"
   */
  service?: string;
  /**
   * The call the agent makes, shown on the packet that travels.
   * @default "GET /charges"
   */
  request?: string;
  /** Holds the picture on its first step. It also waits while it is off screen. */
  paused?: boolean;
}

// Each step: where the packet is, whether it carries the key, how long the step lasts, and what is said.
const A = 124,
  V = 400,
  S = 676;
// Where the packet rests beside the agent and the service, clear of their plates.
const AE = 240,
  SE = 560;
const STEPS = [
  { from: AE, to: V, lane: 0, keyed: false, ms: 1500, text: "The agent asks to make a call. It holds no key." },
  { from: V, to: V, lane: 0, keyed: false, ms: 1200, text: "Locksmith checks the grant and opens the vault." },
  { from: V, to: SE, lane: 0, keyed: true, ms: 1500, text: "Locksmith adds the key and relays the call." },
  { from: SE, to: V, lane: 1, keyed: false, ms: 1400, text: "The service answers. The key stays behind the line." },
  { from: V, to: AE, lane: 1, keyed: false, ms: 1500, text: "The agent gets the answer, never the key." },
] as const;

// The product in one picture: an agent's call goes to Locksmith, the key is added inside the vault, and only
// the answer comes back. Five steps on a loop, each with one sentence. Built for a landing page: it runs only
// while on screen, and with reduced motion it shows the relay step as a still picture.
export function RelayPath({
  agent = "Your agent",
  service = "Stripe API",
  request = "GET /charges",
  paused,
  className,
  ...props
}: RelayPathProps) {
  const root = useRef<HTMLElement>(null);
  const seen = useInView(root, { amount: 0.4 });
  const still = useReducedMotion();
  const [n, setN] = useState(0);
  const run = seen && !paused && !still;
  const i = still ? 2 : n;
  const step = STEPS[i]!;
  useEffect(() => {
    if (!run) return;
    const t = setTimeout(() => setN((n + 1) % STEPS.length), STEPS[n]!.ms + 500);
    return () => clearTimeout(t);
  }, [run, n]);
  const y = step.lane ? 132 : 100;
  const open = i === 1 || i === 2;
  return (
    <figure data-slot="relay-path" className={cn("relay-path", className)} ref={root} {...props}>
      <svg
        viewBox="0 0 800 232"
        role="img"
        aria-label={`${agent} makes a call through Locksmith to ${service}. Locksmith adds the key inside the vault; the agent only ever gets the answer.`}
      >
        {/* the two sides: nothing secret on the left, the key only on the right */}
        <rect x="8" y="8" width="392" height="216" rx="10" className="relay-side" />
        <rect x="400" y="8" width="392" height="216" rx="10" className="relay-side keyed" />
        <text x="28" y="34" className="relay-zone">
          NO SECRETS ON THIS SIDE
        </text>
        <text x="772" y="34" textAnchor="end" className="relay-zone keyed">
          THE KEY IS USED HERE
        </text>
        <path d="M400 8V224" className="relay-seal" />

        {/* rails: the call goes out on the upper lane and the answer returns on the lower */}
        <path d="M178 100H338" className="relay-rail" data-live={i === 0 ? "agent" : undefined} />
        <path d="M462 100H622" className="relay-rail" data-live={i === 2 ? "key" : undefined} />
        <path d="M622 132H462" className="relay-rail" data-live={i === 3 ? "answer" : undefined} />
        <path d="M338 132H178" className="relay-rail" data-live={i === 4 ? "answer" : undefined} />
        <path d="M330 95l8 5-8 5M614 95l8 5-8 5M470 127l-8 5 8 5M186 127l-8 5 8 5" className="relay-arrow" />

        <g className="relay-node agent">
          <rect x={A - 54} y="72" width="108" height="88" rx="10" />
          <Bot x={A - 14} y="94" width="28" height="28" />
          <text x={A} y="146" textAnchor="middle">
            {agent}
          </text>
        </g>
        <g className="relay-node service">
          <rect x={S - 54} y="72" width="108" height="88" rx="10" />
          <Cloud x={S - 14} y="94" width="28" height="28" />
          <text x={S} y="146" textAnchor="middle">
            {service}
          </text>
        </g>
        <g className="relay-node vault" data-open={open || undefined}>
          <circle cx={V} cy="116" r="62" />
          <Mark x={V - 34} y="82" size={68} open={open} />
          <text x={V} y="206" textAnchor="middle">
            Locksmith
          </text>
        </g>

        {/* the grant check, a tick that appears above the vault while it decides */}
        <AnimatePresence>
          {i === 1 ? (
            <motion.g
              className="relay-check"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ delay: 0.35 }}
            >
              <rect x={V - 46} y="26" width="92" height="22" rx="11" />
              <Check x={V - 38} y="30" width="14" height="14" />
              <text x={V + 8} y="41" textAnchor="middle">
                grant ok
              </text>
            </motion.g>
          ) : null}
        </AnimatePresence>

        {/* the packet: plain on the agent's side, carrying the key only between the vault and the service */}
        <motion.g
          className="relay-packet"
          data-keyed={step.keyed || undefined}
          data-answer={step.lane ? true : undefined}
          initial={false}
          // it fades as it enters the vault and appears as it leaves, so it never covers the mark
          animate={{
            x: [step.from, step.to],
            y: [y, y],
            opacity: step.from === step.to ? 0 : step.to === V ? [1, 1, 0] : [0, 1, 1],
          }}
          transition={
            still
              ? { duration: 0 }
              : {
                  duration: step.ms / 1000,
                  ease: [0.65, 0, 0.35, 1],
                  opacity: { times: step.to === V ? [0, 0.7, 1] : [0, 0.3, 1] },
                }
          }
        >
          <rect x="-58" y="-13" width="116" height="26" rx="13" />
          <text x={step.keyed ? -11 : 0} y="4" textAnchor="middle">
            {step.lane ? "200 OK" : request}
          </text>
          {step.keyed ? (
            <g className="relay-key">
              <circle cx="44" cy="0" r="9" />
              <KeyRound x="38" y="-6" width="12" height="12" />
            </g>
          ) : null}
        </motion.g>
      </svg>
      <figcaption>
        <span className="relay-steps" aria-hidden="true">
          {STEPS.map((_, k) => (
            <i key={k} data-on={k === i || undefined} />
          ))}
        </span>
        <AnimatePresence mode="wait" initial={false}>
          <motion.span
            key={i}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: still ? 0 : 0.2 }}
          >
            {step.text}
          </motion.span>
        </AnimatePresence>
      </figcaption>
    </figure>
  );
}
