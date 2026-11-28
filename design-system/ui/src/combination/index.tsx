import type { ComponentProps } from "react";
import { cn } from "cn";
import { motion, useReducedMotion } from "motion/react";

export interface CombinationProps extends Omit<ComponentProps<"span">, "children"> {
  /** What to show. Each digit gets its own wheel; any other character (a colon, a dash, a letter) stands still. */
  value: number | string;
  /** Pads a number with leading zeros to this many digits, so the wheels do not appear and vanish as it changes. */
  digits?: number;
}

const WHEEL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

// A number on the wheels of a combination lock: when it changes, each wheel rolls to its new digit and
// settles with a click. For one-time codes, countdowns and counts that change while you watch.
// Screen readers get the plain value; the wheels are decoration.
export function Combination({ value, digits, className, ...props }: CombinationProps) {
  const still = useReducedMotion();
  const text = String(value).padStart(digits ?? 0, "0");
  return (
    <span data-slot="combination" className={cn("ls-combination", className)} {...props}>
      <span className="sr-only">{text}</span>
      <span aria-hidden="true" className="ls-combination-row">
        {/* keyed from the right, so the ones wheel stays the ones wheel when a digit is added */}
        {[...text].map((ch, i) =>
          /\d/.test(ch) ? (
            <span key={text.length - i} className="ls-combination-wheel">
              <motion.span
                initial={false}
                animate={{ y: `${-Number(ch) * 10}%` }}
                transition={still ? { duration: 0 } : { type: "spring", stiffness: 260, damping: 22, mass: 0.8 }}
              >
                {WHEEL.map((n) => (
                  <span key={n}>{n}</span>
                ))}
              </motion.span>
            </span>
          ) : (
            <span key={text.length - i} className="ls-combination-gap">
              {ch}
            </span>
          ),
        )}
      </span>
    </span>
  );
}
