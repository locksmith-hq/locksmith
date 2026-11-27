import type { ComponentProps } from "react";
import { cn } from "cn";
import { Check } from "lucide-react";

export interface StepperProps extends Omit<ComponentProps<"ol">, "children"> {
  /** Step names, in order. */
  steps: string[];
  /** Index of the current step, starting from 0. Earlier steps show as done. */
  current: number;
  /**
   * Accessible name of the list; it is not shown.
   * @default "Steps"
   */
  label?: string;
}

// Steps in order, each a pin: done ones are set (teal, checked), the current one stands up, the rest wait in the well.
export function Stepper({ steps, current, label = "Steps", className, ...props }: StepperProps) {
  return (
    <ol data-slot="stepper" className={cn("steps", className)} aria-label={label} {...props}>
      {(steps || []).map((s, i) => (
        <li
          key={i}
          data-state={i < current ? "done" : i === current ? "current" : "todo"}
          aria-current={i === current ? "step" : undefined}
        >
          <span className="step-pin">{i < current ? <Check /> : i + 1}</span>
          <span>
            {s}
            {i < current ? <span className="sr-only"> (done)</span> : null}
          </span>
        </li>
      ))}
    </ol>
  );
}
