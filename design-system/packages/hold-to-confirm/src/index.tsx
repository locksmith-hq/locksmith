import { useRef } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { animate, motion, useMotionValue } from "motion/react";
import { Button } from "@locksmith-hq/button";

export interface HoldToConfirmProps extends Omit<ComponentProps<typeof Button>, "onClick"> {
  /** Called once, when the button has been held for the whole `duration`. */
  onConfirm: () => void;
  /**
   * How long to hold, in milliseconds.
   * @default 1200
   */
  duration?: number;
}

// A button for what cannot be undone: it does nothing on a click. Hold it and a bolt travels across; let go
// early and the bolt springs back. Works with the pointer and with Space or Enter held down.
export function HoldToConfirm({
  onConfirm,
  duration = 1200,
  variant = "destructive",
  className,
  children,
  ...props
}: HoldToConfirmProps) {
  const progress = useMotionValue(0);
  const run = useRef<ReturnType<typeof animate>>(undefined);
  const start = () => {
    run.current?.stop();
    run.current = animate(progress, 1, {
      duration: (duration / 1000) * (1 - progress.get()),
      ease: "linear",
      onComplete: () => {
        onConfirm();
        progress.set(0);
      },
    });
  };
  const cancel = () => {
    run.current?.stop();
    run.current = animate(progress, 0, { type: "spring", stiffness: 300, damping: 26 });
  };
  const isKey = (key: string) => key === " " || key === "Enter";
  return (
    <Button
      data-hold=""
      variant={variant}
      className={cn("hold-to-confirm", className)}
      onPointerDown={(e) => e.button === 0 && start()}
      onPointerUp={cancel}
      onPointerLeave={cancel}
      onPointerCancel={cancel}
      onKeyDown={(e) => isKey(e.key) && !e.repeat && start()}
      onKeyUp={(e) => isKey(e.key) && cancel()}
      onBlur={cancel}
      {...props}
    >
      <motion.span aria-hidden="true" className="hold-fill" style={{ scaleX: progress }} />
      <span className="hold-label">{children}</span>
      <span className="sr-only">. Press and hold to confirm.</span>
    </Button>
  );
}
