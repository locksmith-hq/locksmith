import { useRef } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { animate, motion, useMotionValue } from "motion/react";
import { Button } from "../button";
import { useLabels } from "../labels";

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
  onPointerDown,
  onPointerUp,
  onPointerLeave,
  onPointerCancel,
  onKeyDown,
  onKeyUp,
  onBlur,
  ...props
}: HoldToConfirmProps) {
  const t = useLabels();
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
  // A handler the caller passes runs first, then the hold's own: neither replaces the other.
  return (
    <Button
      data-hold=""
      variant={variant}
      className={cn("ls-hold-to-confirm", className)}
      {...props}
      onPointerDown={(e) => (onPointerDown?.(e), e.button === 0 && start())}
      onPointerUp={(e) => (onPointerUp?.(e), cancel())}
      onPointerLeave={(e) => (onPointerLeave?.(e), cancel())}
      onPointerCancel={(e) => (onPointerCancel?.(e), cancel())}
      onKeyDown={(e) => (onKeyDown?.(e), isKey(e.key) && !e.repeat && start())}
      onKeyUp={(e) => (onKeyUp?.(e), isKey(e.key) && cancel())}
      onBlur={(e) => (onBlur?.(e), cancel())}
    >
      <motion.span aria-hidden="true" className="ls-hold-fill" style={{ scaleX: progress }} />
      <span className="ls-hold-label">{children}</span>
      <span className="sr-only">. {t.holdToConfirm}</span>
    </Button>
  );
}
