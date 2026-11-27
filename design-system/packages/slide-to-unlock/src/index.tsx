import { useRef, useState } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { animate, motion, useMotionValue, useReducedMotion, useTransform } from "motion/react";

export interface SlideToUnlockProps extends Omit<ComponentProps<"div">, "children"> {
  /**
   * Text in the track while it is locked.
   * @default "Slide to unlock"
   */
  label?: string;
  /**
   * Text in the track once the bolt is home.
   * @default "Unlocked"
   */
  doneLabel?: string;
  /** Called once, when the bolt reaches the end of the track. */
  onUnlock?: () => void;
  /** Turns the control off. */
  disabled?: boolean;
}

// A deadbolt you throw by hand: drag the bolt to the end of its track to confirm. Let go short of the end and
// it springs back. With the keyboard, focus the bolt and press Enter, Space or the right arrow.
// shortcut: it unlocks once and stays; remount it (change its `key`) to lock it again.
export function SlideToUnlock({
  label = "Slide to unlock",
  doneLabel = "Unlocked",
  onUnlock,
  disabled,
  className,
  ...props
}: SlideToUnlockProps) {
  const track = useRef<HTMLDivElement>(null);
  const bolt = useRef<HTMLButtonElement>(null);
  const [done, setDone] = useState(false);
  const still = useReducedMotion();
  const x = useMotionValue(0);
  const fade = useTransform(x, [0, 90], [1, 0]);
  // How far the bolt can travel: the track's inner width less the bolt's.
  const reach = () => (track.current && bolt.current ? track.current.clientWidth - bolt.current.offsetWidth - 8 : 0);
  const spring = still ? { duration: 0 } : ({ type: "spring", stiffness: 420, damping: 30 } as const);
  const finish = () => {
    animate(x, reach(), spring);
    setDone(true);
    onUnlock?.();
  };
  return (
    <div
      data-slot="slide-to-unlock"
      data-done={done || undefined}
      data-disabled={disabled || undefined}
      className={cn("slide-to-unlock", className)}
      ref={track}
      {...props}
    >
      <motion.span aria-hidden="true" className="slide-label" style={{ opacity: done ? 1 : fade }}>
        {done ? doneLabel : label}
      </motion.span>
      <motion.button
        ref={bolt}
        type="button"
        className="slide-bolt"
        aria-label={done ? doneLabel : label}
        aria-pressed={done}
        disabled={disabled || done}
        style={{ x }}
        drag={disabled || done ? false : "x"}
        dragConstraints={track}
        dragElastic={0}
        dragMomentum={false}
        onDragEnd={() => (x.get() >= reach() * 0.9 ? finish() : animate(x, 0, spring))}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " " || e.key === "ArrowRight") {
            e.preventDefault();
            finish();
          }
        }}
      />
    </div>
  );
}
