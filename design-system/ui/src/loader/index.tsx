import type { ComponentProps, ReactNode } from "react";
import { cn } from "cn";
import { Mark } from "../mark";

export interface LoaderProps extends ComponentProps<"div"> {
  /**
   * Text for screen readers when there are no children; it is not shown.
   * @default "Loading"
   */
  label?: string;
  /** Text shown under the dial, such as "Opening the vault". Screen readers read it in place of `label`. */
  children?: ReactNode;
  /** Centres the loader on the whole viewport instead of its container. */
  fill?: boolean;
  /**
   * Size of the dial in pixels.
   * @default 42
   */
  size?: number;
  /** Set when the load has ended and the loader stays on screen: the dial stops and throws its bolts home once. */
  done?: boolean;
}

// The product's loader: the vault dial turning and throwing its bolts, faded in after a beat so quick loads
// show nothing. Use Spinner for one line of text or a button; this is for a page or a panel.
export function Loader({
  label = "Loading",
  fill = false,
  size = 42,
  done = false,
  className,
  children,
  ...props
}: LoaderProps) {
  return (
    <div
      data-slot="loader"
      data-done={done || undefined}
      className={cn("ls-loader", fill && "ls-loader-fill", className)}
      role="status"
      {...props}
    >
      <Mark small size={size} />
      {children ? <span className="ls-loader-text">{children}</span> : <span className="sr-only">{label}</span>}
    </div>
  );
}
