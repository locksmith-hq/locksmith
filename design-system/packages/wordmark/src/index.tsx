import type { ComponentProps } from "react";
import { cn } from "cn";
import { Mark } from "@locksmith-hq/mark";

export interface WordmarkProps extends Omit<ComponentProps<"span">, "children"> {
  /**
   * Font size in pixels. The bar, its tooth and the mark scale with it.
   * @default 15
   */
  size?: number;
  /**
   * `plain` drops the bar and tooth, for a footer or a very small size. `mono` draws them in the text colour,
   * for print or for sitting on a coloured surface.
   * @default "default"
   */
  variant?: "default" | "plain" | "mono";
  /** Adds the mark to make the full logo: `left` for a header, `top` for a sign-in page or a splash. */
  mark?: "left" | "top";
}

// The name in two weights: LOCK heavy, SMITH light, with the Tabs bar and its key tooth under LOCK.
export function Wordmark({ size = 15, variant = "default", mark, className, style, ...props }: WordmarkProps) {
  const word = (
    <span
      data-slot="wordmark"
      data-variant={variant}
      className={cn("wordmark", !mark && className)}
      style={{ fontSize: size, ...(mark ? undefined : style) }}
      {...(mark ? undefined : props)}
    >
      <b>Lock</b>smith
    </span>
  );
  if (!mark) return word;
  return (
    <span
      data-slot="wordmark-lockup"
      data-mark={mark}
      className={cn("wordmark-lockup", className)}
      style={style}
      {...props}
    >
      <Mark small={size < 22} size={Math.round(size * (mark === "top" ? 2.8 : 1.9))} />
      {word}
    </span>
  );
}
