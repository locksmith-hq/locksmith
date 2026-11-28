import { cn } from "cn";

// The ring of the Locksmith dial, in six segments (the Mark's small cut).
const RING =
  "M70.35 21.36A40 40 0 0 1 88.28 31.72M98.64 49.65A40 40 0 0 1 98.64 70.35M88.28 88.28A40 40 0 0 1 70.35 98.64M49.65 98.64A40 40 0 0 1 31.72 88.28M21.36 70.35A40 40 0 0 1 21.36 49.65M31.72 31.72A40 40 0 0 1 49.65 21.36";
const SIZE = { sm: "size-3", default: "size-4", lg: "size-6" };

// shadcn's Spinner with its icon swapped, as its docs suggest: the ring of the Locksmith dial. The ring has
// six-fold symmetry, so the theme turns it a sixth of a turn at a time and the loop has no seam.
// `variant` and `size` are not in shadcn's Spinner. The variants are the same dial, a little more or less of it:
// "dial" (ring and hub) for buttons and lines of text, "ring" (no hub) where it sits on a busy surface, and
// "bolts" (ring, hub and the six bolts) for a card or panel where there is room to read it.
function Spinner({
  className,
  variant = "dial",
  size = "default",
  ...props
}: React.ComponentProps<"svg"> & { variant?: "dial" | "ring" | "bolts"; size?: "sm" | "default" | "lg" }) {
  return (
    <svg
      data-slot="spinner"
      data-variant={variant}
      role="status"
      aria-label="Loading"
      viewBox="0 0 120 120"
      fill="none"
      stroke="currentColor"
      strokeWidth={variant === "bolts" ? 11 : 14}
      className={cn(SIZE[size], "shrink-0", className)}
      {...props}
    >
      <path d={RING} />
      {variant === "bolts"
        ? [0, 60, 120, 180, 240, 300].map((a) => <path key={a} d="M88 60H112" transform={`rotate(${a - 90} 60 60)`} />)
        : null}
      {variant === "ring" ? null : <circle cx="60" cy="60" r="9" fill="currentColor" stroke="none" />}
    </svg>
  );
}

export { Spinner };
