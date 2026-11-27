// Clock helpers for the mockup's sample data and labels.
/** Page-load time in epoch seconds; "ago" and "in" labels are relative to it. */
export const NOW = Math.floor(Date.now() / 1000);

export const MIN = 60,
  HOUR = 3600,
  DAY = 86400;
export const plural = (n: number, w: string) => `${n} ${n === 1 ? w : `${w}s`}`;
/** "3m ago", "2d ago"; `null` reads "never". */
export const ago = (ts: number | null) => {
  if (ts === null) return "never";
  const s = NOW - ts;
  return s < 60
    ? "just now"
    : s < HOUR
      ? `${Math.floor(s / 60)}m ago`
      : s < DAY
        ? `${Math.floor(s / HOUR)}h ago`
        : `${Math.floor(s / DAY)}d ago`;
};
/** "in 5h", "in 12d"; `null` reads "never". */
export const inTime = (ts: number | null) => {
  if (ts === null) return "never";
  const s = ts - NOW;
  return s <= 0
    ? "now"
    : s < HOUR
      ? `in ${Math.ceil(s / 60)}m`
      : s < DAY
        ? `in ${Math.ceil(s / HOUR)}h`
        : `in ${Math.ceil(s / DAY)}d`;
};
