// What a lease timer shows at `now`: how much of the lease is left (1 full, 0 expired) and the time as text.
// All three times are milliseconds; `total` is the whole length of the lease.
export function lease(now: number, expiresAt: number, total: number): { left: number; text: string } {
  const ms = Math.max(0, expiresAt - now);
  const s = Math.ceil(ms / 1000);
  const two = (n: number) => String(n).padStart(2, "0");
  const text =
    s === 0
      ? "Expired"
      : s >= 3600
        ? `${Math.floor(s / 3600)}h ${two(Math.floor((s % 3600) / 60))}m`
        : `${Math.floor(s / 60)}:${two(s % 60)}`;
  return { left: total > 0 ? Math.min(1, ms / total) : 0, text };
}
