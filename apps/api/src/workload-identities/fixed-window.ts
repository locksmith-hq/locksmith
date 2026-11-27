/**
 * Fixed-window counter per key, in memory (Rust `ls-oidc-verify` `AbuseGuard::hit`): the first `limit` hits in a
 * window pass, the rest are refused; a window starts at its key's first hit. Per replica and best effort, bounded
 * by `maxKeys` (the oldest windows are dropped first).
 */
export class FixedWindowLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs = 60_000,
    private readonly maxKeys = 50_000,
    private readonly now: () => number = Date.now,
  ) {}

  allow(key: string): boolean {
    if (this.limit === 0) return true;
    const t = this.now();
    const w = this.windows.get(key);
    if (!w || t - w.start >= this.windowMs) {
      if (!w && this.windows.size >= this.maxKeys) {
        const oldest = this.windows.keys().next().value;
        if (oldest !== undefined) this.windows.delete(oldest);
      }
      this.windows.delete(key);
      this.windows.set(key, { start: t, count: 1 });
      return true;
    }
    w.count += 1;
    return w.count <= this.limit;
  }
}
