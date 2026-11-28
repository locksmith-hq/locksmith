// Calendar-date maths for the DatePicker, on ISO strings (YYYY-MM-DD) in UTC so daylight saving never shifts a day.
const DAY = 86400000;
const parse = (iso: string) => new Date(iso + "T00:00:00Z");
const toISO = (d: Date) => d.toISOString().slice(0, 10);

export const addDays = (iso: string, n: number) => toISO(new Date(parse(iso).getTime() + n * DAY));
export const daysBetween = (from: string, to: string) =>
  Math.round((parse(to).getTime() - parse(from).getTime()) / DAY);

// `iso` moved inside min..max; either end may be missing.
export const clamp = (iso: string, min?: string, max?: string) =>
  min && iso < min ? min : max && iso > max ? max : iso;

// Same day of the month n months away, clamped to that month's last day (31 Jan + 1 month = 28 Feb).
export function addMonths(iso: string, n: number): string {
  const d = parse(iso),
    day = d.getUTCDate();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() + n);
  const last = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(day, last));
  return toISO(d);
}

// The 42 days (six weeks) that show the month of `iso`, starting on weekStart (0 Sunday, 1 Monday).
export function monthGrid(iso: string, weekStart = 1): string[] {
  const first = iso.slice(0, 8) + "01";
  const lead = (parse(first).getUTCDay() - weekStart + 7) % 7;
  return Array.from({ length: 42 }, (_, i) => addDays(first, i - lead));
}

// Today's date where the person is, as an ISO string.
export function today(): string {
  const n = new Date();
  return toISO(new Date(Date.UTC(n.getFullYear(), n.getMonth(), n.getDate())));
}

export const formatDate = (iso: string, opts: Intl.DateTimeFormatOptions) =>
  new Intl.DateTimeFormat(undefined, { timeZone: "UTC", ...opts }).format(parse(iso));
