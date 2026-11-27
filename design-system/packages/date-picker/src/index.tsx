import { Fragment, useEffect, useId, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { CalendarDays, ChevronDown } from "lucide-react";
import { Button } from "@locksmith-hq/button";
import { addDays, addMonths, clamp, daysBetween, formatDate, monthGrid, today } from "./dates.js";

export interface DatePickerProps {
  /** Label shown above the field. */
  label: string;
  /** The date as `YYYY-MM-DD`, when the parent holds it. Pass `""` for none, and update it in `onChange`. */
  value?: string;
  /** Starting date as `YYYY-MM-DD`, when the field holds its own value. */
  defaultValue?: string;
  /** Earliest date that can be picked, as `YYYY-MM-DD`. */
  min?: string;
  /** Latest date that can be picked, as `YYYY-MM-DD`. */
  max?: string;
  /** Shortcut buttons, each a number of days from today. Multiples of 365 read as years. */
  presets?: number[];
  /**
   * First day of the week: `0` for Sunday, `1` for Monday.
   * @default 1
   */
  weekStart?: 0 | 1;
  /** Hint shown under the field. */
  help?: string;
  /** Error message under the field. It replaces `help` and marks the field invalid. */
  error?: string;
  /** Turns the field off: it cannot be focused or changed, and its value is not sent with a form. */
  disabled?: boolean;
  /** Marks the field as required, for screen readers. The browser does not check it, so check it when the form is sent. */
  required?: boolean;
  /** Field name, so the value is sent with a native form. */
  name?: string;
  /** Called with the picked date, as `YYYY-MM-DD`. */
  onChange?: (value: string) => void;
}

// Dates in Locksmith are lifetimes: when a grant expires, when a key rotates. So the calendar shows the life
// of the thing, a run of days from today to the chosen day, and says how long that is. Today carries the key
// tooth, the chosen day stands up like a button, and `presets` offers the usual lifetimes in days.
// Keys: arrows move by day and week, PageUp/PageDown by month, Enter picks, Escape closes.
// shortcut: inside a Dialog, Escape closes the dialog along with the calendar.
export function DatePicker(p: DatePickerProps) {
  const id = useId(),
    now = today();
  const [own, setValue] = useState(p.defaultValue || "");
  const value = p.value ?? own;
  const error = p.error;
  const [open, setOpen] = useState(false);
  const [cursor, setCursor] = useState(value || now);
  const [hover, setHover] = useState("");
  const root = useRef<HTMLDivElement>(null),
    trigger = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (open) root.current?.querySelector<HTMLElement>(`[data-day="${cursor}"]`)?.focus();
  }, [open, cursor]);
  const out = (d: string) => clamp(d, p.min, p.max) !== d;
  const move = (d: string) => {
    setHover("");
    setCursor(clamp(d, p.min, p.max));
  };
  const pick = (d: string) => {
    if (out(d)) return;
    setValue(d);
    p.onChange?.(d);
    setOpen(false);
    trigger.current?.focus();
  };
  const life = (d: string) => {
    const n = daysBetween(now, d),
      s = Math.abs(n) === 1 ? "" : "s";
    return n === 0 ? "today" : n > 0 ? `in ${n} day${s}` : `${-n} day${s} ago`;
  };
  function onKey(e: KeyboardEvent) {
    const step = ({ ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 } as Record<string, number>)[e.key];
    if (step) {
      e.preventDefault();
      move(addDays(cursor, step));
    } else if (e.key === "PageUp" || e.key === "PageDown") {
      e.preventDefault();
      move(addMonths(cursor, e.key === "PageUp" ? -1 : 1));
    } else if (e.key === "Escape") {
      setOpen(false);
      trigger.current?.focus();
    }
  }
  const end = hover || cursor;
  return (
    <div
      data-slot="date-picker"
      className="field"
      data-disabled={p.disabled || undefined}
      data-required={p.required || undefined}
      ref={root}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) setOpen(false);
      }}
    >
      <label htmlFor={id}>{p.label}</label>
      <div className="combo-box">
        <button
          id={id}
          ref={trigger}
          type="button"
          className="date-well"
          aria-haspopup="dialog"
          aria-expanded={open}
          disabled={p.disabled}
          aria-required={p.required || undefined}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={error || p.help ? id + "-note" : undefined}
          onClick={() => {
            setCursor(clamp(value || now, p.min, p.max));
            setHover("");
            setOpen(!open);
          }}
        >
          <CalendarDays />
          {value ? (
            <>
              <span>{formatDate(value, { day: "numeric", month: "short", year: "numeric" })}</span>
              <span className="date-life">{life(value)}</span>
            </>
          ) : (
            <span className="muted">Pick a date</span>
          )}
        </button>
        {open ? (
          // mousedown is cancelled so a click never moves focus out of the calendar (Safari does not focus buttons)
          <div
            className="date-pop"
            role="dialog"
            aria-label={p.label}
            onKeyDown={onKey}
            onMouseDown={(e) => e.preventDefault()}
            onMouseLeave={() => setHover("")}
          >
            <div className="date-head">
              <button type="button" aria-label="Previous month" onClick={() => move(addMonths(cursor, -1))}>
                <ChevronDown />
              </button>
              <b aria-live="polite">{formatDate(cursor, { month: "long", year: "numeric" })}</b>
              <button type="button" aria-label="Next month" onClick={() => move(addMonths(cursor, 1))}>
                <ChevronDown />
              </button>
            </div>
            <div className="date-grid">
              {monthGrid(cursor, p.weekStart ?? 1).map((d, i) => (
                <Fragment key={d}>
                  {i < 7 ? (
                    <span className="date-dow" aria-hidden="true" style={{ gridRow: 1, gridColumn: i + 1 }}>
                      {formatDate(d, { weekday: "narrow" })}
                    </span>
                  ) : null}
                  <button
                    type="button"
                    data-day={d}
                    tabIndex={d === cursor ? 0 : -1}
                    disabled={out(d)}
                    aria-label={formatDate(d, { dateStyle: "full" })}
                    aria-pressed={d === value}
                    aria-current={d === now ? "date" : undefined}
                    data-out={d.slice(0, 7) !== cursor.slice(0, 7) || undefined}
                    data-life={(d > now && d < end) || (d < now && d > end) || undefined}
                    data-end={(d === end && d !== value) || undefined}
                    onClick={() => pick(d)}
                    onMouseEnter={() => setHover(d)}
                  >
                    {Number(d.slice(8))}
                  </button>
                </Fragment>
              ))}
            </div>
            {p.presets?.length ? (
              <div className="date-presets">
                {p.presets.map((n) => (
                  <Button key={n} variant="outline" size="sm" onClick={() => pick(addDays(now, n))}>
                    {n % 365 === 0 ? `${n / 365} year${n === 365 ? "" : "s"}` : `${n} days`}
                  </Button>
                ))}
              </div>
            ) : null}
            <p className="date-foot">
              <span>{formatDate(end, { weekday: "long", day: "numeric", month: "long" })}</span>
              <span className="date-life">{life(end)}</span>
            </p>
          </div>
        ) : null}
      </div>
      {p.name && !p.disabled ? <input type="hidden" name={p.name} value={value} /> : null}
      {error ? (
        <span id={id + "-note"} className="error" role="alert">
          {error}
        </span>
      ) : p.help ? (
        <span id={id + "-note"} className="help">
          {p.help}
        </span>
      ) : null}
    </div>
  );
}

// The date maths, shared with DateRangePicker.
export { addDays, addMonths, clamp, daysBetween, formatDate, monthGrid, today } from "./dates.js";
