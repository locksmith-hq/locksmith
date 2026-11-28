import type { ComponentProps } from "react";
import { Fragment, useEffect, useId, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { addDays, addMonths, clamp, daysBetween, formatDate, monthGrid, today } from "../date-picker";
import { CalendarDays, ChevronDown } from "lucide-react";
import { Button } from "../button";

export type DateRange = { from: string; to: string };
import { LabeledField } from "../field/shell";
import { useLabels } from "../labels";

export interface DateRangePickerProps extends Omit<ComponentProps<"div">, "onChange" | "defaultValue" | "children"> {
  /** Label shown above the field. */
  label: string;
  /** The range, when the parent holds it. Pass `null` for none, and update it in `onChange`. */
  value?: DateRange | null;
  /** Starting range, both ends as `YYYY-MM-DD`, when the field holds its own value. */
  defaultValue?: DateRange;
  /** Earliest date that can be picked, as `YYYY-MM-DD`. */
  min?: string;
  /** Latest date that can be picked, as `YYYY-MM-DD`. Set it to today for logs and usage, which have no future. */
  max?: string;
  /** Shortcut buttons, each a number of days ending today: `7` reads "Last 7 days". */
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
  /** Field name, so the range is sent with a native form, as `from/to`. */
  name?: string;
  /** Called with the picked range once both ends are set. Both ends are included. */
  onChange?: (range: DateRange) => void;
}

// A window of days, for an audit log or a usage chart: click the first day, then the last (either order).
// Keys: arrows move by day and week, PageUp/PageDown by month, Enter picks, Escape closes.
// shortcut: inside a Dialog, Escape closes the dialog along with the calendar.
export function DateRangePicker({
  label,
  value: valueProp,
  defaultValue,
  min,
  max,
  presets,
  weekStart,
  help,
  error: errorProp,
  disabled,
  required,
  name,
  onChange,
  ...rest
}: DateRangePickerProps) {
  const t = useLabels();
  const id = useId(),
    now = today();
  const [own, setValue] = useState<DateRange | null>(defaultValue ?? null);
  const value = valueProp !== undefined ? valueProp : own;
  const error = errorProp;
  const [open, setOpen] = useState(false);
  const [start, setStart] = useState(""); // the first click, while the second is still to come
  const [cursor, setCursor] = useState(value?.to || now);
  const [hover, setHover] = useState("");
  const root = useRef<HTMLDivElement>(null),
    trigger = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (open) root.current?.querySelector<HTMLElement>(`[data-day="${cursor}"]`)?.focus();
  }, [open, cursor]);
  const out = (d: string) => clamp(d, min, max) !== d;
  const move = (d: string) => {
    setHover("");
    setCursor(clamp(d, min, max));
  };
  function done(range: DateRange) {
    setValue(range);
    setStart("");
    onChange?.(range);
    setOpen(false);
    trigger.current?.focus();
  }
  function pick(d: string) {
    if (out(d)) return;
    if (!start) setStart(d);
    else done(d < start ? { from: d, to: start } : { from: start, to: d });
  }
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
      setStart("");
      trigger.current?.focus();
    }
  }
  // What the grid draws: the range being picked (first click to the pointer), or the range already set.
  const other = hover || cursor;
  const shown: DateRange | null = start
    ? other < start
      ? { from: other, to: start }
      : { from: start, to: other }
    : value;
  const days = (r: DateRange) => {
    const n = daysBetween(r.from, r.to) + 1;
    return `${n} day${n === 1 ? "" : "s"}`;
  };
  const short = (d: string) => formatDate(d, { day: "numeric", month: "short", year: "numeric" });
  return (
    <LabeledField
      id={id}
      label={label}
      help={help}
      error={error}
      required={required}
      disabled={disabled}
      {...rest}
      ref={root}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node)) {
          setOpen(false);
          setStart("");
        }
      }}
    >
      <div className="ls-combo-box ls-range">
        <button
          id={id}
          ref={trigger}
          type="button"
          className="ls-date-well"
          aria-haspopup="dialog"
          aria-expanded={open}
          disabled={disabled}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={error || help ? id + "-note" : undefined}
          onClick={() => {
            setCursor(clamp(value?.to || now, min, max));
            setHover("");
            setStart("");
            setOpen(!open);
          }}
        >
          <CalendarDays />
          {value ? (
            <>
              <span>
                {short(value.from)} – {short(value.to)}
              </span>
              <span className="ls-date-life">{days(value)}</span>
            </>
          ) : (
            <span className="ls-muted">{t.pickRange}</span>
          )}
        </button>
        {open ? (
          // mousedown is cancelled so a click never moves focus out of the calendar (Safari does not focus buttons)
          <div
            className="ls-date-pop"
            role="dialog"
            aria-label={label}
            onKeyDown={onKey}
            onMouseDown={(e) => e.preventDefault()}
            onMouseLeave={() => setHover("")}
          >
            <div className="ls-date-head">
              <button type="button" aria-label={t.previousMonth} onClick={() => move(addMonths(cursor, -1))}>
                <ChevronDown />
              </button>
              <b aria-live="polite">{formatDate(cursor, { month: "long", year: "numeric" })}</b>
              <button type="button" aria-label={t.nextMonth} onClick={() => move(addMonths(cursor, 1))}>
                <ChevronDown />
              </button>
            </div>
            <div className="ls-date-grid">
              {monthGrid(cursor, weekStart ?? 1).map((d, i) => {
                const end = !!shown && (d === shown.from || d === shown.to);
                return (
                  <Fragment key={d}>
                    {i < 7 ? (
                      <span className="ls-date-dow" aria-hidden="true" style={{ gridRow: 1, gridColumn: i + 1 }}>
                        {formatDate(d, { weekday: "narrow" })}
                      </span>
                    ) : null}
                    <button
                      type="button"
                      data-day={d}
                      tabIndex={d === cursor ? 0 : -1}
                      disabled={out(d)}
                      aria-label={formatDate(d, { dateStyle: "full" })}
                      aria-pressed={end}
                      aria-current={d === now ? "date" : undefined}
                      data-out={d.slice(0, 7) !== cursor.slice(0, 7) || undefined}
                      data-life={(!!shown && d > shown.from && d < shown.to) || undefined}
                      onClick={() => pick(d)}
                      onMouseEnter={() => setHover(d)}
                    >
                      {Number(d.slice(8))}
                    </button>
                  </Fragment>
                );
              })}
            </div>
            {presets?.length ? (
              <div className="ls-date-presets">
                {presets.map((n) => (
                  <Button
                    key={n}
                    variant="outline"
                    size="sm"
                    onClick={() => done({ from: clamp(addDays(now, 1 - n), min, max), to: clamp(now, min, max) })}
                  >
                    Last {n} days
                  </Button>
                ))}
              </div>
            ) : null}
            <p className="ls-date-foot">
              <span>{start ? "Now pick the last day" : "Pick the first day"}</span>
              {shown ? <span className="ls-date-life">{days(shown)}</span> : null}
            </p>
          </div>
        ) : null}
      </div>
      {name && !disabled && value ? <input type="hidden" name={name} value={`${value.from}/${value.to}`} /> : null}
    </LabeledField>
  );
}
