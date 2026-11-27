import { useId, useRef } from "react";

export interface NumberFieldProps {
  /** Label shown above the field. */
  label: string;
  /** The number, when the parent holds it. Pass `NaN` for empty, and update it in `onChange`. */
  value?: number;
  /** Starting number, when the field holds its own value. */
  defaultValue?: number;
  /** Lowest number allowed. */
  min?: number;
  /** Highest number allowed. */
  max?: number;
  /** How much one press of a step button or arrow key adds or removes. */
  step?: number;
  /** Hint shown under the field. */
  help?: string;
  /** Error message under the field. It replaces `help` and marks the field invalid. */
  error?: string;
  /** Turns the field off: it cannot be focused or changed, and its value is not sent with a form. */
  disabled?: boolean;
  /** Marks the field as required, for the browser and for screen readers. */
  required?: boolean;
  /** Field name, so the value is sent with a native form. */
  name?: string;
  /** Called with the new number. It is `NaN` while the input is empty. */
  onChange?: (value: number) => void;
}

// A number in a well with a raised step button on each side. The native input does the stepping and clamping
// (arrow keys too), so the buttons stay out of the tab order.
export function NumberField(p: NumberFieldProps) {
  const id = useId();
  const ref = useRef<HTMLInputElement>(null);
  const error = p.error;
  const bump = (up: boolean) => {
    const el = ref.current;
    if (!el) return;
    if (up) el.stepUp();
    else el.stepDown();
    p.onChange?.(el.valueAsNumber);
  };
  return (
    <div
      data-slot="number-field"
      className="field"
      data-disabled={p.disabled || undefined}
      data-required={p.required || undefined}
    >
      <label htmlFor={id}>{p.label}</label>
      <span className="stepper">
        <button type="button" tabIndex={-1} aria-label="Decrease" disabled={p.disabled} onClick={() => bump(false)}>
          −
        </button>
        <input
          id={id}
          ref={ref}
          type="number"
          name={p.name}
          value={p.value === undefined ? undefined : Number.isNaN(p.value) ? "" : p.value}
          defaultValue={p.defaultValue}
          disabled={p.disabled}
          required={p.required}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={error || p.help ? id + "-note" : undefined}
          min={p.min}
          max={p.max}
          step={p.step}
          onChange={(e) => p.onChange?.(e.target.valueAsNumber)}
        />
        <button type="button" tabIndex={-1} aria-label="Increase" disabled={p.disabled} onClick={() => bump(true)}>
          +
        </button>
      </span>
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
