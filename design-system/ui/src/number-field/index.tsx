import { useId, useRef } from "react";
import type { ComponentProps } from "react";
import { Button } from "../button";
import { ButtonGroup } from "../button-group";
import { LabeledField } from "../field/shell";
import { Input } from "../input";
import { useLabels } from "../labels";

export interface NumberFieldProps extends Omit<ComponentProps<"div">, "onChange" | "defaultValue" | "children"> {
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
export function NumberField({
  label,
  value,
  defaultValue,
  min,
  max,
  step,
  help,
  error,
  disabled,
  required,
  name,
  onChange,
  ...rest
}: NumberFieldProps) {
  const t = useLabels();
  const id = useId();
  const ref = useRef<HTMLInputElement>(null);
  const bump = (up: boolean) => {
    const el = ref.current;
    if (!el) return;
    if (up) el.stepUp();
    else el.stepDown();
    onChange?.(el.valueAsNumber);
  };
  return (
    <LabeledField id={id} label={label} help={help} error={error} required={required} disabled={disabled} {...rest}>
      {/* Field stretches its children; the wrapper takes that so the stepper keeps its own width. */}
      <div>
        <ButtonGroup className="w-37.5">
          <Button
            variant="outline"
            size="icon"
            tabIndex={-1}
            aria-label={t.decrease}
            disabled={disabled}
            onClick={() => bump(false)}
          >
            −
          </Button>
          <Input
            id={id}
            ref={ref}
            type="number"
            className="[appearance:textfield] px-1 text-center font-mono text-(length:--font-size-sm) [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
            name={name}
            value={value === undefined ? undefined : Number.isNaN(value) ? "" : value}
            defaultValue={defaultValue}
            disabled={disabled}
            required={required}
            aria-invalid={error ? "true" : undefined}
            aria-describedby={error || help ? id + "-note" : undefined}
            min={min}
            max={max}
            step={step}
            onChange={(e) => onChange?.(e.target.valueAsNumber)}
          />
          <Button
            variant="outline"
            size="icon"
            tabIndex={-1}
            aria-label={t.increase}
            disabled={disabled}
            onClick={() => bump(true)}
          >
            +
          </Button>
        </ButtonGroup>
      </div>
    </LabeledField>
  );
}
