import { useId, useState } from "react";
import type { ChangeEvent, ComponentProps } from "react";
import { Lock, LockOpen } from "lucide-react";
import { LabeledField } from "../field/shell";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "../input-group";
import { useLabels } from "../labels";

export interface PasswordFieldProps extends Omit<ComponentProps<"div">, "onChange" | "defaultValue" | "children"> {
  /** Label shown above the field. */
  label: string;
  /** The value, when the parent holds it. Update it in `onChange`. */
  value?: string;
  /** Starting value, when the field holds its own value. */
  defaultValue?: string;
  /** Text shown while the field is empty. */
  placeholder?: string;
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
  /**
   * What the browser may fill in. Use `new-password` when the person is setting a value and `current-password` when signing in.
   * @default "off"
   */
  autoComplete?: "off" | "current-password" | "new-password";
  /** Called with the input's change event. */
  onChange?: (e: ChangeEvent<HTMLInputElement>) => void;
}

// A field for typing or pasting a secret: masked until its lock is opened, never spell-checked.
export function PasswordField({
  label,
  value,
  defaultValue,
  placeholder,
  help,
  error,
  disabled,
  required,
  name,
  autoComplete = "off",
  onChange,
  ...rest
}: PasswordFieldProps) {
  const t = useLabels();
  const id = useId();
  const [shown, show] = useState(false);
  return (
    <LabeledField id={id} label={label} help={help} error={error} required={required} disabled={disabled} {...rest}>
      <InputGroup>
        <InputGroupInput
          id={id}
          type={shown ? "text" : "password"}
          className="font-mono text-(length:--font-size-sm)"
          name={name}
          value={value}
          defaultValue={defaultValue}
          disabled={disabled}
          required={required}
          aria-describedby={error || help ? id + "-note" : undefined}
          placeholder={placeholder}
          autoComplete={autoComplete}
          spellCheck={false}
          aria-invalid={error ? "true" : undefined}
          onChange={onChange}
        />
        <InputGroupAddon align="inline-end">
          <InputGroupButton
            size="icon-xs"
            className="aria-pressed:text-(--brand-text)"
            disabled={disabled}
            aria-pressed={shown}
            aria-label={shown ? t.hideValue : t.showValue}
            onClick={() => show(!shown)}
          >
            {shown ? <LockOpen /> : <Lock />}
          </InputGroupButton>
        </InputGroupAddon>
      </InputGroup>
    </LabeledField>
  );
}
