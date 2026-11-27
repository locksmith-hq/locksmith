import { useId, useState } from "react";
import { Lock, LockOpen } from "lucide-react";

export interface PasswordFieldProps {
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
  onChange?: (e: any) => void;
}

// A field for typing or pasting a secret: masked until its lock is opened, never spell-checked.
export function PasswordField(p: PasswordFieldProps) {
  const id = useId();
  const [shown, show] = useState(false);
  const error = p.error;
  return (
    <div
      data-slot="password-field"
      className="field"
      data-disabled={p.disabled || undefined}
      data-required={p.required || undefined}
    >
      <label htmlFor={id}>{p.label}</label>
      <span className="pw">
        <input
          id={id}
          type={shown ? "text" : "password"}
          className="mono"
          name={p.name}
          value={p.value}
          defaultValue={p.defaultValue}
          disabled={p.disabled}
          required={p.required}
          aria-describedby={error || p.help ? id + "-note" : undefined}
          placeholder={p.placeholder}
          autoComplete={p.autoComplete ?? "off"}
          spellCheck={false}
          aria-invalid={p.error ? "true" : undefined}
          onChange={p.onChange}
        />
        <button
          type="button"
          disabled={p.disabled}
          aria-pressed={shown}
          aria-label={shown ? "Hide value" : "Show value"}
          onClick={() => show(!shown)}
        >
          {shown ? <LockOpen /> : <Lock />}
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
