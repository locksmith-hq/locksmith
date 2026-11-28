import type { ComponentProps, ReactNode } from "react";
import { Field, FieldDescription, FieldError, FieldLabel } from "./index";

export interface LabeledFieldProps extends ComponentProps<typeof Field> {
  /** The id of the control inside. The note under it gets `id + "-note"`, for the control's `aria-describedby`. */
  id: string;
  label: ReactNode;
  help?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  disabled?: boolean;
}

// The shell the Locksmith-only form controls share, built from Field: the label, the control, then the error
// or, without one, the hint. Not exported from the package; an app composes Field's parts itself.
export function LabeledField({ id, label, help, error, required, disabled, children, ...props }: LabeledFieldProps) {
  return (
    <Field data-invalid={error ? true : undefined} data-disabled={disabled || undefined} {...props}>
      <FieldLabel htmlFor={id}>
        {label}
        {required ? (
          <span aria-hidden="true" className="text-(--destructive-text)">
            *
          </span>
        ) : null}
      </FieldLabel>
      {children}
      {error ? (
        <FieldError id={id + "-note"}>{error}</FieldError>
      ) : help ? (
        <FieldDescription id={id + "-note"}>{help}</FieldDescription>
      ) : null}
    </Field>
  );
}
