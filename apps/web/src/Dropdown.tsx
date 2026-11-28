import { Children, Fragment, isValidElement } from "react";
import type { ReactNode } from "react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@locksmith-hq/ui/select";

type OptionProps = { value?: string | number; disabled?: boolean; children: ReactNode };

/** One choice of a Dropdown. Its text is the value when `value` is left out, as with a native option. */
export const Option = (_: OptionProps) => null;

function read(children: ReactNode): OptionProps[] {
  return Children.toArray(children).flatMap((c) =>
    !isValidElement<OptionProps>(c) ? [] : c.type === Fragment ? read(c.props.children) : [c.props],
  );
}

export interface DropdownProps {
  children: ReactNode;
  value?: string | number;
  defaultValue?: string | number;
  onChange?: (value: string) => void;
  name?: string;
  disabled?: boolean;
  autoFocus?: boolean;
  id?: string;
  className?: string;
  "aria-label"?: string;
}

// The kit's Select in the shape of a native select: Option children, `name` for a form, and the first option
// chosen when no value is given. Values are always strings.
// shortcut: an Option with an empty value is not supported (Radix refuses it); use a real value for "none".
export function Dropdown({ children, value, defaultValue, onChange, name, disabled, ...trigger }: DropdownProps) {
  const options = read(children).map((o) => ({
    ...o,
    value: String(o.value ?? Children.toArray(o.children).join("")),
  }));
  return (
    <Select
      name={name}
      disabled={disabled}
      onValueChange={onChange}
      {...(value !== undefined
        ? { value: String(value) }
        : { defaultValue: String(defaultValue ?? options[0]?.value ?? "") })}
    >
      <SelectTrigger {...trigger}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value} disabled={o.disabled}>
            {o.children}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
