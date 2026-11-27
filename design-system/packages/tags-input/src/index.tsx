import { useId, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { Chip } from "@locksmith-hq/chip";

export interface TagsInputProps {
  /** Label shown above the field. */
  label: string;
  /** The values, when the parent holds them. Update them in `onChange`. */
  value?: string[];
  /** Starting values, when the field holds its own. */
  defaultValue?: string[];
  /** Text shown while the field is empty. */
  placeholder?: string;
  /** Hint shown under the field. */
  help?: string;
  /** Error message under the field, for a check the parent made. A message from `validate` shows first. */
  error?: string;
  /** Turns the field off: it cannot be focused or changed, and its values are not sent with a form. */
  disabled?: boolean;
  /** Marks the field as required: the browser asks for at least one value. */
  required?: boolean;
  /** Field name. Each value is sent with a native form under this name. */
  name?: string;
  /** Monospace text, for ids, keys and other values a machine issued. */
  mono?: boolean;
  /** Checks one typed value. Return a message to reject it; the message shows under the field. */
  validate?: (value: string) => string | undefined;
  /** Called with all the values each time one is added or removed. */
  onChange?: (values: string[]) => void;
}

// Free-typed values kept as chips: hosts, IP ranges, scopes. Enter or a comma adds one, Backspace on an empty
// input removes the last, and pasted text is split on commas and spaces. Use Combobox to pick from a known list.
export function TagsInput(p: TagsInputProps) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [own, setTags] = useState<string[]>(p.defaultValue ?? []);
  const tags = p.value ?? own;
  const [text, setText] = useState("");
  const [rejected, setError] = useState<string>();
  const error = rejected || p.error;
  const put = (next: string[]) => {
    setTags(next);
    p.onChange?.(next);
  };
  // Adds every valid, new value; the first one rejected stays in the input with its message.
  function add(raw: string) {
    const next = [...tags];
    const values = raw.split(/[\s,]+/).filter(Boolean);
    for (const [i, v] of values.entries()) {
      if (next.includes(v)) continue;
      const why = p.validate?.(v);
      if (why) {
        if (next.length > tags.length) put(next);
        setText(values.slice(i).join(" ")); // keep what was not added, so nothing typed is lost
        setError(why);
        return;
      }
      next.push(v);
    }
    if (next.length > tags.length) put(next);
    setText("");
    setError(undefined);
  }
  function onKey(e: KeyboardEvent) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      add(text);
    } else if (e.key === "Backspace" && !text && tags.length) put(tags.slice(0, -1));
  }
  return (
    <div
      data-slot="tags-input"
      className="field"
      data-disabled={p.disabled || undefined}
      data-required={p.required || undefined}
    >
      <label htmlFor={id}>{p.label}</label>
      <div className="combo-box">
        <div
          className="combo-well tags-well"
          onMouseDown={(e) => {
            if (e.target !== input.current && !(e.target as Element).closest("button")) {
              e.preventDefault();
              input.current?.focus();
            }
          }}
        >
          {tags.map((t) => (
            <Chip key={t} onRemove={p.disabled ? undefined : () => put(tags.filter((x) => x !== t))}>
              {t}
            </Chip>
          ))}
          <input
            id={id}
            ref={input}
            className={p.mono ? "mono" : undefined}
            value={text}
            placeholder={tags.length ? undefined : p.placeholder}
            autoComplete="off"
            disabled={p.disabled}
            required={p.required && !tags.length}
            aria-invalid={error ? "true" : undefined}
            aria-describedby={error || p.help ? id + "-note" : undefined}
            onChange={(e) => {
              setText(e.target.value);
              setError(undefined);
            }}
            onKeyDown={onKey}
            onPaste={(e) => {
              e.preventDefault();
              add(text + e.clipboardData.getData("text"));
            }}
            onBlur={() => add(text)}
          />
        </div>
      </div>
      {p.name && !p.disabled ? tags.map((t) => <input key={t} type="hidden" name={p.name} value={t} />) : null}
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
