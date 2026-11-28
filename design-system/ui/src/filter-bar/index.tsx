import { useState } from "react";
import type { ComponentProps } from "react";
import { cn } from "cn";
import { ChevronDown } from "lucide-react";
import { Button } from "../button";
import { Checkbox } from "../checkbox";
import { Popover, PopoverContent, PopoverTrigger } from "../popover";
import { useLabels } from "../labels";

export type Filter = { key: string; label: string; options: string[] };
export type FilterValue = Record<string, string[]>;

export interface FilterBarProps extends Omit<ComponentProps<"div">, "onChange" | "defaultValue"> {
  /** The filters. Each opens a list of `options` to tick; `key` names it in the value. */
  filters: Filter[];
  /** Starting picks, by filter `key`. The bar keeps its own state after that. */
  defaultValue?: FilterValue;
  /** Called with every filter's picks each time one changes. A filter with no picks is left out. */
  onChange?: (value: FilterValue) => void;
}

// One row above a list: a search (the children), a button per filter with a count of its picks, and a way to clear them all.
export function FilterBar({ filters, defaultValue, onChange, className, children, ...props }: FilterBarProps) {
  const t = useLabels();
  const [value, setValue] = useState<FilterValue>(defaultValue ?? {});
  const put = (next: FilterValue) => {
    setValue(next);
    onChange?.(next);
  };
  function toggle(key: string, option: string) {
    const had = value[key] ?? [];
    const picks = had.includes(option) ? had.filter((o) => o !== option) : [...had, option];
    const { [key]: _, ...rest } = value;
    put(picks.length ? { ...rest, [key]: picks } : rest);
  }
  return (
    <div
      data-slot="filter-bar"
      className={cn("ls-filter-bar", className)}
      role="group"
      aria-label={t.filters}
      {...props}
    >
      {children}
      {(filters || []).map((f) => {
        const picks = value[f.key] ?? [];
        return (
          <Popover key={f.key}>
            <PopoverTrigger asChild>
              <Button variant="outline" size="sm">
                {f.label}
                {picks.length ? <span className="ls-filter-n">{picks.length}</span> : null}
                <ChevronDown />
              </Button>
            </PopoverTrigger>
            <PopoverContent align="start" className="w-auto min-w-44" aria-label={t.filterBy(f.label)}>
              <div className="ls-filter-opts">
                {f.options.map((o) => (
                  <label key={o} className="flex cursor-pointer items-center gap-2">
                    <Checkbox checked={picks.includes(o)} onCheckedChange={() => toggle(f.key, o)} />
                    {o}
                  </label>
                ))}
              </div>
            </PopoverContent>
          </Popover>
        );
      })}
      {Object.keys(value).length ? (
        <Button variant="ghost" size="sm" onClick={() => put({})}>
          Clear filters
        </Button>
      ) : null}
    </div>
  );
}
