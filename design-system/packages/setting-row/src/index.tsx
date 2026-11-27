import type { ComponentProps, ReactNode } from "react";
import { cn } from "cn";

export interface SettingRowProps extends Omit<ComponentProps<"div">, "title" | "about"> {
  /** The setting's name. */
  title: string;
  /** What the setting does, under the name. */
  about?: ReactNode;
}

// One setting: what it does on the left, its control (the children) on the right.
export function SettingRow({ title, about, className, children, ...props }: SettingRowProps) {
  return (
    <div data-slot="setting-row" className={cn("set-row", className)} {...props}>
      <div>
        <b>{title}</b>
        {about ? <p>{about}</p> : null}
      </div>
      <div className="set-ctl">{children}</div>
    </div>
  );
}
