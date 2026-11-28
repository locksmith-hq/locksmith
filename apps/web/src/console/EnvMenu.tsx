// The kebab on an environment's row: what can be done with that environment.
import { Button } from "@locksmith-hq/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@locksmith-hq/ui/dropdown-menu";
import { EllipsisVertical } from "lucide-react";

export interface EnvAction {
  label: string;
  run: () => void;
  danger?: boolean;
}

export function EnvMenu({ env, actions }: { env: string; actions: EnvAction[] }) {
  if (actions.length === 0) return null;
  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" type="button" aria-label={`Actions for ${env}`}>
          <EllipsisVertical />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {actions.map((a) => (
          <DropdownMenuItem key={a.label} variant={a.danger ? "destructive" : "default"} onSelect={a.run}>
            {a.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
