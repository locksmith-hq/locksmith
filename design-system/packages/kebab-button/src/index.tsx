import type { ComponentProps } from "react";
import { EllipsisIcon, EllipsisVerticalIcon } from "lucide-react";
import { Button } from "@locksmith-hq/button";

export interface KebabButtonProps extends Omit<ComponentProps<typeof Button>, "children"> {
  /**
   * Which way the three dots run. Vertical at the end of a table row or a card; horizontal in a toolbar or header.
   * @default "vertical"
   */
  orientation?: "vertical" | "horizontal";
  /**
   * What the button is called for screen readers. Name the thing it acts on: "Actions for deploy-bot".
   * @default "More actions"
   */
  label?: string;
}

// The three-dot button that opens a menu of more actions. It is a kit Button, so it takes every Button prop
// and works as a trigger: <DropdownMenuTrigger asChild><KebabButton /></DropdownMenuTrigger>.
export function KebabButton({
  orientation = "vertical",
  label = "More actions",
  variant = "ghost",
  size = "icon-sm",
  ...props
}: KebabButtonProps) {
  return (
    <Button data-kebab={orientation} variant={variant} size={size} aria-label={label} {...props}>
      {orientation === "horizontal" ? <EllipsisIcon /> : <EllipsisVerticalIcon />}
    </Button>
  );
}
