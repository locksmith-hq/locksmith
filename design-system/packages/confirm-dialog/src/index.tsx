import { useEffect, useId, useState } from "react";
import type { ReactNode } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@locksmith-hq/alert-dialog";
import { Input } from "@locksmith-hq/input";
import { Label } from "@locksmith-hq/label";

export interface ConfirmDialogProps {
  /** Whether it is shown. The component is controlled: the parent holds this state. */
  open: boolean;
  /** Called when it should close: on Escape, Cancel, or after confirming. */
  onClose: () => void;
  /** Called when the person confirms. `onClose` is called right after. */
  onConfirm: () => void;
  /** The question, naming the thing: "Revoke deploy-bot's grant?" */
  title: string;
  /** What will happen, and whether it can be undone. */
  children?: ReactNode;
  /**
   * Text of the confirm button. Name the action, not "OK".
   * @default "Confirm"
   */
  confirmLabel?: string;
  /** Makes the confirm button red, for actions that cannot be undone. */
  danger?: boolean;
  /** A phrase the person must type before the confirm button works, such as the name of the thing being deleted. */
  confirmText?: string;
}

// shadcn's AlertDialog, with the one thing it lacks: for the worst actions the person types a phrase first.
export function ConfirmDialog(p: ConfirmDialogProps) {
  const id = useId();
  const [typed, setTyped] = useState("");
  useEffect(() => {
    if (!p.open) setTyped("");
  }, [p.open]);
  return (
    <AlertDialog open={p.open} onOpenChange={(open) => !open && p.onClose()}>
      <AlertDialogContent data-slot="confirm-dialog">
        <AlertDialogHeader>
          <AlertDialogTitle>{p.title}</AlertDialogTitle>
          {p.children ? <AlertDialogDescription>{p.children}</AlertDialogDescription> : null}
        </AlertDialogHeader>
        {p.confirmText ? (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor={id}>
              Type <span className="font-mono">{p.confirmText}</span> to confirm
            </Label>
            <Input
              id={id}
              className="font-mono"
              autoComplete="off"
              spellCheck={false}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
            />
          </div>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            variant={p.danger ? "destructive" : "default"}
            disabled={!!p.confirmText && typed !== p.confirmText}
            onClick={p.onConfirm}
          >
            {p.confirmLabel || "Confirm"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
