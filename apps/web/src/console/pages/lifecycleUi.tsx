// Rollback confirmation for the History page.
import { Button } from "@locksmith-hq/ui/button";
import { plural } from "../kit";
import { later, stamp, type Entry, type P } from "./lifecycleStore";

/** Inline confirmation before a rollback: says exactly what is undone. Nobody sees a value. */
export function RollbackAsk({
  s,
  e,
  onApply,
  onCancel,
}: {
  s: P;
  e: Entry;
  onApply: () => void;
  onCancel: () => void;
}) {
  const undo = later(s, e);
  return (
    <div className="alert lc-ask" role="alert">
      <p>
        This sets {e.name} in {e.env} back to how it was on {stamp(e.at)}. It undoes{" "}
        {plural(undo.length, "later change")}: {undo.map((u) => `${u.act.toLowerCase()} (${u.note})`).join("; ")}.
      </p>
      <p>The current value is kept as a new version, so you can roll forward again. Nobody sees any value.</p>
      <p>
        <Button variant="destructive" size="sm" type="button" onClick={onApply}>
          Roll back {e.name}
        </Button>{" "}
        <Button variant="ghost" size="sm" type="button" onClick={onCancel}>
          Cancel
        </Button>
      </p>
    </div>
  );
}
