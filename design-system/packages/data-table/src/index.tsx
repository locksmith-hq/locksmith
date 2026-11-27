import { useState } from "react";
import type { ReactNode } from "react";
import { cn } from "cn";
import { ChevronDown } from "lucide-react";
import { Checkbox } from "@locksmith-hq/checkbox";
import { Skeleton } from "@locksmith-hq/skeleton";
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/table";
import { sortRows } from "./sort.js";

export type DataTableRow = Record<string, ReactNode> & { id: string; bad?: boolean };
export interface DataTableColumn {
  key: string;
  label: string;
  mono?: boolean;
  num?: boolean;
  muted?: boolean;
  /** Lets the person sort by this column. Text and number cells sort as they are. */
  sortable?: boolean;
  /** The value to sort by when the cell is not plain text or a number, such as a Pill or a formatted date. */
  sortBy?: (row: DataTableRow) => string | number | null | undefined;
}
export type DataTableSort = { key: string; dir: "asc" | "desc" };

export interface DataTableProps {
  /** The columns. `key` picks the cell from each row; `sortable` adds sorting; `mono`, `num` and `muted` style the cells. */
  columns: DataTableColumn[];
  /** One object per row, with a unique `id` and a cell for each column `key`. `bad: true` marks a row that needs attention. */
  rows: DataTableRow[];
  /** Adds a checkbox to every row and one in the header that selects them all. */
  selectable?: boolean;
  /** The selected row ids, when the parent holds the selection (needed to clear it from an ActionBar). Without it the table keeps its own. */
  selected?: string[];
  /** Called with the selected row ids each time the selection changes. */
  onSelectionChange?: (ids: string[]) => void;
  /** The sort applied at first. */
  defaultSort?: DataTableSort;
  /** Called with the new sort, or `null` when sorting is turned off. Sort on the server here when the rows are one page of many. */
  onSortChange?: (sort: DataTableSort | null) => void;
  /** Height in pixels after which the rows scroll under a header that stays in place. */
  maxHeight?: number;
  /** Shows five skeleton rows in place of the data. */
  loading?: boolean;
  /** Shown in place of the rows when there are none, normally an EmptyState. */
  empty?: ReactNode;
}

// The Table with the things a long list needs: sorting from the header, row selection, and a header that stays put.
// shortcut: sorts and renders every row it is given; paginate or sort on the server beyond a few hundred rows.
export function DataTable(p: DataTableProps) {
  const cols = p.columns || [];
  const [sort, setSort] = useState<DataTableSort | null>(p.defaultSort ?? null);
  const [own, setOwn] = useState<string[]>([]);
  const picked = p.selected ?? own;

  const by = cols.find((c) => c.key === sort?.key);
  const rows =
    sort && by ? sortRows(p.rows || [], (r) => (by.sortBy ? by.sortBy(r) : r[by.key]), sort.dir) : p.rows || [];
  const ids = rows.map((r) => r.id);
  const count = ids.filter((id) => picked.includes(id)).length;

  const pick = (next: string[]) => {
    setOwn(next);
    p.onSelectionChange?.(next);
  };
  // asc, then desc, then off: the third click returns the rows to the order they were given in.
  function turn(key: string) {
    const next: DataTableSort | null =
      sort?.key !== key ? { key, dir: "asc" } : sort.dir === "asc" ? { key, dir: "desc" } : null;
    setSort(next);
    p.onSortChange?.(next);
  }
  const span = cols.length + (p.selectable ? 1 : 0);
  const name = (r: DataTableRow) => (typeof r[cols[0]?.key] === "string" ? (r[cols[0].key] as string) : r.id);

  const cell = (c: DataTableColumn) =>
    cn(c.mono && "font-mono text-xs", c.num && "text-right", c.muted && "text-muted-foreground");

  // shadcn's Table parts in our own container: theirs scrolls sideways only, which would stop the header sticking.
  return (
    <div
      data-slot="table-container"
      className="relative w-full overflow-auto"
      style={p.maxHeight ? { maxHeight: p.maxHeight } : undefined}
    >
      <table data-slot="table" data-sticky={p.maxHeight ? "" : undefined} className="w-full caption-bottom text-sm">
        <TableHeader>
          <TableRow>
            {p.selectable ? (
              <TableHead className="w-px pr-0">
                <Checkbox
                  aria-label="Select all rows"
                  checked={count === 0 ? false : count === ids.length ? true : "indeterminate"}
                  disabled={p.loading || !ids.length}
                  onCheckedChange={(on) => pick(on === true ? ids : [])}
                />
              </TableHead>
            ) : null}
            {cols.map((c) => (
              <TableHead
                key={c.key}
                className={c.num ? "text-right" : undefined}
                aria-sort={sort?.key === c.key ? (sort.dir === "asc" ? "ascending" : "descending") : undefined}
              >
                {c.sortable ? (
                  <button
                    type="button"
                    className="sort"
                    data-dir={sort?.key === c.key ? sort.dir : undefined}
                    onClick={() => turn(c.key)}
                  >
                    {c.label}
                    <ChevronDown />
                  </button>
                ) : (
                  c.label
                )}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {p.loading ? (
            [0, 1, 2, 3, 4].map((i) => (
              <TableRow key={i}>
                {p.selectable ? <TableCell /> : null}
                {cols.map((c, j) => (
                  <TableCell key={c.key}>
                    <Skeleton className={j === 0 ? "h-3 w-40" : "h-3 w-18"} />
                  </TableCell>
                ))}
              </TableRow>
            ))
          ) : rows.length ? (
            rows.map((r) => (
              <TableRow
                key={r.id}
                data-bad={r.bad ? "true" : undefined}
                data-state={picked.includes(r.id) ? "selected" : undefined}
              >
                {p.selectable ? (
                  <TableCell className="w-px pr-0">
                    <Checkbox
                      aria-label={`Select ${name(r)}`}
                      checked={picked.includes(r.id)}
                      onCheckedChange={(on) =>
                        pick(on === true ? [...picked, r.id] : picked.filter((id) => id !== r.id))
                      }
                    />
                  </TableCell>
                ) : null}
                {cols.map((c) => (
                  <TableCell key={c.key} className={cell(c)}>
                    {r[c.key]}
                  </TableCell>
                ))}
              </TableRow>
            ))
          ) : (
            <TableRow>
              <TableCell colSpan={span} className="py-7 text-center">
                {p.empty ?? <span className="text-muted-foreground">Nothing to show.</span>}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </table>
    </div>
  );
}
