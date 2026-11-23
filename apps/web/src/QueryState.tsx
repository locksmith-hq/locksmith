import { Loader } from "./Loader";
import type { ReactNode } from "react";
import { Empty } from "@locksmith/ui";

/** The part of a TanStack Query result this component reads, so any `useQuery` result fits. */
export interface QueryLike<T> {
  data: T | undefined;
  isPending: boolean;
  isError: boolean;
  error: unknown;
  refetch: () => unknown;
}

/**
 * Honest page states: loading, error with retry (never the empty message), empty, or the data.
 * `isEmpty` decides what counts as empty (default: an empty array).
 */
export function QueryState<T>({ query, isEmpty = (d) => Array.isArray(d) && d.length === 0, empty = "Nothing here yet.", children }: {
  query: QueryLike<T>;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (query.isPending) return <Loader />;
  if (query.isError || query.data === undefined) {
    const msg = query.error instanceof Error ? query.error.message : "request failed";
    return (
      <div role="alert" className="state">
        <p>{msg}</p>
        <button className="btn sm" onClick={() => void query.refetch()}>Retry</button>
      </div>
    );
  }
  if (isEmpty(query.data)) return <Empty icon="doc">{empty}</Empty>;
  return <>{children(query.data)}</>;
}
