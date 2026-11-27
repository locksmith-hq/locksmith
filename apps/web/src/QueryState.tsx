import type { ReactNode } from "react";
import { FileText } from "lucide-react";
import { Alert, AlertDescription } from "@locksmith-hq/alert";
import { Button } from "@locksmith-hq/button";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia } from "@locksmith-hq/empty";
import { Loader } from "@locksmith-hq/loader";

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
export function QueryState<T>({
  query,
  isEmpty = (d) => Array.isArray(d) && d.length === 0,
  empty = "Nothing here yet.",
  children,
}: {
  query: QueryLike<T>;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (query.isPending) return <Loader />;
  if (query.isError || query.data === undefined) {
    const msg = query.error instanceof Error ? query.error.message : "request failed";
    return (
      <Alert variant="destructive">
        <AlertDescription>
          <p>{msg}</p>
          <Button variant="outline" size="sm" className="mt-2 w-fit" onClick={() => void query.refetch()}>
            Retry
          </Button>
        </AlertDescription>
      </Alert>
    );
  }
  if (isEmpty(query.data))
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <FileText />
          </EmptyMedia>
          <EmptyDescription>{empty}</EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  return <>{children(query.data)}</>;
}
