import { Card } from "@locksmith-hq/ui/card";
import { Alert, AlertDescription } from "@locksmith-hq/ui/alert";
import { Label } from "@locksmith-hq/ui/label";
import { Button } from "@locksmith-hq/ui/button";
import { Dropdown, Option } from "../Dropdown";
import { PageHeader } from "@locksmith-hq/ui/page-header";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@locksmith-hq/ui/table";
import { useEffect, useRef, useState } from "react";
import {
  auditOutcomeMatches as auditMatches,
  type AuditOutcomeFilter as AuditFilter,
  type AuditEvent,
  type AuditStatus,
  type Client,
} from "@locksmith/control-plane-client";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

function chainSummary(s: AuditStatus): string {
  const v = s.latest_verify;
  if (!v) return "Not verified yet";
  if (v.ok) return `Verified OK at ${v.finished_at}`;
  return `Verification FAILED at ${v.finished_at}${v.broken_seq != null ? ` (first broken seq ${v.broken_seq}${v.break_kind ? `, ${v.break_kind}` : ""})` : ""}`;
}

export function Activity({ client }: { client: Client }) {
  const [status, setStatus] = useState<AuditStatus | null>(null);
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const inflight = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<AuditFilter>("all");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let live = true; // a response for an earlier client (org) is ignored
    setStatus(null);
    setEvents(null);
    setNext(null);
    setError(null);
    setLoadingMore(false);
    client.auditStatus().then(
      (s) => live && setStatus(s),
      (e) => live && setError(errMsg(e)),
    );
    client.listAuditEvents().then(
      (p) => {
        if (live) {
          setEvents(p.items);
          setNext(p.next ?? null);
        }
      },
      (e) => live && setError(errMsg(e)),
    );
    return () => {
      live = false;
    };
  }, [client, attempt]);

  const more = () => {
    if (inflight.current || !next) return;
    inflight.current = true;
    setLoadingMore(true);
    client
      .listAuditEvents({ cursor: next })
      .then(
        (p) => {
          setEvents((cur) => [...(cur ?? []), ...p.items]);
          setNext(p.next ?? null);
          setError(null);
        },
        (e) => setError(errMsg(e)),
      )
      .finally(() => {
        inflight.current = false;
        setLoadingMore(false);
      });
  };

  return (
    <section aria-label="Audit">
      <PageHeader title="Activity" />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
          {!events && (
            <Button variant="outline" size="sm" className="w-fit" onClick={() => setAttempt((n) => n + 1)}>
              Retry
            </Button>
          )}
        </Alert>
      )}
      {status && (
        <Card role="region" aria-label="Chain status" className="mb-4 gap-1 px-5">
          <p>Head seq: {status.head_seq}</p>
          <p>
            Latest checkpoint:{" "}
            {status.latest_checkpoint
              ? `seq ${status.latest_checkpoint.seq} at ${status.latest_checkpoint.at}`
              : "none yet"}
          </p>
          <p data-testid="verify-result">{chainSummary(status)}</p>
        </Card>
      )}
      <Label className="mb-3">
        Outcome{" "}
        <Dropdown aria-label="Outcome filter" value={filter} onChange={(e) => setFilter(e as AuditFilter)}>
          <Option value="all">All</Option>
          <Option value="denied">Denied</Option>
          <Option value="redaction_failed">Redaction failed</Option>
        </Dropdown>
      </Label>
      {!events ? (
        error ? null : (
          <p>Reading the ledger…</p>
        )
      ) : events.length === 0 ? (
        <p>No audit events yet.</p>
      ) : !events.some((e) => auditMatches(e, filter)) ? (
        <p>No matching events{next ? " loaded yet" : ""}.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Seq</TableHead>
              <TableHead>Time</TableHead>
              <TableHead>Kind</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Outcome</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {events
              .filter((e) => auditMatches(e, filter))
              .map((e) => (
                <TableRow key={e.id}>
                  <TableCell>{e.seq}</TableCell>
                  <TableCell>{e.at}</TableCell>
                  <TableCell>{e.kind}</TableCell>
                  <TableCell>{e.actor}</TableCell>
                  <TableCell>{e.target ?? ""}</TableCell>
                  <TableCell>{e.outcome}</TableCell>
                </TableRow>
              ))}
          </TableBody>
        </Table>
      )}
      {next && (
        <Button variant="outline" className="mt-3" disabled={loadingMore} onClick={more}>
          Load more
        </Button>
      )}
    </section>
  );
}
