import { Head } from "@locksmith/ui";
import { useEffect, useRef, useState } from "react";
import { auditOutcomeMatches as auditMatches, type AuditOutcomeFilter as AuditFilter, type AuditEvent, type AuditStatus, type Client } from "@locksmith/control-plane-client";

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
    setStatus(null); setEvents(null); setNext(null); setError(null); setLoadingMore(false);
    client.auditStatus().then((s) => live && setStatus(s), (e) => live && setError(errMsg(e)));
    client.listAuditEvents().then(
      (p) => { if (live) { setEvents(p.items); setNext(p.next ?? null); } },
      (e) => live && setError(errMsg(e)),
    );
    return () => { live = false; };
  }, [client, attempt]);

  const more = () => {
    if (inflight.current || !next) return;
    inflight.current = true;
    setLoadingMore(true);
    client.listAuditEvents({ cursor: next }).then(
      (p) => { setEvents((cur) => [...(cur ?? []), ...p.items]); setNext(p.next ?? null); setError(null); },
      (e) => setError(errMsg(e)),
    ).finally(() => { inflight.current = false; setLoadingMore(false); });
  };

  return (
    <section aria-label="Audit">
      <Head title="Activity" />
      {error && (
        <div role="alert" className="state">
          <p>{error}</p>
          {!events && <button className="btn sm" onClick={() => setAttempt((n) => n + 1)}>Retry</button>}
        </div>
      )}
      {status && (
        <div aria-label="Chain status" className="panel">
          <p>Head seq: {status.head_seq}</p>
          <p>
            Latest checkpoint:{" "}
            {status.latest_checkpoint ? `seq ${status.latest_checkpoint.seq} at ${status.latest_checkpoint.at}` : "none yet"}
          </p>
          <p data-testid="verify-result">{chainSummary(status)}</p>
        </div>
      )}
      <label>
        Outcome{" "}
        <select aria-label="Outcome filter" value={filter} onChange={(e) => setFilter(e.target.value as AuditFilter)}>
          <option value="all">All</option>
          <option value="denied">Denied</option>
          <option value="redaction_failed">Redaction failed</option>
        </select>
      </label>
      {!events ? (error ? null : <p>Reading the ledger…</p>) : events.length === 0 ? <p>No audit events yet.</p> : !events.some((e) => auditMatches(e, filter)) ? <p>No matching events{next ? " loaded yet" : ""}.</p> : (
        <table className="grid">
          <thead>
            <tr><th>Seq</th><th>Time</th><th>Kind</th><th>Actor</th><th>Target</th><th>Outcome</th></tr>
          </thead>
          <tbody>
            {events.filter((e) => auditMatches(e, filter)).map((e) => (
              <tr key={e.id}>
                <td>{e.seq}</td><td>{e.at}</td><td>{e.kind}</td><td>{e.actor}</td><td>{e.target ?? ""}</td><td>{e.outcome}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {next && <button className="btn" disabled={loadingMore} onClick={more}>Load more</button>}
    </section>
  );
}
