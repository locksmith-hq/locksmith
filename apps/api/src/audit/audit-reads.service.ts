import { Inject, Injectable } from "@nestjs/common";
import { parsePageQuery } from "../platform/paging.js";
import { ProblemException } from "../platform/problem.js";
import { TenantService } from "../tenant/tenant.service.js";
import type { AuditEvent, AuditStatus } from "./audit.schemas.js";

const iso = (d: Date) => new Date(d).toISOString();
const hex = (b: Buffer) => Buffer.from(b).toString("hex");
/** Postgres bigint comes back as a string; seqs and counts stay far below 2^53 (Rust serialises i64 as a JSON number). */
const num = (v: string | number | bigint) => Number(v);
const numOrNull = (v: string | number | bigint | null) => (v === null ? null : Number(v));

/** The cursor is the last `seq` returned: big-endian i64 as canonical base64url, so paging is stable under appends. */
const encodeCursor = (seq: number) => {
  const b = Buffer.alloc(8);
  b.writeBigInt64BE(BigInt(seq));
  return b.toString("base64url");
};

function decodeCursor(cursor: string): number | null {
  if (!/^[A-Za-z0-9_-]+$/.test(cursor)) return null;
  const bytes = Buffer.from(cursor, "base64url");
  if (bytes.length !== 8 || bytes.toString("base64url") !== cursor) return null;
  const seq = bytes.readBigInt64BE();
  return seq >= 1n ? Number(seq) : null;
}

/**
 * The audit ledger, read side (Rust `api/audit.rs`). Reads only, in the request's tenant transaction, so row-level
 * security shows an org nothing but its own ledger. Rows hold identifiers and public chain digests, never a secret.
 */
@Injectable()
export class AuditReadsService {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  async events(raw: unknown): Promise<{ items: AuditEvent[]; next?: string }> {
    const { limit, cursor } = parsePageQuery(raw);
    let before: number | null = null;
    if (cursor !== undefined) {
      before = decodeCursor(cursor);
      if (before === null) throw new ProblemException("validation", "`cursor` is not valid");
    }
    let q = this.tenant
      .tx()
      .selectFrom("audit_events")
      .select(["seq", "id", "at", "kind", "actor", "target", "outcome", "attrs", "prev_hash", "hash"]);
    if (before !== null) q = q.where("seq", "<", String(before));
    const rows = await q
      .orderBy("seq", "desc")
      .limit(limit + 1)
      .execute();
    const items: AuditEvent[] = rows.slice(0, limit).map((r) => ({
      seq: num(r.seq),
      id: r.id,
      at: iso(r.at),
      kind: r.kind,
      actor: r.actor,
      ...(r.target === null ? {} : { target: r.target }),
      outcome: r.outcome,
      attrs: r.attrs as Record<string, unknown>,
      prev_digest: hex(r.prev_hash),
      digest: hex(r.hash),
    }));
    return rows.length > limit ? { items, next: encodeCursor(items[items.length - 1]!.seq) } : { items };
  }

  async status(): Promise<AuditStatus> {
    const tx = this.tenant.tx();
    const head = await tx.selectFrom("audit_heads").select("seq").executeTakeFirst();
    const cp = await tx
      .selectFrom("audit_checkpoints")
      .select(["seq", "hash", "at", "key_id"])
      .orderBy("seq", "desc")
      .limit(1)
      .executeTakeFirst();
    const vr = await tx
      .selectFrom("audit_verify_runs")
      .select([
        "id",
        "mode",
        "started_at",
        "finished_at",
        "ok",
        "events",
        "checkpoints",
        "broken_seq",
        "break_kind",
        "truncated_at",
      ])
      .orderBy("finished_at", "desc")
      .orderBy("id", "desc")
      .limit(1)
      .executeTakeFirst();
    return {
      head_seq: head ? num(head.seq) : 0,
      ...(cp
        ? { latest_checkpoint: { seq: num(cp.seq), digest: hex(cp.hash), at: iso(cp.at), key_id: cp.key_id } }
        : {}),
      ...(vr
        ? {
            latest_verify: {
              id: vr.id,
              mode: vr.mode,
              started_at: iso(vr.started_at),
              finished_at: iso(vr.finished_at),
              ok: vr.ok,
              events: num(vr.events),
              checkpoints: num(vr.checkpoints),
              ...(vr.broken_seq === null ? {} : { broken_seq: numOrNull(vr.broken_seq) }),
              ...(vr.break_kind === null ? {} : { break_kind: vr.break_kind }),
              ...(vr.truncated_at === null ? {} : { truncated_at: numOrNull(vr.truncated_at) }),
            },
          }
        : {}),
    };
  }
}
