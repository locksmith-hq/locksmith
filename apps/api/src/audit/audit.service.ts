import { Inject, Injectable } from "@nestjs/common";
import type { Page } from "../platform/paging.js";
import { TenantService, type Tx } from "../tenant/tenant.service.js";
import type { AuditCheckpoint, AuditEvent, AuditStatus, AuditVerifyRun } from "./audit.schemas.js";

const iso = (d: Date) => new Date(d).toISOString();
const hex = (b: Buffer) => Buffer.from(b).toString("hex");

/** Rust `encode_cursor`: the last `seq` as 8 big-endian bytes, base64url. Paging stays stable while events append. */
export const encodeSeqCursor = (seq: number) => {
  const b = Buffer.alloc(8);
  b.writeBigInt64BE(BigInt(seq));
  return b.toString("base64url");
};

/** Rust `decode_cursor`: canonical base64url of exactly 8 bytes, seq >= 1. Returns the seq as a string key. */
export function decodeSeqCursor(cursor: string): string | null {
  if (!/^[A-Za-z0-9_-]+$/.test(cursor)) return null;
  const bytes = Buffer.from(cursor, "base64url");
  if (bytes.length !== 8 || bytes.toString("base64url") !== cursor) return null;
  const seq = bytes.readBigInt64BE();
  return seq >= 1n ? seq.toString() : null;
}

/**
 * The audit ledger, read side only: no append, no signing, no verification. Reads the ledger tables in the request's
 * tenant transaction (row-level security scopes every query).
 */
@Injectable()
export class AuditService {
  constructor(@Inject(TenantService) private readonly tenant: TenantService) {}

  private get tx(): Tx {
    return this.tenant.tx();
  }

  async listEvents(page: Page): Promise<{ items: AuditEvent[]; next?: string }> {
    let q = this.tx
      .selectFrom("audit_events")
      .select(["seq", "id", "at", "kind", "actor", "target", "outcome", "attrs", "prev_hash", "hash"]);
    if (page.after) q = q.where("seq", "<", page.after);
    const rows = await q
      .orderBy("seq", "desc")
      .limit(page.limit + 1)
      .execute();
    const more = rows.length > page.limit;
    const items: AuditEvent[] = rows.slice(0, page.limit).map((r) => ({
      seq: Number(r.seq),
      id: r.id,
      at: iso(r.at),
      kind: r.kind,
      actor: r.actor,
      ...(r.target !== null ? { target: r.target } : {}),
      outcome: r.outcome,
      attrs: (r.attrs ?? {}) as Record<string, unknown>,
      prev_digest: hex(r.prev_hash),
      digest: hex(r.hash),
    }));
    return more ? { items, next: encodeSeqCursor(items[items.length - 1]!.seq) } : { items };
  }

  async status(): Promise<AuditStatus> {
    const head = await this.tx.selectFrom("audit_heads").select("seq").executeTakeFirst();
    const cp = await this.tx
      .selectFrom("audit_checkpoints")
      .select(["seq", "hash", "at", "key_id"])
      .orderBy("seq", "desc")
      .limit(1)
      .executeTakeFirst();
    const v = await this.tx
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
    const latest_checkpoint: AuditCheckpoint | undefined = cp && {
      seq: Number(cp.seq),
      digest: hex(cp.hash),
      at: iso(cp.at),
      key_id: cp.key_id,
    };
    const latest_verify: AuditVerifyRun | undefined = v && {
      id: v.id,
      mode: v.mode,
      started_at: iso(v.started_at),
      finished_at: iso(v.finished_at),
      ok: v.ok,
      events: Number(v.events),
      checkpoints: Number(v.checkpoints),
      ...(v.broken_seq !== null ? { broken_seq: Number(v.broken_seq) } : {}),
      ...(v.break_kind !== null ? { break_kind: v.break_kind } : {}),
      ...(v.truncated_at !== null ? { truncated_at: Number(v.truncated_at) } : {}),
    };
    return {
      head_seq: head ? Number(head.seq) : 0,
      ...(latest_checkpoint ? { latest_checkpoint } : {}),
      ...(latest_verify ? { latest_verify } : {}),
    };
  }
}
