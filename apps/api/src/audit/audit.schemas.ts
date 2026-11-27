import { z } from "zod";

/** Response schemas of the audit reads, for the OpenAPI registry (Rust `api/audit.rs`). */
export const AuditEventSchema = z.object({
  seq: z.number().int(),
  id: z.string(),
  at: z.string(),
  kind: z.string(),
  actor: z.string(),
  target: z.string().nullable().optional(),
  outcome: z.string(),
  attrs: z.record(z.string(), z.unknown()),
  prev_digest: z.string(),
  digest: z.string(),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

const AuditCheckpointSchema = z.object({
  seq: z.number().int(),
  digest: z.string(),
  at: z.string(),
  key_id: z.string(),
});

const AuditVerifyRunSchema = z.object({
  id: z.string(),
  mode: z.string(),
  started_at: z.string(),
  finished_at: z.string(),
  ok: z.boolean(),
  events: z.number().int(),
  checkpoints: z.number().int(),
  broken_seq: z.number().int().nullable().optional(),
  break_kind: z.string().nullable().optional(),
  truncated_at: z.number().int().nullable().optional(),
});

export const AuditStatusSchema = z.object({
  head_seq: z.number().int(),
  latest_checkpoint: AuditCheckpointSchema.nullable().optional(),
  latest_verify: AuditVerifyRunSchema.nullable().optional(),
});
export type AuditStatus = z.infer<typeof AuditStatusSchema>;
