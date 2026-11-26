import { z } from "zod";

/** Frozen contract shapes: a plain `integer` (no safe-integer bounds), nullable variants and `oneOf` as utoipa emits. */
const Int = z.number().meta({ type: "integer" });
const NullableInt = z.number().meta({ type: ["integer", "null"] });

/** One audit event: identifier-only columns and the public chain digests (Rust `AuditEvent`). */
export const AuditEvent = z.object({
  seq: Int,
  id: z.string(),
  at: z.string(),
  kind: z.string(),
  actor: z.string(),
  target: z.string().nullable().optional(),
  outcome: z.string(),
  attrs: z.any().meta({ type: "object" }),
  prev_digest: z.string(),
  digest: z.string(),
});
export type AuditEvent = Omit<z.infer<typeof AuditEvent>, "attrs"> & { attrs: Record<string, unknown> };

export const AuditCheckpoint = z.object({
  seq: Int,
  digest: z.string(),
  at: z.string(),
  key_id: z.string(),
});
export type AuditCheckpoint = z.infer<typeof AuditCheckpoint>;

export const AuditVerifyRun = z.object({
  id: z.string(),
  mode: z.string(),
  started_at: z.string(),
  finished_at: z.string(),
  ok: z.boolean(),
  events: Int,
  checkpoints: Int,
  broken_seq: NullableInt.optional(),
  break_kind: z.string().nullable().optional(),
  truncated_at: NullableInt.optional(),
});
export type AuditVerifyRun = z.infer<typeof AuditVerifyRun>;

/** utoipa renders an optional struct as `oneOf: [object, null]`; zod would emit `anyOf`, so the shapes are spelled out. */
const oneOfNull = (schema: z.ZodType) =>
  z.any().meta({ oneOf: [z.toJSONSchema(schema, { io: "output" }), { type: "null" }] });

export const AuditStatus = z.object({
  head_seq: Int,
  latest_checkpoint: oneOfNull(AuditCheckpoint).optional(),
  latest_verify: oneOfNull(AuditVerifyRun).optional(),
});
export type AuditStatus = {
  head_seq: number;
  latest_checkpoint?: AuditCheckpoint;
  latest_verify?: AuditVerifyRun;
};
