/**
 * Port for appending to the org's hash-chained audit ledger. The ledger is Rust only (never
 * reimplement hashing here); the API hands events to the core over HTTP.
 */
export type AuditEventInput = {
  orgId: string;
  /** Ledger event kind, e.g. `auth.sign_in`. */
  kind: string;
  /** The human user the event is about. */
  actorUserId: string;
  /** Lowercased host of the OIDC issuer; absent when the issuer has no usable host. */
  issuerHost?: string | undefined;
  idempotencyKey?: string | undefined;
};

/** Static reason only: never a response body, token or URL. */
export class AuditSinkError extends Error {
  constructor(readonly reason: "unreachable" | "rejected") {
    super(`audit sink ${reason}`);
    this.name = "AuditSinkError";
  }
}

export abstract class AuditSink {
  /** Resolves once the event is durably appended; throws {@link AuditSinkError} otherwise. */
  abstract append(event: AuditEventInput): Promise<void>;
}

/** Injection token for `AuditSink | null` (null when the core is not configured). */
export const AUDIT_SINK = Symbol("AUDIT_SINK");
