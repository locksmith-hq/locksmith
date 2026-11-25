import { ServiceUnavailableException } from "@nestjs/common";

/** Injection token for the audit sink. */
export const AUDIT_SINK = Symbol("AUDIT_SINK");

/** The audit kinds the sign-in flow emits (same codes as the Rust `ls-audit` kinds). */
type AuthAuditKind = "auth.sign_in" | "auth.sign_out" | "org.personal_created";

/**
 * One audit event. Holds ids and the issuer host only, never a token or an email (Rust
 * `audit::auth`): `actor` is the user, `org` the target.
 */
export interface AuthAuditEvent {
  kind: AuthAuditKind;
  userId: string;
  orgId: string;
  issuerHost?: string | undefined;
  outcome: "ok";
}

/**
 * Appends to an org's audit chain. The chain is hashed and signed in Rust, so the real sink is
 * the core client (change task 5.4); the API never computes a chain hash itself.
 */
export interface AuditSink {
  append(event: AuthAuditEvent): Promise<void>;
}

/**
 * Default sink until the core client lands: fails closed. An audit append that cannot be made
 * refuses the request (never silently skipped), so a sign-in cannot succeed unrecorded.
 */
export class FailClosedAuditSink implements AuditSink {
  async append(): Promise<void> {
    throw new ServiceUnavailableException();
  }
}

/** The host of an issuer URL (public configuration), or undefined when it does not parse. */
export function issuerHost(issuer: string): string | undefined {
  try {
    return new URL(issuer).host || undefined;
  } catch {
    return undefined;
  }
}
