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
  /** An admin event (agents, grants): the same ledger and the same fail-closed rule. */
  appendAdmin(event: AdminAuditEvent): Promise<void>;
}

/**
 * An admin audit event as the core takes it: allow-listed kind, ids, integers and short codes
 * only (Rust `audit::agent_created` and friends). Never a name, description or secret.
 */
export interface AdminAuditEvent {
  kind:
    | "agent.created"
    | "agent.rotated"
    | "agent.deleted"
    | "grant.created"
    | "grant.revoked"
    | "workload_identity.created"
    | "workload_identity.deleted";
  orgId: string;
  /** Until the console session lands the actor is the dev-auth service, as in Rust. */
  actor: { type: "service"; code: string } | { type: "user"; id: string };
  target: { type: "agent" | "grant" | "workload"; id: string };
  attrs: Record<string, string | number | boolean>;
}

/** The actor of admin requests while the org binding is the dev-only header (Rust `DEV_AUTH_ACTOR`). */
export const DEV_AUTH_ACTOR = { type: "service", code: "dev_auth" } as const;

/**
 * Default sink until the core client lands: fails closed. An audit append that cannot be made
 * refuses the request (never silently skipped), so a sign-in cannot succeed unrecorded.
 */
export class FailClosedAuditSink implements AuditSink {
  async append(): Promise<void> {
    throw new ServiceUnavailableException();
  }

  async appendAdmin(): Promise<void> {
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
