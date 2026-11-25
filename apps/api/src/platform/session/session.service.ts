import { Inject, Injectable, Logger } from "@nestjs/common";
import { ProblemException } from "../problem/problem.js";
import type { HumanIdentity } from "../auth/token-verifier.js";
import { AUDIT_SINK, AuditSinkError, type AuditSink } from "./audit-sink.js";
import { UsersService } from "./users.service.js";

/** Lowercased host of an issuer URL (the only identity attribute the ledger records), if it has one. */
export function issuerHost(issuer: string): string | undefined {
  try {
    return new URL(issuer).hostname.toLowerCase() || undefined;
  } catch {
    return undefined;
  }
}

/** Sign-in and sign-out markers for the audit ledger (port of services/control-plane/src/api/session.rs). */
@Injectable()
export class SessionService {
  private readonly log = new Logger("session");

  constructor(
    @Inject(UsersService) private readonly users: UsersService,
    @Inject(AUDIT_SINK) private readonly sink: AuditSink | null,
  ) {}

  signIn(identity: HumanIdentity): Promise<void> {
    return this.record(identity, "auth.sign_in");
  }

  signOut(identity: HumanIdentity): Promise<void> {
    return this.record(identity, "auth.sign_out");
  }

  private async record(identity: HumanIdentity, kind: "auth.sign_in" | "auth.sign_out"): Promise<void> {
    // Never succeed unaudited: without a core there is nowhere to write the event.
    const sink = this.sink;
    if (!sink) throw new ProblemException("unavailable");
    const user = await this.users.resolve(identity);
    const host = issuerHost(identity.issuer);
    const event = (k: string) => ({ orgId: user.orgId, kind: k, actorUserId: user.userId, issuerHost: host });
    try {
      // Known gap: Rust appends org.personal_created in the user transaction. Here the user commits
      // first and the event follows, so a failure in between leaves a personal org with no event
      // (the client's retry then sees a known user and does not re-emit it).
      if (user.orgCreated) await sink.append(event("org.personal_created"));
      await sink.append(event(kind));
    } catch (e) {
      this.log.warn({ event: "audit.append_failed", reason: e instanceof AuditSinkError ? e.reason : "unknown" });
      throw new ProblemException("unavailable");
    }
  }
}
