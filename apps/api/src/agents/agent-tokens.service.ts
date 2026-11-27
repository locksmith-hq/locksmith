import { Inject, Injectable, ServiceUnavailableException } from "@nestjs/common";
import type { CoreClient } from "@locksmith/core-client";
import { CORE_CLIENT } from "../core/core.tokens.js";
import { ProblemException } from "../platform/problem.js";
import { TenantService } from "../tenant/tenant.service.js";

const PREFIX = "lse_";
const RAW_BYTES = 64;

/** The routing ids of a well-formed enrollment secret (`org_id(16) || agent_id(16) || random(32)`); they are plain bytes, not secret. */
export function enrollmentIds(text: string): { orgId: string; agentId: string } | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith(PREFIX)) return null;
  const body = trimmed.slice(PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(body)) return null;
  const raw = Buffer.from(body, "base64url");
  if (raw.length !== RAW_BYTES) return null;
  const uuid = (b: Buffer) => {
    const h = b.toString("hex");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
  return { orgId: uuid(raw.subarray(0, 16)), agentId: uuid(raw.subarray(16, 32)) };
}

export interface AgentToken {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  expires_at: string;
}

/**
 * `POST /v1/agent-tokens` (Rust `api/agents.rs::mint_token`): the enrollment secret is the credential, so
 * the org comes from the secret and every bad, unknown or replaced secret is the same 401. The Argon2id
 * check and the signing happen in the core; this service never signs and never keeps the secret.
 */
@Injectable()
export class AgentTokensService {
  constructor(
    @Inject(TenantService) private readonly tenant: TenantService,
    @Inject(CORE_CLIENT) private readonly core: CoreClient,
  ) {}

  async mint(enrollmentSecret: string): Promise<AgentToken> {
    const ids = enrollmentIds(enrollmentSecret);
    if (!ids) throw new ProblemException("unauthenticated");
    const hash = await this.tenant.run(ids.orgId, async (tx) => {
      const row = await tx
        .selectFrom("agents")
        .select("enrollment_hash")
        .where("id", "=", ids.agentId)
        .executeTakeFirst();
      return row?.enrollment_hash ?? null;
    });
    try {
      // An unknown agent sends a null hash: the core spends the same Argon2id work as for a wrong secret.
      const verdict = await this.core.verifyEnrollmentSecret({
        enrollment_secret: enrollmentSecret,
        enrollment_hash: hash,
      });
      if (!verdict.valid) throw new ProblemException("unauthenticated");
      const t = await this.core.mintAgentToken({ org_id: ids.orgId, agent_id: ids.agentId });
      return { access_token: t.token, token_type: "Bearer", expires_in: t.expires_in, expires_at: t.expires_at };
    } catch (e) {
      if (e instanceof ProblemException) throw e;
      throw new ServiceUnavailableException();
    }
  }
}
