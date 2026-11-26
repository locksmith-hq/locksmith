// Fixture responses for every core operation, for dependents' mocks (B1 task 5.4).
// Test data only: ids, hashes, ciphertext-shaped strings and obviously fake tokens. No real
// token, key or secret value appears here.
import type {
  AgentTokenVerdict, AppendAuditEventResponse, EnrollmentSecretVerdict, GeneratedEnrollmentSecret,
  MintedToken, Problem, SignCheckpointResponse, UnwrapDekResponse, WorkloadTokenVerdict, WrapDekResponse,
} from "./index";

export const fixtureIds = {
  org: "0192f0a0-0000-7000-8000-000000000001",
  agent: "0192f0a0-0000-7000-8000-0000000000a1",
  policy: "0192f0a0-0000-7000-8000-0000000000b1",
  event: "0192f0a0-0000-7000-8000-0000000000e1",
} as const;

const hash = "0".repeat(63) + "1";
const mintedAgentToken: MintedToken = {
  token: "fixture.agent.token",
  token_type: "Bearer",
  expires_at: "2026-01-01T00:15:00Z",
  expires_in: 900,
};

export const appendAuditEvent: AppendAuditEventResponse = { id: fixtureIds.event, seq: 1, hash, deduplicated: false };
export const signAuditCheckpoint: SignCheckpointResponse = { key_id: "audit-checkpoint:1", signature: "A".repeat(86) + "==" };
export const mintAgentToken: MintedToken = mintedAgentToken;
export const verifyAgentToken: AgentTokenVerdict = {
  valid: true, agent_id: fixtureIds.agent, org_id: fixtureIds.org, expires_at: "2026-01-01T00:15:00Z",
};
export const verifyAgentTokenInvalid: AgentTokenVerdict = { valid: false, reason: "expired" };
export const mintWorkloadToken: MintedToken = mintedAgentToken;
export const verifyWorkloadToken: WorkloadTokenVerdict = {
  valid: true, org_id: fixtureIds.org, policy_id: fixtureIds.policy, agent_id: fixtureIds.agent,
};
export const verifyWorkloadTokenInvalid: WorkloadTokenVerdict = { valid: false, reason: "not_trusted" };
export const wrapDek: WrapDekResponse = { wrapped_dek: "Zml4dHVyZS13cmFwcGVkLWRlaw==", key_id: "gateway:v1", dek_handle: "fixture_dek_handle_0000000" };
export const unwrapDek: UnwrapDekResponse = { dek_handle: wrapDek.dek_handle, key_id: "gateway:v1" };
// Fake: the right shape (`lse_` + 86 base64url chars) but all zero bytes, so it names no agent.
export const generateEnrollmentSecret: GeneratedEnrollmentSecret = {
  enrollment_secret: "lse_" + "A".repeat(86),
  enrollment_hash: "$argon2id$v=19$m=19456,t=2,p=1$Zml4dHVyZS1zYWx0$Zml4dHVyZS1oYXNoLW5vdC1yZWFsLWZpeHR1cmUtb25seQ",
};
export const verifyEnrollmentSecret: EnrollmentSecretVerdict = { valid: true, org_id: fixtureIds.org, agent_id: fixtureIds.agent };
export const verifyEnrollmentSecretInvalid: EnrollmentSecretVerdict = {
  valid: false, org_id: fixtureIds.org, agent_id: fixtureIds.agent, reason: "wrong_secret",
};

export const unauthorized: Problem = { type: "about:blank", title: "Unauthorized", status: 401, detail: null };
export const badRequest: Problem = { type: "about:blank", title: "Bad Request", status: 400, detail: "invalid request" };

/** The 200 fixture of every operation, keyed by operationId. */
export const fixtures = {
  appendAuditEvent, signAuditCheckpoint, mintAgentToken, verifyAgentToken,
  mintWorkloadToken, verifyWorkloadToken, wrapDek, unwrapDek,
  generateEnrollmentSecret, verifyEnrollmentSecret,
} as const;
