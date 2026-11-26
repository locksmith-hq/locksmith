// Typed client for the internal Rust core service (OC-9 G1). Types are generated from
// services/core/openapi.json (`npm run gen`); a drift test fails when they disagree.
// Nothing here logs or persists a request or response body: tokens only live in the objects
// handed to the caller, and the API carries no plaintext vault secret or key bytes by design
// (the agent enrollment secret from generateEnrollmentSecret is returned once, for display).
import createClient, { type Client } from "openapi-fetch";
import type { components, paths } from "./schema";

export type { components, paths };
type S = components["schemas"];

export type AppendAuditEventRequest = S["AppendAuditEventRequest"];
export type AppendAuditEventResponse = S["AppendAuditEventResponse"];
export type SignCheckpointRequest = S["SignCheckpointRequest"];
export type SignCheckpointResponse = S["SignCheckpointResponse"];
export type MintAgentTokenRequest = S["MintAgentTokenRequest"];
export type MintWorkloadTokenRequest = S["MintWorkloadTokenRequest"];
export type MintedToken = S["MintedToken"];
export type VerifyTokenRequest = S["VerifyTokenRequest"];
export type VerifyWorkloadTokenRequest = S["VerifyWorkloadTokenRequest"];
export type AgentTokenVerdict = S["AgentTokenVerdict"];
export type WorkloadTokenVerdict = S["WorkloadTokenVerdict"];
export type WrapDekRequest = S["WrapDekRequest"];
export type WrapDekResponse = S["WrapDekResponse"];
export type UnwrapDekRequest = S["UnwrapDekRequest"];
export type UnwrapDekResponse = S["UnwrapDekResponse"];
export type GenerateEnrollmentSecretRequest = S["GenerateEnrollmentSecretRequest"];
export type GeneratedEnrollmentSecret = S["GeneratedEnrollmentSecret"];
export type VerifyEnrollmentSecretRequest = S["VerifyEnrollmentSecretRequest"];
export type EnrollmentSecretVerdict = S["EnrollmentSecretVerdict"];
export type Problem = S["Problem"];

export type CoreRawClient = Client<paths>;

export interface CoreClientOptions {
  baseUrl: string;
  /** Service token, or a function read on every request so a rotated token is used. */
  token: string | (() => string | undefined);
  fetch?: typeof fetch;
}

/** A non-2xx answer from the core. Carries the problem fields only, never a request body. */
export class CoreError extends Error {
  constructor(
    public readonly status: number,
    public readonly problem: Partial<Problem> = {},
  ) {
    super(problem.detail ?? problem.title ?? `core request failed with status ${status}`);
    this.name = "CoreError";
  }
}

function unwrap<T>(r: { data?: T; error?: unknown; response: Response }): T {
  if (r.error !== undefined || r.data === undefined) {
    const p = r.error && typeof r.error === "object" ? (r.error as Partial<Problem>) : {};
    throw new CoreError(r.response.status, p);
  }
  return r.data;
}

export function createCoreClient(opts: CoreClientOptions) {
  const raw: CoreRawClient = createClient<paths>({ baseUrl: opts.baseUrl, ...(opts.fetch ? { fetch: opts.fetch } : {}) });
  raw.use({
    onRequest({ request }) {
      const token = typeof opts.token === "function" ? opts.token() : opts.token;
      if (token) request.headers.set("authorization", `Bearer ${token}`);
      return request;
    },
  });
  return {
    raw,
    appendAuditEvent: async (body: AppendAuditEventRequest) => unwrap(await raw.POST("/v1/audit/events", { body })),
    signAuditCheckpoint: async (body: SignCheckpointRequest) => unwrap(await raw.POST("/v1/audit/checkpoints", { body })),
    mintAgentToken: async (body: MintAgentTokenRequest) => unwrap(await raw.POST("/v1/agent-tokens/mint", { body })),
    verifyAgentToken: async (body: VerifyTokenRequest) => unwrap(await raw.POST("/v1/agent-tokens/verify", { body })),
    mintWorkloadToken: async (body: MintWorkloadTokenRequest) => unwrap(await raw.POST("/v1/workload-tokens/mint", { body })),
    verifyWorkloadToken: async (body: VerifyWorkloadTokenRequest) => unwrap(await raw.POST("/v1/workload-tokens/verify", { body })),
    wrapDek: async (body: WrapDekRequest) => unwrap(await raw.POST("/v1/deks/wrap", { body })),
    unwrapDek: async (body: UnwrapDekRequest) => unwrap(await raw.POST("/v1/deks/unwrap", { body })),
    /** The returned `enrollment_secret` is shown to the human once; store only `enrollment_hash`. */
    generateEnrollmentSecret: async (body: GenerateEnrollmentSecretRequest) =>
      unwrap(await raw.POST("/v1/enrollment-secrets/generate", { body })),
    /** `enrollment_hash: null` for an unknown agent (the core then runs the dummy-hash path). */
    verifyEnrollmentSecret: async (body: VerifyEnrollmentSecretRequest) =>
      unwrap(await raw.POST("/v1/enrollment-secrets/verify", { body })),
  };
}
export type CoreClient = ReturnType<typeof createCoreClient>;
