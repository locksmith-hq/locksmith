// Contract types of the Locksmith agent client. No value or key material appears here: a grant
// names a secret, a relay response is already redacted by the gateway.

/** Gateway error slugs (`tests/kit/agent-contract/errors.json`; one per gateway status code). */
export const GATEWAY_SLUGS = [
  "bad_request",
  "unauthenticated",
  "denied",
  "denied_address",
  "no_grant",
  "not_found",
  "audit_failed",
  "internal",
  "grants_unavailable",
  "response_withheld",
  "secret_unavailable",
  "secret_unusable",
  "upstream_error",
  "upstream_unreachable",
  "audit_unavailable",
  "unavailable",
  "upstream_timeout",
  "invalid_request",
  "duration_too_short",
  "binding_ambiguous",
  "not_bound",
  "vend_disabled",
  "service_denied",
  "sts_error",
  "sts_unreachable",
  "redaction_failed",
  "token_unavailable",
  "upstream_unauthorized",
  "upstream_redirect",
  "too_many_credentials",
  "settings_unavailable",
] as const;
export type GatewaySlug = (typeof GATEWAY_SLUGS)[number];

/** Slugs the client itself raises. */
export type ClientSlug = "unauthorized" | "bad_config" | "foreign_origin" | "transport";

export type AgentErrorSlug = GatewaySlug | ClientSlug;

/** A fixed slug and an HTTP status (0 when no response arrived); never server or transport text. */
export class AgentError extends Error {
  readonly slug: AgentErrorSlug;
  readonly status: number;
  constructor(slug: AgentErrorSlug, status: number) {
    super(slug);
    this.name = "AgentError";
    this.slug = slug;
    this.status = status;
  }
}

export interface AgentClientOptions {
  /** Defaults to `LOCKSMITH_CONTROL_PLANE_URL`; needed only with an enrolment secret. */
  controlPlaneUrl?: string;
  /** Defaults to `LOCKSMITH_GATEWAY_URL`. */
  gatewayUrl?: string;
  /** Defaults to `LOCKSMITH_ENROLLMENT_SECRET`. Exchanged once for a token, never kept as a property. */
  enrollmentSecret?: string;
  /** A token or a function that returns a current one (workload identity, `smith login --agent`). */
  token?: string | (() => string | Promise<string>);
  fetch?: typeof fetch;
}

/** One grant of `GET /v1/grants` (a `GrantView`): ids and names, never a value. */
export interface Grant {
  secret_id: string;
  secret_name: string;
  mode: string;
  expires_at: string | null;
  allowed_origin: string;
}

export interface RelayRequest {
  secretId: string;
  version: number;
  method: string;
  url: string;
  headers?: [string, string][];
  body?: string;
  bodyBase64?: string;
}

/** The redacted upstream response of `POST /v1/relay`. */
export interface RelayResponse {
  status: number;
  headers: [string, string][];
  body?: string;
  body_base64?: string;
}

/** The only Agent MCP tools an adapter exposes. */
export const ALLOWED_TOOLS = ["list_my_keys", "relay_http_request", "explain_block"] as const;
