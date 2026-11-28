// OAuth connections: wire types mirrored from `crates/ls-oauth` and a client for the gateway's
// `/v1/oauth/*` endpoints. No type or method here carries a provider token: the gateway holds them.

/** Closed set of error slugs the gateway answers with (`ErrorSlug` in `ls-oauth`). */
export const OAUTH_ERROR_SLUGS = [
  "unknown_provider",
  "return_to_not_allowed",
  "flow_expired",
  "flow_not_found",
  "wrong_person",
  "provider_error",
  "exchange_failed",
  "connection_needs_reconnect",
  "no_grant",
  "host_not_allowed",
] as const;
export type OAuthErrorSlug = (typeof OAUTH_ERROR_SLUGS)[number];

export interface OAuthErrorBody {
  error: OAuthErrorSlug;
}

/** A provider the gateway has enabled. */
export interface ProviderSummary {
  provider: string;
  name: string;
  scopes: string[];
  revoke_supported: boolean;
}

export type ConnectionStatus = "connected" | "refresh_failed" | "revoked";

/** One person's connection to a provider account. Timestamps are RFC 3339 strings. */
export interface ConnectionSummary {
  id: string;
  provider: string;
  account_login: string;
  account_id: string;
  scopes: string[];
  status: ConnectionStatus;
  connected_at: string;
  expires_at?: string;
  last_refreshed_at?: string;
  last_error_code?: string;
  /** Only on a disconnect answer. */
  revoked_at_provider?: boolean;
}

export interface ConnectionGrant {
  id: string;
  agent_id: string;
  connection_id: string;
  expires_at?: string;
  created_by: string;
  created_at: string;
}

/** A connection grant as listed by `GET /v1/grants`. */
export interface ConnectionGrantListing {
  connection_id: string;
  provider: string;
  person_name: string;
  expires_at?: string;
}

export interface ConnectRequest {
  provider: string;
  return_to: string;
}

export interface ConnectResponse {
  flow_id: string;
  authorize_url: string;
}

/** The `result` query parameter of the callback redirect to `return_to`. */
export type CallbackResult = "pending_confirm" | OAuthErrorSlug;

export const isOAuthErrorSlug = (v: unknown): v is OAuthErrorSlug =>
  typeof v === "string" && (OAUTH_ERROR_SLUGS as readonly string[]).includes(v);

/** Parses the redirect's query (`flow` and `result`); anything unexpected is `null`. */
export function parseCallback(search: string): { flow: string; result: CallbackResult } | null {
  const p = new URLSearchParams(search);
  const flow = p.get("flow");
  const result = p.get("result");
  if (!flow || !result) return null;
  return result === "pending_confirm" || isOAuthErrorSlug(result) ? { flow, result } : null;
}

export class OAuthError extends Error {
  constructor(
    readonly status: number,
    readonly slug: OAuthErrorSlug | null,
  ) {
    super(slug ?? `oauth request failed (${status})`);
    this.name = "OAuthError";
  }
}

export interface GatewayClient {
  connect(body: ConnectRequest): Promise<ConnectResponse>;
  confirm(flowId: string): Promise<ConnectionSummary>;
  disconnect(connectionId: string): Promise<ConnectionSummary>;
}

/** Gateway client on its own base URL; `getToken` is read per request. Errors carry only the slug. */
export function createGatewayClient(
  baseUrl: string,
  getToken?: () => string | undefined,
  fetchFn: typeof fetch = (...a) => globalThis.fetch(...a),
): GatewayClient {
  const base = baseUrl.replace(/\/+$/, "");
  async function post<T>(path: string, body?: unknown): Promise<T> {
    const token = getToken?.();
    const r = await fetchFn(`${base}${path}`, {
      method: "POST",
      headers: {
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });
    if (!r.ok) {
      let slug: OAuthErrorSlug | null = null;
      try {
        const e = (await r.json()) as Partial<OAuthErrorBody>;
        if (isOAuthErrorSlug(e.error)) slug = e.error;
      } catch {
        // not JSON: status only
      }
      throw new OAuthError(r.status, slug);
    }
    return (await r.json()) as T;
  }
  const id = encodeURIComponent;
  return {
    connect: (body) => post("/v1/oauth/connect", body),
    confirm: (flowId) => post(`/v1/oauth/flows/${id(flowId)}/confirm`),
    disconnect: (connectionId) => post(`/v1/oauth/connections/${id(connectionId)}/disconnect`),
  };
}
