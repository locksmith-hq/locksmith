import type { components } from "@locksmith/sdk";
import {
  AgentError,
  GATEWAY_SLUGS,
  type AgentClientOptions,
  type AgentErrorSlug,
  type Grant,
  type RelayRequest,
  type RelayResponse,
} from "./types";

type AgentToken = components["schemas"]["AgentToken"];
type AgentTokenRequest = components["schemas"]["AgentTokenRequest"];

const RENEW_BEFORE_MS = 60_000;

export interface AgentClient {
  listGrants(): Promise<Grant[]>;
  relay(req: RelayRequest): Promise<RelayResponse>;
  readonly mcpUrl: string;
  /** A fetch that adds the token only for requests to the gateway origin. */
  authorizedFetch: typeof fetch;
  /**
   * The current gateway token (renewed 60 s before expiry; `renew` forces a fresh one), for frameworks
   * that take an auth hook instead of a fetch. Call it per request; never store the result.
   */
  bearerToken(renew?: boolean): Promise<string>;
  close(): void;
}

function envVar(name: string): string | undefined {
  const v = process.env[name];
  return v ? v : undefined;
}

function slugOf(status: number, body: unknown): AgentErrorSlug {
  const s = (body as { error?: unknown } | null)?.error;
  if ((GATEWAY_SLUGS as readonly unknown[]).includes(s)) return s as AgentErrorSlug;
  return status === 401 ? "unauthorized" : "transport";
}

/** Creates the client. Secrets live in closures only: no property holds the enrolment secret or token. */
export function createAgentClient(opts: AgentClientOptions = {}): AgentClient {
  const doFetch = opts.fetch ?? globalThis.fetch;
  const gatewayUrl = (opts.gatewayUrl ?? envVar("LOCKSMITH_GATEWAY_URL") ?? "").replace(/\/+$/, "");
  if (!gatewayUrl) throw new AgentError("bad_config", 0);
  let gatewayOrigin: string;
  try {
    gatewayOrigin = new URL(gatewayUrl).origin;
  } catch {
    throw new AgentError("bad_config", 0);
  }
  const controlPlane = (opts.controlPlaneUrl ?? envVar("LOCKSMITH_CONTROL_PLANE_URL") ?? gatewayUrl).replace(
    /\/+$/,
    "",
  );
  const enrollment = opts.enrollmentSecret ?? envVar("LOCKSMITH_ENROLLMENT_SECRET");
  const tokenSource = opts.token;
  if (!tokenSource && !enrollment) throw new AgentError("bad_config", 0);

  let token: string | undefined;
  let expiresAt = 0;
  let inflight: Promise<string> | undefined;

  async function mint(): Promise<string> {
    if (typeof tokenSource === "string") return tokenSource;
    if (typeof tokenSource === "function") {
      try {
        return await tokenSource();
      } catch {
        throw new AgentError("unauthorized", 0);
      }
    }
    let res: Response;
    try {
      res = await doFetch(`${controlPlane}/v1/agent-tokens`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ enrollment_secret: enrollment ?? "" } satisfies AgentTokenRequest),
      });
    } catch {
      throw new AgentError("transport", 0);
    }
    const body = await res.json().catch(() => null);
    if (!res.ok) throw new AgentError(slugOf(res.status, body), res.status);
    const t = body as Partial<AgentToken> | null;
    if (typeof t?.access_token !== "string") throw new AgentError("transport", res.status);
    token = t.access_token;
    const exp = Date.parse(t.expires_at ?? "");
    expiresAt = Number.isNaN(exp) ? Date.now() + 5 * 60_000 : exp;
    return token;
  }

  function currentToken(force = false): Promise<string> {
    if (!force && token && Date.now() < expiresAt - RENEW_BEFORE_MS) return Promise.resolve(token);
    inflight ??= mint().finally(() => {
      inflight = undefined;
    });
    return inflight;
  }

  async function authed(url: string, init: RequestInit = {}): Promise<Response> {
    const target = new URL(url, gatewayUrl + "/");
    if (target.origin !== gatewayOrigin) throw new AgentError("foreign_origin", 0);
    for (let attempt = 0; ; attempt++) {
      const t = await currentToken(attempt > 0);
      const headers = new Headers(init.headers);
      headers.set("authorization", `Bearer ${t}`);
      let res: Response;
      try {
        res = await doFetch(target.href, { ...init, headers });
      } catch {
        throw new AgentError("transport", 0);
      }
      if (res.status === 401 && attempt === 0 && typeof tokenSource !== "string") {
        token = undefined;
        continue;
      }
      return res;
    }
  }

  async function json<T>(res: Response): Promise<T> {
    const body = await res.json().catch(() => null);
    if (!res.ok) throw new AgentError(slugOf(res.status, body), res.status);
    return body as T;
  }

  const authorizedFetch: typeof fetch = (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    const merged: RequestInit =
      input instanceof Request
        ? ({ method: input.method, headers: input.headers, body: input.body, duplex: "half", ...init } as RequestInit)
        : (init ?? {});
    return authed(url, merged);
  };

  return {
    mcpUrl: `${gatewayUrl}/mcp`,
    authorizedFetch,
    bearerToken: (renew = false) => currentToken(renew),
    async listGrants() {
      const body = await json<{ grants: Grant[] }>(await authed("/v1/grants"));
      return body.grants;
    },
    async relay(req) {
      const wire = {
        secret_id: req.secretId,
        version: req.version,
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: req.body,
        body_base64: req.bodyBase64,
      };
      return json<RelayResponse>(
        await authed("/v1/relay", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(wire),
        }),
      );
    },
    close() {
      token = undefined;
      expiresAt = 0;
    },
  };
}
