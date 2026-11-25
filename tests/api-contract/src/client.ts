import { Normaliser, type Json } from "./normalise.ts";

export const DEV_ORG_HEADER = "x-locksmith-dev-org";

export interface Exchange {
  name: string;
  method: string;
  path: string;
  status: number;
  headers: Record<string, string>;
  body: Json | null;
}

export interface Call {
  method: string;
  /** Request path with `{param}` already substituted. */
  path: string;
  headers?: Record<string, string>;
  body?: Json;
}

function baseUrl(override?: string): string {
  const url = override ?? process.env.API_CONTRACT_URL;
  if (!url) throw new Error("API_CONTRACT_URL is not set (for example http://127.0.0.1:8080)");
  return url.replace(/\/+$/, "");
}

/** Sends one request and returns the raw status, headers and parsed body. */
export async function send(
  call: Call,
  base?: string,
): Promise<{ status: number; headers: Headers; body: Json | null }> {
  const res = await fetch(baseUrl(base) + call.path, {
    method: call.method,
    headers: {
      ...(call.body === undefined ? {} : { "content-type": "application/json" }),
      ...call.headers,
    },
    body: call.body === undefined ? undefined : JSON.stringify(call.body),
    redirect: "manual",
  });
  const text = await res.text();
  let body: Json | null = null;
  if (text !== "") {
    try {
      body = JSON.parse(text) as Json;
    } catch {
      body = text;
    }
  }
  return { status: res.status, headers: res.headers, body };
}

/** Records every exchange of a run into one normalised transcript. */
export class Recorder {
  readonly norm = new Normaliser();
  readonly exchanges: Exchange[] = [];

  async call(name: string, call: Call) {
    const res = await send(call);
    this.exchanges.push({
      name,
      method: call.method,
      path: this.norm.text(call.path),
      status: res.status,
      headers: this.norm.headers(res.headers),
      body: res.body === null ? null : this.norm.json(res.body),
    });
    return res;
  }
}

/** Headers for `/internal/v1/*`: the gateway's service token and the org it acts for. */
export function internalAuth(orgId: string): Record<string, string> {
  const token = process.env.LOCKSMITH_GATEWAY_SERVICE_TOKEN;
  if (!token) throw new Error("LOCKSMITH_GATEWAY_SERVICE_TOKEN is not set; run through scripts/api-contract.sh");
  return { authorization: `Bearer ${token}`, "x-locksmith-org": orgId };
}
