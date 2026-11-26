import { ProblemException } from "../../platform/problem/problem.js";

export type HoneyTemplate = "aws_access_key" | "github_pat" | "slack_token" | "generic_api_key";

/** Port for the Rust core's mint endpoint. The value is generated and sealed there; it never reaches the API. */
export abstract class HoneyMinter {
  /** Seals a fresh decoy as version 1 of `secretId`. Throws a {@link ProblemException} on refusal. */
  abstract mint(orgId: string, secretId: string, template: HoneyTemplate): Promise<void>;
}

/** Injection token for `HoneyMinter | null` (null when the core is not configured). */
export const HONEY_MINTER = Symbol("HONEY_MINTER");

const TIMEOUT_MS = 10_000;

/**
 * Calls `POST /internal/v1/honey/mint` (service token plus `X-Locksmith-Org`). The token is sent only in
 * the Authorization header; neither it nor any body is logged or put in an error.
 */
export class CoreHoneyMinter extends HoneyMinter {
  private readonly url: string;

  constructor(
    baseUrl: string,
    private readonly token: string,
  ) {
    super();
    this.url = `${baseUrl.replace(/\/+$/, "")}/internal/v1/honey/mint`;
  }

  async mint(orgId: string, secretId: string, template: HoneyTemplate): Promise<void> {
    let res: Response;
    try {
      res = await fetch(this.url, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${this.token}`, "x-locksmith-org": orgId },
        body: JSON.stringify({ template, secret_id: secretId }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new ProblemException("unavailable");
    }
    // Drain without reading into memory or logs: the response is the version only, which the API ignores.
    await res.body?.cancel().catch(() => {});
    if (res.ok) return;
    if (res.status === 404) throw new ProblemException("not-found");
    if (res.status === 409) throw new ProblemException("conflict");
    throw new ProblemException("unavailable");
  }
}
