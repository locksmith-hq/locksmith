import { ApiError, type Client } from "@locksmith/control-plane-client";

/** Wraps every client method: a `401` calls `onUnauthorized` (sign out) and the error still reaches the caller. */
export function withUnauthorizedHandler(client: Client, onUnauthorized: () => void): Client {
  const wrapped = {} as Record<string, unknown>;
  for (const key of Object.keys(client) as (keyof Client)[]) {
    const fn = client[key] as (...a: unknown[]) => Promise<unknown>;
    wrapped[key] = async (...args: unknown[]) => {
      try {
        return await fn(...args);
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) onUnauthorized();
        throw e;
      }
    };
  }
  return wrapped as unknown as Client;
}
