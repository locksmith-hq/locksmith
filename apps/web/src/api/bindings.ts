import type { BindingView } from "@locksmith/api-types";
import { bindingFixtures } from "@locksmith/api-types/fixtures";

/**
 * Read-only binding list (D2-1, D2-2). The source of truth is the gateway bindings file; the
 * endpoint that serves it does not exist yet, so the console uses `mockBindingsClient` until it
 * does (openspec/changes/d2-aws-sts/design.md, "Bindings list"). Never carries a secret.
 */
export interface BindingsClient {
  listBindings(): Promise<BindingView[]>;
}

export const mockBindingsClient: BindingsClient = { listBindings: async () => bindingFixtures };
