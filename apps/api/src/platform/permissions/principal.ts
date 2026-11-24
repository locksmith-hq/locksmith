import type { Request } from "express";

// Mirror of the Rust control plane's authorization model (services/control-plane/src/auth.rs):
// a caller is a human, an agent or a service, and is allowed only through its org binding.
// There are no per-org roles (decision B6-2), so no role matrix exists to copy.
export type PrincipalKind = "human" | "agent" | "service";

export type Principal = { kind: PrincipalKind; orgId: string | null };

export type RequestWithPrincipal = Request & { principal?: Principal };
