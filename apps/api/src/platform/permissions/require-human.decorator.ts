import { SetMetadata } from "@nestjs/common";

export const REQUIRE_HUMAN = "locksmith:require-human";

/**
 * Route (or controller) is for a signed-in person only: agents and services are refused with 403.
 * There are no per-org roles (decision B6-2), so "owner-only" means a human principal bound to the org.
 */
export const RequireHuman = () => SetMetadata(REQUIRE_HUMAN, true);
