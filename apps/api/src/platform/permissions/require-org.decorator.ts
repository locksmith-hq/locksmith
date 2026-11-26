import { SetMetadata } from "@nestjs/common";

export const REQUIRE_ORG = "locksmith:require-org";

/** Route (or controller) needs a principal bound to an org. Org-scoped handlers use this. */
export const RequireOrg = () => SetMetadata(REQUIRE_ORG, true);
