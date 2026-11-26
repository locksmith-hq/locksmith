import { honeyTokenRoutes } from "../domains/honey-tokens/honey-token.schemas.js";
import { notificationRoutes } from "../domains/notifications/notification.schemas.js";
import type { RouteDef } from "./build.js";

/**
 * Every operation implemented by the Nest API, described with zod. Add a route here in the same change
 * that flips its path to `nest` in `apps/api/route-table.json`; `openapi.contract.test.ts` then holds the
 * generated operation to the frozen `services/control-plane/openapi.json`.
 */
export const routes: RouteDef[] = [...notificationRoutes, ...honeyTokenRoutes];
