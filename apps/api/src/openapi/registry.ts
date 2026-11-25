import { defineRoute, type RouteDef } from "./build.js";

// Error responses are `application/problem+json` in the frozen document, which the comparison
// does not read, so they are declared without a body here (as `204` is).
const authRoute = (path: string) =>
  defineRoute({ method: "POST", path, responses: { 204: null, 401: null, 403: null, 404: null, 503: null } });

/**
 * Every operation implemented by the Nest API, described with zod. Add a route here in the same change
 * that flips its path to `nest` in `apps/api/route-table.json`; `openapi.contract.test.ts` then holds the
 * generated operation to the frozen `services/control-plane/openapi.json`.
 */
export const routes: RouteDef[] = [authRoute("/v1/auth/sign-in"), authRoute("/v1/auth/sign-out")];
