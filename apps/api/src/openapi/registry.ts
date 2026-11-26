import { NewOrg, Org, OrgParams } from "../orgs/orgs.schemas.js";
import { defineRoute, type RouteDef } from "./build.js";

/**
 * Every operation implemented by the Nest API, described with zod. Add a route here in the same change
 * that flips its path to `nest` in `apps/api/route-table.json`; `openapi.contract.test.ts` then holds the
 * generated operation to the frozen `services/control-plane/openapi.json`.
 */
export const routes: RouteDef[] = [
  defineRoute({
    method: "POST",
    path: "/v1/orgs",
    body: NewOrg,
    responses: { 201: Org, 400: null, 401: null, 403: null, 503: null },
  }),
  defineRoute({
    method: "GET",
    path: "/v1/orgs/current",
    responses: { 200: Org, 401: null, 403: null, 404: null, 503: null },
  }),
  defineRoute({
    method: "GET",
    path: "/v1/orgs/{org_id}",
    params: OrgParams,
    responses: { 200: Org, 401: null, 403: null, 404: null, 503: null },
  }),
];
