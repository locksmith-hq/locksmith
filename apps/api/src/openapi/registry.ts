import { NewOrg, Org, OrgParams } from "../orgs/orgs.schemas.js";
import {
  Environment,
  EnvironmentParams,
  NewEnvironment,
  NewProject,
  Paged,
  PageQuerySchema,
  Patch,
  Project,
  ProjectParams,
} from "../projects/projects.schemas.js";
import {
  NewWorkloadIdentity,
  WorkloadIdentityParams,
  WorkloadIdentitySchema,
} from "../workload-identities/workload-identities.schemas.js";
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

const E = (...c: number[]) => Object.fromEntries(c.map((s) => [s, null]));
const envPath = "/v1/projects/{project_id}/environments";
const projectRoutes: RouteDef[] = [
  defineRoute({
    method: "GET",
    path: "/v1/projects",
    query: PageQuerySchema,
    responses: { 200: Paged(Project), ...E(400, 401, 403, 404, 503) },
  }),
  defineRoute({
    method: "POST",
    path: "/v1/projects",
    body: NewProject,
    responses: { 201: Project, ...E(400, 401, 403, 409, 503) },
  }),
  defineRoute({
    method: "GET",
    path: "/v1/projects/{project_id}",
    params: ProjectParams,
    responses: { 200: Project, ...E(401, 403, 404, 503) },
  }),
  defineRoute({
    method: "PATCH",
    path: "/v1/projects/{project_id}",
    params: ProjectParams,
    body: Patch,
    responses: { 200: Project, ...E(400, 401, 403, 404, 409, 503) },
  }),
  defineRoute({
    method: "DELETE",
    path: "/v1/projects/{project_id}",
    params: ProjectParams,
    responses: { 204: null, ...E(401, 403, 404, 409, 503) },
  }),
  defineRoute({
    method: "GET",
    path: envPath,
    params: ProjectParams,
    query: PageQuerySchema,
    responses: { 200: Paged(Environment), ...E(400, 401, 403, 404, 503) },
  }),
  defineRoute({
    method: "POST",
    path: envPath,
    params: ProjectParams,
    body: NewEnvironment,
    responses: { 201: Environment, ...E(400, 401, 403, 404, 409, 503) },
  }),
  defineRoute({
    method: "GET",
    path: `${envPath}/{environment_id}`,
    params: EnvironmentParams,
    responses: { 200: Environment, ...E(401, 403, 404, 503) },
  }),
  defineRoute({
    method: "PATCH",
    path: `${envPath}/{environment_id}`,
    params: EnvironmentParams,
    body: Patch,
    responses: { 200: Environment, ...E(400, 401, 403, 404, 409, 503) },
  }),
  defineRoute({
    method: "DELETE",
    path: `${envPath}/{environment_id}`,
    params: EnvironmentParams,
    responses: { 204: null, ...E(401, 403, 404, 409, 503) },
  }),
];
routes.push(...projectRoutes);

/**
 * Workload identity routes (task 6.5 slice). NOT yet in `routes`: the route table still marks them `rust` until
 * a contract diff against the Rust service has been run. Their shape is held to the frozen openapi.json by
 * `workload-identities.contract.test.ts`. On the flip, push them onto `routes` and mark the four paths `nest`.
 */
export const workloadIdentityRoutes: RouteDef[] = [
  defineRoute({
    method: "GET",
    path: "/v1/workload-identities",
    query: PageQuerySchema,
    responses: { 200: Paged(WorkloadIdentitySchema), ...E(400, 401, 403, 404, 503) },
  }),
  defineRoute({
    method: "POST",
    path: "/v1/workload-identities",
    body: NewWorkloadIdentity,
    responses: { 201: WorkloadIdentitySchema, ...E(400, 401, 403, 409, 422, 503) },
  }),
  defineRoute({
    method: "GET",
    path: "/v1/workload-identities/{id}",
    params: WorkloadIdentityParams,
    responses: { 200: WorkloadIdentitySchema, ...E(401, 403, 404, 503) },
  }),
  defineRoute({
    method: "DELETE",
    path: "/v1/workload-identities/{id}",
    params: WorkloadIdentityParams,
    responses: { 204: null, ...E(401, 403, 404, 409, 503) },
  }),
];
