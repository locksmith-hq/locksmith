import { z } from "zod";
import { defineRoute, type RouteDef } from "../../openapi/build.js";

/** Decoy formats the core can mint (t5 design); the value is never part of any API response. */
const HoneyTemplate = z.enum(["aws_access_key", "github_pat", "slack_token", "generic_api_key"]);

/**
 * A honey token's metadata. There is deliberately no value field: the decoy is shown only through the
 * owner-only gateway reveal and `smith honey plant`, never through this API.
 */
const HoneyToken = z.object({
  id: z.uuid(),
  name: z.string(),
  template: HoneyTemplate,
  created_at: z.string(),
  disabled_at: z.string().nullable(),
  last_triggered_at: z.string().nullable(),
});

const HoneyTokenList = z.object({ items: z.array(HoneyToken) });

export const NewHoneyToken = z.object({ name: z.string().min(1).max(100), template: HoneyTemplate });

/** RFC 9457 problem body shared by every error response (B1 task 4.4 owns the filter). */
const Problem = z.object({ type: z.string(), title: z.string(), status: z.number().int(), detail: z.string() });

const base = "/v1/projects/{project_id}/environments/{environment_id}/honey-tokens";
const envParams = z.object({ project_id: z.uuid(), environment_id: z.uuid() });
const tokenParams = envParams.extend({ id: z.uuid() });

export const honeyTokenRoutes: RouteDef[] = [
  defineRoute({
    method: "GET",
    path: base,
    params: envParams,
    responses: { 200: HoneyTokenList, 401: Problem, 403: Problem, 404: Problem },
  }),
  defineRoute({
    method: "POST",
    path: base,
    params: envParams,
    body: NewHoneyToken,
    responses: { 201: HoneyToken, 401: Problem, 403: Problem, 404: Problem, 422: Problem },
  }),
  defineRoute({
    method: "POST",
    path: `${base}/{id}/disable`,
    params: tokenParams,
    responses: { 200: HoneyToken, 401: Problem, 403: Problem, 404: Problem },
  }),
  defineRoute({
    method: "DELETE",
    path: `${base}/{id}`,
    params: tokenParams,
    responses: { 204: null, 401: Problem, 403: Problem, 404: Problem },
  }),
];
