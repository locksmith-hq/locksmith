import { z } from "zod";

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

/** One API operation, described once with zod schemas; the OpenAPI operation is generated from it. */
export interface RouteDef {
  method: Method;
  /** OpenAPI path template, e.g. `/v1/orgs/{org_id}`. */
  path: string;
  params?: z.ZodObject;
  query?: z.ZodObject;
  body?: z.ZodType;
  /** Success and error responses by status code. A schema of `null` means no body. */
  responses: Record<number, z.ZodType | null>;
}

export const defineRoute = (r: RouteDef): RouteDef => r;

export interface Operation {
  parameters: { name: string; in: "path" | "query"; required: boolean; schema: unknown }[];
  requestBody?: unknown;
  responses: Record<string, unknown>;
}

const json = (s: z.ZodType) => z.toJSONSchema(s, { target: "draft-2020-12", io: "output" });

function fields(obj: z.ZodObject, where: "path" | "query"): Operation["parameters"] {
  const schema = z.toJSONSchema(obj, { target: "draft-2020-12", io: "input" }) as {
    properties?: Record<string, unknown>;
    required?: string[];
  };
  return Object.entries(schema.properties ?? {}).map(([name, s]) => ({
    name,
    in: where,
    required: where === "path" || (schema.required ?? []).includes(name),
    schema: s,
  }));
}

function buildOperation(r: RouteDef): Operation {
  return {
    parameters: [...(r.params ? fields(r.params, "path") : []), ...(r.query ? fields(r.query, "query") : [])],
    ...(r.body
      ? {
          requestBody: {
            content: {
              "application/json": { schema: z.toJSONSchema(r.body, { target: "draft-2020-12", io: "input" }) },
            },
          },
        }
      : {}),
    responses: Object.fromEntries(
      Object.entries(r.responses).map(([status, s]) => [
        status,
        s ? { content: { "application/json": { schema: json(s) } } } : {},
      ]),
    ),
  };
}

export const routeKey = (method: string, path: string) => `${method.toUpperCase()} ${path}`;

export function buildOperations(routes: RouteDef[]): Map<string, Operation> {
  const out = new Map<string, Operation>();
  for (const r of routes) {
    const key = routeKey(r.method, r.path);
    if (out.has(key)) throw new Error(`duplicate route ${key}`);
    out.set(key, buildOperation(r));
  }
  return out;
}
