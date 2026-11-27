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

type Doc = { paths: Record<string, Record<string, unknown>> };

/**
 * The OpenAPI document for the routes whose path the frozen Rust document does not own (NC-1): sorted
 * keys, so the committed `openapi.nest.json` only changes when a route does.
 */
export function buildNestDocument(routes: RouteDef[], frozen: Doc): unknown {
  const own = routes.filter((r) => !(r.path in frozen.paths));
  const paths: Record<string, Record<string, unknown>> = {};
  for (const [key, op] of buildOperations(own)) {
    const [method, path] = [key.slice(0, key.indexOf(" ")), key.slice(key.indexOf(" ") + 1)];
    (paths[path] ??= {})[method.toLowerCase()] = op;
  }
  return sortKeys({
    openapi: "3.1.0",
    info: { title: "Locksmith API (Nest-only routes)", version: "0.0.0" },
    paths,
  });
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v === null || typeof v !== "object") return v;
  return Object.fromEntries(
    Object.entries(v as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, x]) => [k, sortKeys(x)]),
  );
}

export const serialiseDocument = (doc: unknown) => `${JSON.stringify(doc, null, 2)}\n`;
