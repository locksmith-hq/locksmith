import { type Operation, buildOperations, routeKey, type RouteDef } from "./build.js";

type Json = unknown;
type Frozen = { paths: Record<string, Record<string, Json>>; components?: { schemas?: Record<string, Json> } };
export type RouteTable = { routes: { method: string; path: string; owner: string }[] };

/** Inline `#/components/schemas/*` references and drop annotation-only keys, so documents compare by shape. */
function normalise(v: Json, doc: Frozen, seen: string[] = []): Json {
  if (Array.isArray(v)) return v.map((x) => normalise(x, doc, seen));
  if (v === null || typeof v !== "object") return v;
  const o = v as Record<string, Json>;
  if (typeof o.$ref === "string") {
    const name = o.$ref.replace("#/components/schemas/", "");
    if (seen.includes(name)) return { $recursive: name };
    return normalise(doc.components?.schemas?.[name], doc, [...seen, name]);
  }
  const drop = new Set(["description", "summary", "example", "examples", "title", "$schema", "format", "deprecated"]);
  return Object.fromEntries(
    Object.entries(o)
      .filter(([k]) => !drop.has(k))
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, x]) => [k, normalise(x, doc, seen)]),
  );
}

/** Response objects are compared open: zod marks output objects closed, utoipa leaves them open. */
function open(v: Json): Json {
  if (Array.isArray(v)) return v.map(open);
  if (v === null || typeof v !== "object") return v;
  return Object.fromEntries(
    Object.entries(v as Record<string, Json>)
      .filter(([k, x]) => !(k === "additionalProperties" && x === false))
      .map(([k, x]) => [k, open(x)]),
  );
}

/** The comparable part of a frozen operation: parameters, JSON request body and JSON response schemas. */
function frozenShape(op: Record<string, Json>, doc: Frozen) {
  const o = normalise(op, doc) as {
    parameters?: { name: string; in: string; required?: boolean; schema?: Json }[];
    requestBody?: { content?: Record<string, { schema?: Json }> };
    responses?: Record<string, { content?: Record<string, { schema?: Json }> }>;
  };
  const params = (o.parameters ?? [])
    .filter((p) => p.in === "path" || p.in === "query")
    .map((p) => ({ name: p.name, in: p.in, required: p.in === "path" ? true : !!p.required }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return {
    params,
    body: o.requestBody?.content?.["application/json"]?.schema ?? null,
    responses: Object.fromEntries(
      Object.entries(o.responses ?? {}).map(([s, r]) => [s, open(r.content?.["application/json"]?.schema ?? null)]),
    ),
  };
}

function generatedShape(op: Operation, doc: Frozen) {
  const n = normalise(JSON.parse(JSON.stringify(op)), doc) as Operation;
  return {
    params: n.parameters
      .map((p) => ({ name: p.name, in: p.in, required: p.required }))
      .sort((a, b) => a.name.localeCompare(b.name)),
    body:
      (n.requestBody as { content: Record<string, { schema: Json }> } | undefined)?.content["application/json"]
        ?.schema ?? null,
    responses: Object.fromEntries(
      Object.entries(n.responses).map(([s, r]) => [
        s,
        open((r as { content?: Record<string, { schema: Json }> }).content?.["application/json"]?.schema ?? null),
      ]),
    ),
  };
}

/**
 * Differences between the operations generated from `routes` and the frozen openapi.json, for every
 * path the route table marks `nest`. An empty list means the Nest API honours the contract.
 */
export function diffAgainstFrozen(routes: RouteDef[], frozen: Frozen, table: RouteTable): string[] {
  const generated = buildOperations(routes);
  const diffs: string[] = [];
  const nest = table.routes.filter((r) => r.owner === "nest");
  for (const r of nest) {
    const key = routeKey(r.method, r.path);
    const g = generated.get(key);
    const f = frozen.paths[r.path]?.[r.method.toLowerCase()] as Record<string, Json> | undefined;
    if (!f) diffs.push(`${key}: marked nest but absent from the frozen openapi.json`);
    else if (!g) diffs.push(`${key}: marked nest but no zod route is registered`);
    else {
      const a = JSON.stringify(frozenShape(f, frozen));
      const b = JSON.stringify(generatedShape(g, frozen));
      if (a !== b)
        diffs.push(
          `${key}: generated operation differs from the frozen contract\n  frozen:    ${a}\n  generated: ${b}`,
        );
    }
  }
  const nestKeys = new Set(nest.map((r) => routeKey(r.method, r.path)));
  for (const key of generated.keys()) {
    if (!nestKeys.has(key)) diffs.push(`${key}: zod route registered but the route table does not mark it nest`);
  }
  return diffs;
}
