// Merge the frozen Rust OpenAPI document with the Nest-only one (decision NC-1) into one document for
// openapi-typescript. A path or schema name present in both is a collision and fails with its name.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function mergeSpecs(frozen, nest) {
  const merged = structuredClone(frozen);
  for (const [path, item] of Object.entries(nest.paths ?? {})) {
    if (path in merged.paths) throw new Error(`path collision: ${path} is in both documents`);
    merged.paths[path] = item;
  }
  const schemas = nest.components?.schemas ?? {};
  for (const [name, schema] of Object.entries(schemas)) {
    merged.components ??= {};
    merged.components.schemas ??= {};
    if (name in merged.components.schemas) throw new Error(`schema collision: ${name} is in both documents`);
    merged.components.schemas[name] = schema;
  }
  return merged;
}

const read = (p) => JSON.parse(readFileSync(p, "utf8"));

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = new URL("../../", import.meta.url);
  const merged = mergeSpecs(
    read(new URL("services/control-plane/openapi.json", root)),
    read(new URL("apps/api/openapi.nest.json", root)),
  );
  writeFileSync(process.argv[2], `${JSON.stringify(merged, null, 2)}\n`);
}
