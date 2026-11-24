/** `METHOD /path` entries (upper-case method) for every operation in an OpenAPI document. */
export function operations(spec: { paths: Record<string, Record<string, unknown>> }): string[] {
  const methods = ["get", "put", "post", "delete", "patch"];
  const out: string[] = [];
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const m of methods) if (m in item) out.push(`${m.toUpperCase()} ${path}`);
  }
  return out.sort();
}

/** Operations with neither a scenario nor an exclusion, and exclusions that are stale. */
export function coverageGaps(ops: string[], covered: string[], excluded: Record<string, string>) {
  const cov = new Set(covered);
  const missing = ops.filter((o) => !cov.has(o) && !(o in excluded));
  const staleExclusions = Object.keys(excluded).filter((e) => cov.has(e) || !ops.includes(e));
  const unknownCovers = [...cov].filter((c) => !ops.includes(c));
  return { missing, staleExclusions, unknownCovers };
}
