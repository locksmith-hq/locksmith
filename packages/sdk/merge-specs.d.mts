type Doc = { paths: Record<string, unknown>; components?: { schemas?: Record<string, unknown> } };
export function mergeSpecs<T extends Doc>(frozen: T, nest: Doc): T;
