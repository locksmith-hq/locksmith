// The seam for what is not open source. The API in this repository is the free product. Modules that belong
// to a paid plan live in the private locksmith-cloud repository; its build copies them into ./paid (git-ignored
// here). Each file there is named `<name>.module.ts` and default-exports a Nest module. Nothing in this
// repository may import from ./paid: the open build must run with the folder absent, as it does here.
import { existsSync, readdirSync } from "node:fs";
import type { Type } from "@nestjs/common";

/** The paid modules present in this build, in file-name order. None in the open build. */
export async function paidModules(dir = new URL("./paid/", import.meta.url)): Promise<Type[]> {
  if (!existsSync(dir)) return [];
  const out: Type[] = [];
  for (const file of readdirSync(dir).sort()) {
    if (!/\.module\.(ts|js)$/.test(file) || file.endsWith(".d.ts")) continue;
    const loaded = (await import(new URL(file, dir).href)) as { default?: Type };
    if (typeof loaded.default !== "function") throw new Error(`paid module ${file} has no default export`);
    out.push(loaded.default);
  }
  return out;
}
