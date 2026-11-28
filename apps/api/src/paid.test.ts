import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { paidModules } from "./paid.js";

describe("paid modules", () => {
  it("the open build has none", async () => {
    expect(await paidModules()).toEqual([]);
  });

  it("loads each *.module file's default export and nothing else", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paid-"));
    writeFileSync(join(dir, "b.module.js"), "export default class B {}");
    writeFileSync(join(dir, "a.module.js"), "export default class A {}");
    writeFileSync(join(dir, "helper.js"), "export default class Helper {}");
    const found = await paidModules(pathToFileURL(dir + "/"));
    expect(found.map((m) => m.name)).toEqual(["A", "B"]);
  });

  it("refuses a module file with no default export, so a broken copy cannot start silently", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paid-"));
    writeFileSync(join(dir, "x.module.js"), "export const nothing = 1;");
    await expect(paidModules(pathToFileURL(dir + "/"))).rejects.toThrow(/x\.module\.js has no default export/);
  });
});
