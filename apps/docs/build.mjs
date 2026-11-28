import { copyFileSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = join(import.meta.dirname, "dist");
const content = join(import.meta.dirname, "content");
mkdirSync(dir, { recursive: true });

const pages = readdirSync(content)
  .filter((f) => f.endsWith(".md"))
  .sort();
for (const f of pages) copyFileSync(join(content, f), join(dir, f));
const links = pages.map((f) => `<li><a href="${f}">${f.replace(/\.md$/, "")}</a></li>`).join("\n");
writeFileSync(join(dir, "index.html"), `<h1>Locksmith docs</h1>\n<ul>\n${links}\n</ul>\n`);
