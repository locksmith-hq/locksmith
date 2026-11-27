// What the MCP server knows, read from the design system's own source so it cannot drift from it:
// each package's exports, variants and documented props (the docs site's generator), its demo from the docs
// site, the colour tokens, and the README.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const at = (path) => fileURLToPath(new URL(`../${path}`, import.meta.url));
const read = (path) => readFileSync(at(path), "utf8");

let api;
function load() {
  if (api) return api;
  execFileSync(process.execPath, [at("docs/gen-api.mjs")], { stdio: ["ignore", "ignore", "inherit"] });
  return (api = JSON.parse(read("docs/src/api.json")));
}

// The docs site keeps one entry per page: `  name: ["what it is", <the demo JSX>],`.
function demos() {
  const out = {};
  const text = read("docs/src/demos.tsx");
  const from = text.indexOf("export const DEMOS");
  const starts = [...text.slice(from).matchAll(/^ {2}(?:"([\w-]+)"|(\w+)): \[\n?/gm)];
  starts.forEach((m, i) => {
    const body = text.slice(from + m.index + m[0].length, from + (starts[i + 1]?.index ?? text.length));
    const note = /^\s*"((?:[^"\\]|\\.)*)",/.exec(body);
    const example = body
      .slice(note ? note[0].length : 0)
      .replace(/\],?\s*(\};?\s*)?(export \{[^}]*\};?\s*)?$/, "")
      .replace(/,\s*$/, "");
    out[m[1] ?? m[2]] = { note: note?.[1] ?? "", example: example.replace(/^ {4}/gm, "").trim() };
  });
  return out;
}

const describe = (name) => JSON.parse(read(`packages/${name}/package.json`)).description;

/** Every component: its folder name, npm package and one-line description. */
export function listComponents() {
  const d = demos();
  return Object.entries(load()).map(([name, c]) => ({
    name,
    package: c.package,
    from: c.shadcn ? "shadcn/ui" : "locksmith",
    about: d[name]?.note || describe(name),
  }));
}

/** One component in full, or null when there is none by that name. */
export function getComponent(name) {
  const key = name.toLowerCase().replace(/^@locksmith-hq\//, "");
  const all = load();
  // "DataTable" and "data-table" both find the data-table package
  const found = all[key] ? key : Object.keys(all).find((k) => k.replaceAll("-", "") === key.replaceAll("-", ""));
  if (!found) return null;
  const c = all[found];
  const d = demos()[found];
  const parts = c.exports.filter((e) => /^[A-Z]/.test(e));
  return {
    name: found,
    package: c.package,
    install: `npm install ${c.package} @locksmith-hq/styles`,
    import: `import { ${parts.join(", ")} } from "${c.package}";`,
    about: d?.note || describe(found),
    from: c.shadcn
      ? `shadcn/ui: its parts take the props of the element or primitive they render, plus className. Reference: https://ui.shadcn.com/docs/components/${found}`
      : "Locksmith-only: the props below are the whole API, plus className and the root element's native props.",
    exports: c.exports,
    variants: c.variants,
    props: c.props,
    example: d?.example ?? null,
  };
}

/** The colour tokens: `{ name: { light, dark } }`. Names holding `filter` are kept, case ignored. */
export function getTokens(filter = "") {
  const css = read("packages/styles/tokens.css");
  const block = (start) => {
    const from = css.indexOf(start);
    return Object.fromEntries(
      [...css.slice(from, css.indexOf("\n}", from)).matchAll(/^\s*--([\w-]+):\s*([^;]+);/gm)].map((m) => [m[1], m[2]]),
    );
  };
  const light = block(":root {"),
    dark = block(':root[data-theme="dark"] {');
  const skip = /^(space|radius|shadow|duration|ease|font)-/;
  return Object.fromEntries(
    Object.keys(light)
      .filter((k) => !skip.test(k) && k.includes(filter.toLowerCase()))
      .map((k) => [k, { light: light[k], dark: dark[k] ?? light[k] }]),
  );
}

/** How to install and set up the kit in an app, and how to work on it: the design system's README. */
export const getGuide = () => read("README.md");
