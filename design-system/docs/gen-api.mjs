// Reads every package and writes src/api.json for the docs pages: what it exports, the variants its cva()
// calls define, and (for Locksmith-only components) each documented prop of its `<Name>Props` interface.
// Fails when a documented interface has a prop with no description, so a new prop cannot ship undocumented.
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import ts from "typescript";

const root = new URL("../packages/", import.meta.url);
const api = {};
const bad = [];
for (const dir of readdirSync(root).sort()) {
  const file = new URL(`${dir}/src/index.tsx`, root);
  if (!existsSync(file)) continue;
  const pkg = JSON.parse(readFileSync(new URL(`${dir}/package.json`, root), "utf8"));
  const sf = ts.createSourceFile(dir, readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const exports = [],
    variants = {},
    props = {};
  const exported = (st) => st.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  const visit = (n) => {
    // cva("...", { variants: { variant: { default: "...", outline: "..." }, size: {...} } })
    if (
      ts.isCallExpression(n) &&
      n.expression.getText(sf) === "cva" &&
      n.arguments[1] &&
      ts.isObjectLiteralExpression(n.arguments[1])
    ) {
      const v = n.arguments[1].properties.find((p) => p.name?.getText(sf) === "variants");
      if (v && ts.isObjectLiteralExpression(v.initializer))
        for (const group of v.initializer.properties)
          if (ts.isObjectLiteralExpression(group.initializer))
            variants[group.name.getText(sf)] = [
              ...new Set([
                ...(variants[group.name.getText(sf)] ?? []),
                ...group.initializer.properties.map((o) => o.name.getText(sf).replace(/^"|"$/g, "")),
              ]),
            ];
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  for (const st of sf.statements) {
    if (ts.isExportDeclaration(st) && st.exportClause && ts.isNamedExports(st.exportClause))
      exports.push(...st.exportClause.elements.filter((e) => !e.isTypeOnly).map((e) => e.name.text));
    else if (exported(st) && (ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st))) exports.push(st.name.text);
    else if (exported(st) && ts.isVariableStatement(st))
      exports.push(...st.declarationList.declarations.map((d) => d.name.getText(sf)));
    if (ts.isInterfaceDeclaration(st) && exported(st) && st.name.text.endsWith("Props")) {
      props[st.name.text.slice(0, -5)] = st.members.map((m) => {
        const doc = ts.getJSDocCommentsAndTags(m).find(ts.isJSDoc);
        const description = ts.getTextOfJSDocComment(doc?.comment) ?? "";
        const def = doc?.tags?.find((t) => t.tagName.text === "default");
        const name = m.name.getText(sf).replace(/^"|"$/g, "");
        if (!description) bad.push(`${st.name.text}.${name}`);
        return {
          name,
          type: m.type.getText(sf).replace(/\s+/g, " "),
          required: !m.questionToken,
          default: def ? ts.getTextOfJSDocComment(def.comment) : null,
          description,
        };
      });
    }
  }
  if (!exports.length) continue;
  api[dir] = { package: pkg.name, shadcn: pkg.description.includes("from shadcn/ui"), exports, variants, props };
}
if (bad.length) {
  console.error("props without a description:\n- " + bad.join("\n- "));
  process.exit(1);
}
writeFileSync(new URL("src/api.json", import.meta.url), JSON.stringify(api, null, 2) + "\n");
console.log(`api.json: ${Object.keys(api).length} packages`);
