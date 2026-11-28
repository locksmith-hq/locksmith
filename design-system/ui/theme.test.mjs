// Guards what makes `className` work on a themed component. The theme (styles/theme.css) sits in Tailwind's
// `components` layer, under the utilities, so a class a caller passes wins. The catch: a utility left in a
// component's own source wins too. So no component may carry a utility whose every property its theme rule
// already sets: that utility would silently replace the Locksmith look. This fails when one does, most often
// after a component is pulled again from shadcn/ui, and names the classes to delete from the component.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { compile } from "@tailwindcss/node";
import postcss from "postcss";
import ts from "typescript";

const here = import.meta.dirname;

// { slot: Set(class) }: for each element with a data-slot, the classes in its className and in the cva() it calls.
function slots() {
  const out = {};
  for (const dir of readdirSync(`${here}/src`)) {
    for (const name of readdirSync(`${here}/src/${dir}`).filter((n) => n.endsWith(".tsx") && !n.includes(".test."))) {
      const sf = ts.createSourceFile(
        name,
        readFileSync(`${here}/src/${dir}/${name}`, "utf8"),
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TSX,
      );
      const strings = (n, acc = []) => {
        if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) acc.push(n.text);
        ts.forEachChild(n, (c) => void strings(c, acc));
        return acc;
      };
      const cvas = {};
      const visit = (n) => {
        if (
          ts.isVariableDeclaration(n) &&
          n.initializer &&
          ts.isCallExpression(n.initializer) &&
          n.initializer.expression.getText(sf) === "cva"
        )
          cvas[n.name.getText(sf)] = strings(n.initializer);
        if (ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) {
          const attr = (k) => n.attributes.properties.find((p) => ts.isJsxAttribute(p) && p.name.getText(sf) === k);
          const slot = attr("data-slot")?.initializer;
          const cls = attr("className")?.initializer;
          if (slot && ts.isStringLiteral(slot) && cls) {
            let found = strings(cls);
            const calls = (m) => {
              if (ts.isCallExpression(m) && cvas[m.expression.getText(sf)])
                found = found.concat(cvas[m.expression.getText(sf)]);
              ts.forEachChild(m, calls);
            };
            calls(cls);
            const set = (out[slot.text] ??= new Set());
            for (const c of found.flatMap((s) => s.split(/\s+/)).filter(Boolean)) set.add(c);
          }
        }
        ts.forEachChild(n, visit);
      };
      visit(sf);
    }
  }
  return out;
}

// A property as the set of longhands it sets, physical sides only, so `border` meets `border-top-width`.
const SIDES = ["top", "right", "bottom", "left"];
const sides = (p, tail = "") => SIDES.map((s) => `${p}-${s}${tail}`);
const BORDER = ["width", "style", "color"];
const WHOLE = {
  padding: sides("padding"),
  margin: sides("margin"),
  inset: SIDES,
  border: BORDER.flatMap((k) => sides("border", `-${k}`)),
  "border-width": sides("border", "-width"),
  "border-style": sides("border", "-style"),
  "border-color": sides("border", "-color"),
  "border-radius": ["top-left", "top-right", "bottom-right", "bottom-left"].map((c) => `border-${c}-radius`),
  background: ["color", "image", "position", "size", "repeat", "origin", "clip", "attachment"].map(
    (k) => `background-${k}`,
  ),
  font: ["font-style", "font-weight", "font-size", "line-height", "font-family"],
  gap: ["row-gap", "column-gap"],
  transition: ["property", "duration", "timing-function", "delay"].map((k) => `transition-${k}`),
  outline: BORDER.map((k) => `outline-${k}`),
  flex: ["flex-grow", "flex-shrink", "flex-basis"],
  animation: ["name", "duration", "timing-function", "iteration-count"].map((k) => `animation-${k}`),
  overflow: ["overflow-x", "overflow-y"],
};
for (const s of SIDES) WHOLE[`border-${s}`] = BORDER.map((k) => `border-${s}-${k}`);
const LOGICAL = {
  "inline-start": ["left"],
  "inline-end": ["right"],
  "block-start": ["top"],
  "block-end": ["bottom"],
  inline: ["left", "right"],
  block: ["top", "bottom"],
};
function longhands(prop) {
  if (prop.startsWith("--")) return [];
  const m = /^(.*?)-?(inline-start|inline-end|block-start|block-end|inline|block)(-.*)?$/.exec(prop);
  if (m && /^(padding|margin|inset|border)$/.test(m[1]))
    return LOGICAL[m[2]].flatMap((s) => longhands(m[1] === "inset" ? s : `${m[1]}-${s}${m[3] ?? ""}`));
  return WHOLE[prop] ?? [prop];
}

const split = (sel) => {
  const out = [];
  let depth = 0,
    cur = "";
  for (const ch of sel) {
    if (ch === "(" || ch === "[") depth++;
    if (ch === ")" || ch === "]") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  out.push(cur.trim());
  return out.flatMap((x) => {
    const m = /^:is\((.*)\)([^()]*)$/.exec(x);
    return m && !/^[^(]*\)/.test(m[1]) ? split(m[1]).map((y) => y + m[2]) : [x];
  });
};
const ID = /\[data-slot="([\w-]+)"\]|\.group\\\/button/g;

test("no component carries a utility that its theme rule already decides", async () => {
  const bySlot = slots();
  const css = '@import "tailwindcss";\n@import "tw-animate-css";\n@import "./styles/index.css";\n';
  const compiler = await compile(css, { base: here, onDependency() {} });
  const root = postcss.parse(compiler.build([...new Set(Object.values(bySlot).flatMap((s) => [...s]))]));

  // What the theme always sets for a slot: rules whose selector is the slot alone (no state, no ancestor).
  const always = {};
  const utilities = new Map();
  root.walkAtRules("layer", (layer) => {
    if (layer.params === "components")
      layer.walkRules((rule) => {
        for (const sel of split(rule.selector)) {
          const ids = [...sel.matchAll(ID)].map((m) => m[1] ?? "button");
          const rest = sel
            .replace(/:is\(((\s*(\[data-slot="[\w-]+"\]|\.group\\\/button)\s*,?)+)\)/g, "")
            .replace(ID, "");
          if (ids.length !== 1 || rest.trim()) continue;
          rule.each(
            (d) => d.type === "decl" && longhands(d.prop).forEach((p) => (always[ids[0]] ??= new Set()).add(p)),
          );
        }
      });
    if (layer.params === "utilities")
      layer.each((rule) => {
        if (rule.type !== "rule" || !/^\.[^\s>+~,]+$/.test(rule.selector)) return; // one class, styling its own element
        const name = rule.selector
          .slice(1)
          .replace(/\\([0-9a-f]{1,6}) ?/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
          .replace(/\\(.)/g, "$1");
        const props = utilities.get(name) ?? new Set();
        // Declarations under a state (`&:hover`, a media query) count; ones for a child or a pseudo-element do not.
        const take = (node) =>
          node.each((d) => {
            if (d.type === "decl") longhands(d.prop).forEach((p) => props.add(p));
            else if (d.type === "atrule") take(d);
            else if (
              d.type === "rule" &&
              !/&\s*[\s>+~]\s*\S|::/.test(d.selector.replace(/\([^()]*(\([^()]*\)[^()]*)*\)/g, "")) &&
              d.selector.includes("&")
            )
              take(d);
          });
        take(rule);
        utilities.set(name, props);
      });
  });
  assert.ok(Object.keys(always).length > 50, "the theme's slot rules were not found");
  assert.ok(utilities.size > 300, "the compiled utilities were not found");

  const dead = [];
  for (const [slot, classes] of Object.entries(bySlot)) {
    const set = always[slot];
    if (!set) continue;
    for (const c of classes) {
      if (c.endsWith("!") || /^(peer|group)(\/|$)/.test(c)) continue; // important ones win on purpose; markers style nothing
      const props = utilities.get(c);
      if (props?.size && [...props].every((p) => set.has(p))) dead.push(`${slot}: ${c}`);
    }
  }
  assert.deepEqual(
    dead,
    [],
    "delete these classes from the component (the theme sets the same properties), or drop the property from the theme rule",
  );
});
