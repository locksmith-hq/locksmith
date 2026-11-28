# Locksmith design system

The Locksmith kit: one npm package, `@locksmith-hq/ui`, with a subpath per component, published to GitHub Packages. It is built on [shadcn/ui](https://ui.shadcn.com): Tailwind CSS 4, Radix and Base UI primitives, lucide icons.

| Path | Contents |
|---|---|
| `ui/src/<component>` | One component each. Built with `tsc` to `ui/dist/`. `ui/components.json` says in a line what each one is. |
| `ui/styles` | The design tokens, the Tailwind theme that gives shadcn's parts the Locksmith look, the styles of the Locksmith-only components, and the fonts. |
| `docs` | The docs site: a page per component with a live demo and its API. |
| `mcp` | An MCP server so coding agents can look up components, props, examples and tokens. |

Changes here wait for the owner's review (`.github/CODEOWNERS`).

Two rules, also in the repo's `AGENTS.md`: every Locksmith website and app is built from these components, and every component here is built on shadcn/ui.

## Two kinds of component

- **From shadcn/ui** (button, dialog, table, tabs, select and about 40 more). The source is what the shadcn CLI generates, less the classes the theme replaces (see "How the look is applied"). The Locksmith look (raised buttons, recessed wells, key tags, the tab tooth) is in `ui/styles/theme.css`, in rules keyed on the `data-slot` each shadcn part carries.
- **Locksmith-only** (mark, wordmark, secret, copyable-id, meter, stat, timeline, stepper, date-picker and others). shadcn has no equivalent, so these are ours, written the shadcn way: `className` and native props pass through, a `data-slot` on the root, lucide icons, and shadcn parts inside wherever one fits. The form controls among them (number-field, password-field, tags-input, the date pickers) are built from `Field`, `InputGroup` and `ButtonGroup`. Their own CSS is in `ui/styles/components.css`, under class names that all start with `ls-`.

## Use a component

The kit needs React 19 and Tailwind CSS 4. GitHub Packages needs a token even to install. In the consuming project's `.npmrc`:

```ini
@locksmith-hq:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @locksmith-hq/ui tailwindcss tw-animate-css
```

In the app's stylesheet:

```css
@import "tailwindcss";
@import "tw-animate-css";
@import "@locksmith-hq/ui/styles";
@import "@locksmith-hq/ui/styles/fonts.css";
@source "../node_modules/@locksmith-hq/ui";
```

The `@source` line lets Tailwind see the classes written inside the components; without it they render unstyled. The `fonts.css` line loads Chakra Petch (400 to 700) and Azeret Mono (400, 500) from Fontsource; leave it out if the app loads those two families another way.

```tsx
import { Button } from "@locksmith-hq/ui/button";
```

`<html data-theme="light|dark">` forces a theme; without it the system setting decides.

**A class you pass wins.** `<Button className="h-10">` is 40px high: the theme sits under Tailwind's utilities. Reach for it for layout (width, margin, a one-off height), not to restyle a component; a look that should be shared belongs in the theme.

**Other languages.** The kit's own words (button names for screen readers, a few visible defaults) are English. Wrap the app in `LabelsProvider` from `@locksmith-hq/ui/labels` and pass the ones you translate. Not covered yet: the relative dates in the date pickers and the lease timer, and the narration of `RelayPath`.

## How the look is applied

`theme.css` and `components.css` put their rules in Tailwind's `components` layer. Utilities are in a later layer, so they win: that is what makes a caller's `className` work. It also means a utility written in a component's own source wins over the theme. So a shadcn component must not keep a utility for a property its theme rule sets (`h-8` on a button whose rule sets `height`, say). `ui/theme.test.mjs` checks this for every component and names the classes to delete.

The tokens are in `tokens.css`: colours for both themes, the radius scale (`--radius-sm` to `--radius-2xl`, which Tailwind's `rounded-*` read), the type scale (`--font-size-2xs` to `--font-size-3xl`), shadows, durations and easings. Spacing is Tailwind's own scale; breakpoints are Tailwind's defaults.

The toast rules (sonner) are the one exception to the layer: sonner ships its own unlayered stylesheet, so those rules stay unlayered and marked important.

## For coding agents

`design-system/mcp` is an internal MCP server, used only to build Locksmith and never published. It answers what components exist, their props, a working example of each, and the colour tokens, read from this source. It is configured in the repo's `.mcp.json` as `design-system`; the `design-system-mcp` skill (`.claude/skills/design-system-mcp`) covers setup, use and troubleshooting.

## Work on it

```bash
npm ci                                                # at the repo root
npm run dev --workspace @locksmith-hq/docs            # the docs site, reading the kit from source
npx turbo run build test --filter='./design-system/**'
```

- **Changing how a shadcn component looks:** edit its rule in `ui/styles/theme.css`.
- **Adding or updating a shadcn component:** generate it with the shadcn CLI in a scratch project (`npx shadcn@latest init -t vite -b radix -p nova`, then `npx shadcn@latest add <name>`), copy `src/components/ui/<name>.tsx` to `ui/src/<name>/index.tsx`, change imports of `@/components/ui/<x>` to `../<x>`, and add its line to `ui/components.json`. Add look rules to `theme.css` if it needs them, then run `npm test --workspace @locksmith-hq/ui` and delete from the component the classes the test lists.
- **Locksmith-only components** document each prop on an exported `<Name>Props` interface. The docs build its API tables from those comments (`docs/gen-api.mjs`) and fails when a prop has none. A new class in `components.css` starts with `ls-`.
- **Every component has a demo** in `docs/src/demos.tsx`. `docs/src/demos.test.tsx` renders each one and runs axe on it, so a component is tested for rendering and accessibility as soon as it has a page.

What the tests do not cover: nothing compares screenshots, so a change to the theme is checked by eye on the docs site.

## Releases

The package is published to GitHub Packages, the organization's private npm registry, by the `design-system-release` workflow.

1. The version bump comes from Conventional Commits. Pull requests are squash-merged, so name the pull request: `feat(button): ...` is a minor bump, `fix(...)` or `perf(...)` a patch, and `!` after the type (or a `BREAKING CHANGE:` footer) a major. Other types release nothing.
2. After a change under `design-system/ui/` merges to `main`, the workflow opens a "design-system: version packages" pull request with the new version and the changelog.
3. Merging that pull request publishes the new version.

To override the bump or add a note to the changelog, run `npx changeset` with your change and commit the file it writes. See `.changeset/README.md`.
