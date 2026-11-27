# Locksmith design system

The Locksmith kit as npm packages, one per component, published to GitHub Packages as `@locksmith-hq/*`. It is built on [shadcn/ui](https://ui.shadcn.com): Tailwind CSS 4, Radix and Base UI primitives, lucide icons.

| Path | Contents |
|---|---|
| `packages/<component>` | One component each. Built with `tsc` to `dist/`. |
| `packages/styles` | `@locksmith-hq/styles`: the design tokens, the Tailwind theme that gives shadcn's parts the Locksmith look, and the styles of the Locksmith-only components. |
| `docs` | The docs site: a page per package with a live demo and its API. |
| `mcp` | An MCP server so coding agents can look up components, props, examples and tokens. |

Changes here wait for the owner's review (`.github/CODEOWNERS`).

Two rules, also in the repo's `AGENTS.md`: every Locksmith website and app is built from these components, and every component here is built on shadcn/ui.

## Two kinds of package

- **From shadcn/ui** (button, dialog, table, tabs, select and about 40 more). The source is what the shadcn CLI generates, unchanged. The Locksmith look (raised buttons, recessed wells, key tags, the tab tooth) is applied from `packages/styles/theme.css` by rules keyed on the `data-slot` each shadcn part carries, so a component can be pulled again from shadcn without losing the look.
- **Locksmith-only** (mark, wordmark, secret, copyable-id, meter, stat, timeline, stepper, date-picker and others). shadcn has no equivalent, so these are ours, written the shadcn way: `className` and native props pass through, a `data-slot` on the root, lucide icons, and shadcn parts inside wherever one fits.

## Use a component

The kit needs React 19 and Tailwind CSS 4. GitHub Packages needs a token even to install. In the consuming project's `.npmrc`:

```ini
@locksmith-hq:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @locksmith-hq/button @locksmith-hq/styles tailwindcss tw-animate-css
```

In the app's stylesheet:

```css
@import "tailwindcss";
@import "tw-animate-css";
@import "@locksmith-hq/styles";
@source "../node_modules/@locksmith-hq";
```

The `@source` line lets Tailwind see the classes written inside the components; without it they render unstyled.

```tsx
import { Button } from "@locksmith-hq/button";
```

The tokens name the fonts but do not load them: load Chakra Petch (400 to 700) and Azeret Mono (400, 500) yourself. `<html data-theme="light|dark">` forces a theme; without it the system setting decides.

## For coding agents

`design-system/mcp` is an MCP server that answers what components exist, their props, a working example of each, and the colour tokens, read from this source. It is configured in the repo's `.mcp.json` as `design-system`; the `design-system-mcp` skill (`.claude/skills/design-system-mcp`) covers setup, use and troubleshooting.

## Releases

Packages are published to GitHub Packages, the organization's private npm registry, by the `design-system-release` workflow. The version bump comes from Conventional Commits: name the pull request `feat(button): ...` for a minor bump, `fix(...)` or `perf(...)` for a patch, and add `!` for a major. See `.changeset/README.md`.

## Work on it

```bash
npm ci                                                # at the repo root
npm run dev --workspace @locksmith-hq/docs            # the docs site, reading the packages from source
npx turbo run build test --filter='./design-system/**'
```

- **Changing how a shadcn component looks:** edit `packages/styles/theme.css`, not the component.
- **Adding or updating a shadcn component:** generate it with the shadcn CLI in a scratch project (`npx shadcn@latest init -t vite -b radix -p nova`, then `npx shadcn@latest add <name>`), copy `src/components/ui/<name>.tsx` to `packages/<name>/src/index.tsx`, and change imports of `@/components/ui/<x>` to `@locksmith-hq/<x>`. Add look rules to `theme.css` if it needs them.
- **Locksmith-only components** document each prop on an exported `<Name>Props` interface. The docs build its API tables from those comments (`docs/gen-api.mjs`) and fails when a prop has none.

## Release

1. With your change, run `npx changeset`, pick the packages you changed and the bump, and commit the file it writes.
2. After the change merges to `main`, the `design-system-release` workflow opens a "design-system: version packages" pull request.
3. Merging that pull request publishes the new versions to GitHub Packages.
