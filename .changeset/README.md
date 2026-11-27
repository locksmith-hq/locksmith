# Changesets

Versions and changelogs of the design system packages (`design-system/packages/*`, published as `@locksmith-hq/*`).

You normally write nothing here. The bump comes from Conventional Commits: on each push to `main` that touches a package, the `design-system-release` workflow runs `scripts/design-system-changeset.mjs`, which reads the commits since the last release and writes the changeset.

| Commit (the pull request title, since pull requests are squash-merged) | Bump for the packages it touched |
|---|---|
| `feat(button): add a loading state` | minor |
| `fix: ...`, `perf: ...` | patch |
| `feat(button)!: ...`, or a `BREAKING CHANGE:` footer | major |
| `docs`, `chore`, `test`, `refactor` and anything else | none |

The workflow then opens a "design-system: version packages" pull request with the new versions, the packages that depend on them, and the changelogs. Merging it publishes to GitHub Packages.

To override a bump or add a note, run `npx changeset` and commit the file; it is added to the same pull request.

Apps and the other private packages are not versioned here.

## Packages for the public npm registry

Only the design system (`@locksmith-hq/*`, private, on GitHub Packages) is released today. Open-source packages for users, such as `@locksmith/sdk`, will go to the public npm registry later. Until then they are listed under `ignore` in `config.json`, because the release workflow has no npm login and one failed publish stops the whole run.

To start publishing one:

1. Give it `"publishConfig": { "registry": "https://registry.npmjs.org", "access": "public" }`. Changesets publishes each package to its own registry.
2. Remove it from `ignore` in `config.json`.
3. Give the release workflow a login for npmjs.org (npm trusted publishing, or an `NPM_TOKEN` secret) next to the GitHub Packages one.
4. Add its folder to the paths `scripts/design-system-changeset.mjs` reads, so its bump also comes from Conventional Commits.
