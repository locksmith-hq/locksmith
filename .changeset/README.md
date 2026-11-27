# Changesets

Versions and changelogs of the design system packages (`design-system/packages/*`, published as `@locksmith-hq/*`).

After changing a package, run `npx changeset`, pick the packages you changed and the kind of bump, and commit the file it writes. When the change reaches `main`, the `design-system-release` workflow opens a "Version Packages" pull request; merging it publishes the new versions to GitHub Packages.

Apps and the other private packages are not versioned here.
