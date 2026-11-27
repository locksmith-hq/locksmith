#!/usr/bin/env node
// Turns Conventional Commits into a changeset, so the design system's version bumps come from commit messages.
// It reads the commits on main since the last "design-system: version packages" commit, keeps the ones that
// touch design-system/packages/<name>/, and writes one changeset giving each touched package the largest bump
// its commits ask for: `feat` is minor, `fix` and `perf` are patch, and a `!` after the type or a
// "BREAKING CHANGE:" footer is major. Other types (docs, chore, test, refactor...) release nothing.
// Changesets then does the rest: the version pull request, dependents, changelogs and publishing.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RANK = { patch: 1, minor: 2, major: 3 };

/** The bump one commit asks for, or null when it releases nothing. */
export function bump(message) {
  const [subject = ""] = message.split("\n");
  const head = /^(\w+)(\([^)]*\))?(!)?:\s/.exec(subject);
  if (!head) return null;
  if (head[3] || /^BREAKING[ -]CHANGE:\s/m.test(message)) return "major";
  return head[1] === "feat" ? "minor" : head[1] === "fix" || head[1] === "perf" ? "patch" : null;
}

/** Folds commits ({ message, files }) into { packageDir: bump }, keeping the largest bump per package. */
export function plan(commits) {
  const out = {};
  for (const { message, files } of commits) {
    const b = bump(message);
    if (!b) continue;
    for (const file of files) {
      const dir = /^design-system\/packages\/([^/]+)\//.exec(file)?.[1];
      if (dir && RANK[b] > (RANK[out[dir]] ?? 0)) out[dir] = b;
    }
  }
  return out;
}

const git = (...args) => execFileSync("git", args, { encoding: "utf8", maxBuffer: 1 << 28 });

function main() {
  const last = git("log", "-1", "--format=%H", "--grep=^design-system: version packages").trim();
  const shas = git("log", "--format=%H", last ? `${last}..HEAD` : "HEAD", "--", "design-system/packages")
    .split("\n")
    .filter(Boolean);
  const commits = shas.map((sha) => ({
    message: git("log", "-1", "--format=%B", sha),
    files: git("diff-tree", "--no-commit-id", "--name-only", "-r", "-m", "--first-parent", sha).split("\n"),
  }));
  const bumps = plan(commits);
  const lines = Object.entries(bumps)
    .filter(([dir]) => existsSync(`design-system/packages/${dir}/package.json`)) // a package deleted since
    .map(
      ([dir, b]) => `"${JSON.parse(readFileSync(`design-system/packages/${dir}/package.json`, "utf8")).name}": ${b}`,
    );
  if (!lines.length) return console.log("design-system-changeset: no releasable commits");
  const notes = commits.filter((c) => bump(c.message)).map((c) => `- ${c.message.split("\n")[0]}`);
  writeFileSync(".changeset/from-commits.md", `---\n${lines.join("\n")}\n---\n\n${notes.join("\n")}\n`);
  console.log(`design-system-changeset: wrote .changeset/from-commits.md\n${lines.join("\n")}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
