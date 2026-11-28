#!/usr/bin/env node
// Turns Conventional Commits into a changeset, so the design system's version bump comes from commit messages.
// It reads the commits on main since the last "design-system: version packages" commit, keeps the ones that
// touch design-system/ui/, and writes one changeset giving @locksmith-hq/ui the largest bump they ask for:
// `feat` is minor, `fix` and `perf` are patch, and a `!` after the type or a "BREAKING CHANGE:" footer is
// major. Other types (docs, chore, test, refactor...) release nothing.
// Changesets then does the rest: the version pull request, the changelog and publishing.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RANK = { patch: 1, minor: 2, major: 3 };
const KIT = "design-system/ui/";

/** The bump one commit asks for, or null when it releases nothing. */
export function bump(message) {
  const [subject = ""] = message.split("\n");
  const head = /^(\w+)(\([^)]*\))?(!)?:\s/.exec(subject);
  if (!head) return null;
  if (head[3] || /^BREAKING[ -]CHANGE:\s/m.test(message)) return "major";
  return head[1] === "feat" ? "minor" : head[1] === "fix" || head[1] === "perf" ? "patch" : null;
}

/** The largest bump the commits ({ message, files }) that touch the kit ask for, or null. */
export function plan(commits) {
  let out = null;
  for (const { message, files } of commits) {
    const b = bump(message);
    if (b && files.some((f) => f.startsWith(KIT)) && RANK[b] > (RANK[out] ?? 0)) out = b;
  }
  return out;
}

const git = (...args) => execFileSync("git", args, { encoding: "utf8", maxBuffer: 1 << 28 });

function main() {
  const last = git("log", "-1", "--format=%H", "--grep=^design-system: version packages").trim();
  const shas = git("log", "--format=%H", last ? `${last}..HEAD` : "HEAD", "--", KIT)
    .split("\n")
    .filter(Boolean);
  const commits = shas.map((sha) => ({
    message: git("log", "-1", "--format=%B", sha),
    files: git("diff-tree", "--no-commit-id", "--name-only", "-r", "-m", "--first-parent", sha).split("\n"),
  }));
  const b = plan(commits);
  if (!b) return console.log("design-system-changeset: no releasable commits");
  const notes = commits
    .filter((c) => bump(c.message) && c.files.some((f) => f.startsWith(KIT)))
    .map((c) => `- ${c.message.split("\n")[0]}`);
  writeFileSync(".changeset/from-commits.md", `---\n"@locksmith-hq/ui": ${b}\n---\n\n${notes.join("\n")}\n`);
  console.log(`design-system-changeset: wrote .changeset/from-commits.md (@locksmith-hq/ui: ${b})`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
