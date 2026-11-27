import assert from "node:assert/strict";
import { test } from "node:test";
import { bump, plan } from "./design-system-changeset.mjs";

test("bump: feat is minor, fix and perf are patch, a bang or a BREAKING CHANGE footer is major, the rest release nothing", () => {
  assert.equal(bump("feat(button): add a loading state"), "minor");
  assert.equal(bump("fix: keep the focus ring on Safari"), "patch");
  assert.equal(bump("perf(data-table): sort once"), "patch");
  assert.equal(bump("feat(button)!: rename variant"), "major");
  assert.equal(bump("fix: x\n\nBREAKING CHANGE: the prop is gone"), "major");
  assert.equal(bump("docs: explain tokens"), null);
  assert.equal(bump("design-system: version packages (#12)"), null);
  assert.equal(bump("Merge pull request #1 from x"), null);
});

test("plan: only design system packages are bumped, and each keeps its largest bump", () => {
  assert.deepEqual(
    plan([
      { message: "fix(button): a", files: ["design-system/packages/button/src/index.tsx", "apps/web/src/App.tsx"] },
      {
        message: "feat: b",
        files: ["design-system/packages/button/src/index.tsx", "design-system/packages/styles/theme.css"],
      },
      { message: "fix: c", files: ["design-system/packages/styles/theme.css", "design-system/docs/src/app.tsx"] },
      { message: "chore: d", files: ["design-system/packages/input/package.json"] },
    ]),
    { button: "minor", styles: "minor" },
  );
});
