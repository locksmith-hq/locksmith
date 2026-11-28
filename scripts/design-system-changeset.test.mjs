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

test("plan: only commits that touch the kit count, and the largest bump wins", () => {
  const kit = "design-system/ui/src/button/index.tsx";
  assert.equal(
    plan([
      { message: "fix(button): a", files: [kit, "apps/web/src/App.tsx"] },
      { message: "feat: b", files: [kit, "design-system/ui/styles/theme.css"] },
      { message: "feat!: c", files: ["design-system/docs/src/app.tsx"] },
      { message: "chore: d", files: ["design-system/ui/package.json"] },
    ]),
    "minor",
  );
  assert.equal(plan([{ message: "fix: docs only", files: ["design-system/docs/src/app.tsx"] }]), null);
});
