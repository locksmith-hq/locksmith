import path from "node:path";
import { expect, test, type Page } from "@playwright/test";

// Locked visual baselines for Overview, Projects and Activity (task 6.5). Data-bearing regions
// (lists, tables, panels with ids, counts and timestamps) are hidden by shot.css so only the frame, headings
// and layout are compared. Baselines are Linux Chromium; refresh with `just web-e2e --update-snapshots`.
const USER = "alice@locksmith.test";
const PASSWORD = "alice-dev-only";

async function signIn(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page.locator("#username").fill(USER);
  await page.locator("#password").fill(PASSWORD);
  await page.locator("#kc-login").click();
  await expect(page.getByTestId("signed-in-as")).toBeVisible();
}

const opts = () => ({
  maxDiffPixelRatio: 0.02,
  animations: "disabled" as const,
  stylePath: path.join(process.cwd(), "e2e", "shot.css"),
});

test.use({ viewport: { width: 1280, height: 800 } });

test("baselines: Overview, Projects, Activity", async ({ page }) => {
  await signIn(page);
  await expect(page.getByRole("heading", { name: /overview/i }).first()).toBeVisible();
  await expect(page.getByText(/loading|reading/i)).toHaveCount(0);
  await expect(page).toHaveScreenshot("overview.png", opts());

  await page.getByRole("link", { name: "Projects" }).click();
  await expect(page.getByLabel("Project name")).toBeVisible();
  await expect(page).toHaveScreenshot("projects.png", opts());

  await page.getByRole("link", { name: "Activity" }).click();
  await expect(page.getByRole("region", { name: "Audit" }).getByText("Reading the ledger…")).toHaveCount(0);
  await expect(page).toHaveScreenshot("activity.png", opts());
});
