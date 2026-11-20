import { expect, test, type Page } from "@playwright/test";

// Seeded verified realm user (infra/compose keycloak realm; dev fixture, not a secret).
const USER = "alice@locksmith.test";
const PASSWORD = "alice-dev-only";
const stamp = Date.now().toString(36);

async function signIn(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page.locator("#username").fill(USER);
  await page.locator("#password").fill(PASSWORD);
  await page.locator("#kc-login").click();
  await expect(page.getByTestId("signed-in-as")).toBeVisible();
}

test("sign in, project, environment, agent, grant, activity; no value or material route is ever called", async ({ page }) => {
  const calls: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/v1/") || u.pathname.startsWith("/internal/")) calls.push(`${r.method()} ${u.pathname}`);
  });

  await signIn(page);
  await expect(page.getByRole("heading", { name: /overview/i }).first()).toBeVisible();

  // Project and environment.
  const project = `e2e-proj-${stamp}`;
  await page.getByRole("link", { name: "Projects" }).click();
  await page.getByLabel("Project name").fill(project);
  await page.getByRole("button", { name: "Create Project" }).click();
  await expect(page.getByText(project, { exact: true })).toBeVisible();
  await page.getByRole("link", { name: project }).click();
  const env = `e2e-env-${stamp}`;
  await page.getByLabel("Environment name").fill(env);
  await page.getByRole("button", { name: "Create Environment" }).click();
  await expect(page.getByRole("button", { name: `Rename ${env}` })).toBeVisible();

  // Agent: the enrollment secret is shown once.
  const agent = `e2e-agent-${stamp}`;
  await page.getByRole("link", { name: "Agents" }).click();
  await page.getByLabel("Agent name").fill(agent);
  await page.getByRole("button", { name: "Create agent" }).click();
  await expect(page.getByTestId("enrollment-secret")).toBeVisible();
  await page.getByRole("button", { name: "Dismiss" }).click();
  await expect(page.getByTestId("enrollment-secret")).toHaveCount(0);
  await expect(page.getByText(agent, { exact: true })).toBeVisible();

  // Grant: the control plane has no secret-create route yet, so a grant on an unknown id must surface
  // an error alert (not crash). Create and revoke against a real secret is covered once the secret
  // create route exists (see progress.md).
  await page.getByLabel(`Secret id for ${agent}`).fill("00000000-0000-4000-8000-000000000000");
  await page.getByRole("button", { name: `Grant ${agent}` }).click();
  await expect(page.getByRole("alert")).toBeVisible();

  // Activity.
  await page.getByRole("link", { name: "Activity" }).click();
  await expect(page.getByRole("region", { name: "Audit" })).toBeVisible();

  // Leak check: no request may target secret value or material routes.
  const bad = calls.filter((c) => /\/material|\/value|\/reveal|\/plaintext/.test(c));
  expect(bad, `value or material routes called: ${bad.join(", ")}`).toEqual([]);
  expect(calls.length).toBeGreaterThan(0);
});
