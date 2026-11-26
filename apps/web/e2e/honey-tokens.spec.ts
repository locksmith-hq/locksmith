import { expect, test, type Page } from "@playwright/test";

// Honey tokens page (t5 task 5.3). Sign-in uses the seeded Keycloak realm user like console.spec.ts; the
// honey-token routes are answered from in-test fixtures so the triggered state is deterministic and no
// decoy value exists anywhere in the page. Needs `just up` (Keycloak profile) and `just api`.
const USER = "alice@locksmith.test";
const PASSWORD = "alice-dev-only";
const stamp = Date.now().toString(36);
const SENTINEL = "AKIAHONEYSENTINEL00";

async function signIn(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Continue with email" }).click();
  await page.locator("#username").fill(USER);
  await page.locator("#password").fill(PASSWORD);
  await page.locator("#kc-login").click();
  await expect(page.getByTestId("signed-in-as")).toBeVisible();
}

interface Tok {
  id: string;
  name: string;
  template: string;
  created_at: string;
  disabled_at: string | null;
  last_triggered_at: string | null;
}

test("honey tokens: create, copy the plant command, see a triggered state, disable and delete; no value in the DOM", async ({
  page,
  context,
}) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const tokens: Tok[] = [
    {
      id: "0190b000-0000-7000-8000-0000000000b1",
      name: `triggered-${stamp}`,
      template: "aws_access_key",
      created_at: "2026-11-25T10:00:00Z",
      disabled_at: null,
      last_triggered_at: "2026-11-26T02:15:00Z",
    },
  ];
  await page.route(/\/v1\/projects\/[^/]+\/environments\/[^/]+\/honey-tokens(\/.*)?$/, async (route) => {
    const req = route.request();
    const tail = new URL(req.url()).pathname.split("/honey-tokens")[1] ?? "";
    const json = (status: number, body: unknown) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (tail === "" && req.method() === "GET") return json(200, { items: tokens });
    if (tail === "" && req.method() === "POST") {
      const b = req.postDataJSON() as { name: string; template: string };
      const t: Tok = {
        id: `h-${tokens.length + 1}`,
        ...b,
        created_at: "2026-11-26T08:00:00Z",
        disabled_at: null,
        last_triggered_at: null,
      };
      tokens.push(t);
      return json(201, t);
    }
    const [, id, action] = tail.split("/");
    const i = tokens.findIndex((t) => t.id === id);
    if (i < 0) return json(404, { title: "Not Found", status: 404 });
    if (req.method() === "DELETE") return (tokens.splice(i, 1), route.fulfill({ status: 204 }));
    tokens[i]!.disabled_at ??= "2026-11-26T08:01:00Z";
    return action === "disable" ? json(200, tokens[i]) : json(405, {});
  });

  await signIn(page);
  const project = `e2e-honey-${stamp}`;
  await page.getByRole("link", { name: "Projects" }).click();
  await page.getByLabel("Project name").fill(project);
  await page.getByRole("button", { name: "Create Project" }).click();
  await page.getByRole("link", { name: project }).click();
  const env = `env-${stamp}`;
  await page.getByLabel("Environment name").fill(env);
  await page.getByRole("button", { name: "Create Environment" }).click();
  await page.getByRole("link", { name: `Honey tokens: ${env}` }).click();

  // The triggered state comes from the fixture.
  const triggered = `triggered-${stamp}`;
  await expect(page.getByRole("cell", { name: triggered, exact: true })).toBeVisible();
  await expect(page.getByText("2026-11-26T02:15:00Z")).toBeVisible();

  // Create.
  const name = `decoy-${stamp}`;
  await page.getByLabel("Honey token name").fill(name);
  await page.getByLabel("Honey token template").selectOption("github_pat");
  await page.getByRole("button", { name: "Create honey token" }).click();
  await expect(page.getByRole("cell", { name, exact: true })).toBeVisible();

  // Copy the plant command: a name and a placeholder path, never a value.
  await page.getByRole("button", { name: `Copy plant command: ${name}` }).click();
  await expect(page.getByRole("status")).toHaveText(/Copied/);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`smith honey plant ${name} --into .env`);

  // Disable, then delete.
  await page.getByRole("button", { name: `Disable ${name}` }).click();
  await expect(page.getByRole("button", { name: `Disable ${name}` })).toBeDisabled();
  await page.getByRole("button", { name: `Delete ${name}` }).click();
  await page.getByRole("button", { name: "Confirm delete" }).click();
  await expect(page.getByRole("cell", { name, exact: true })).toHaveCount(0);

  // No decoy value anywhere in the DOM.
  const html = await page.content();
  expect(html).not.toContain(SENTINEL);
  expect(html).not.toMatch(/AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[bp]-/);
});
