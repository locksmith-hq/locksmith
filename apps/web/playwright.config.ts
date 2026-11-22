import { defineConfig } from "@playwright/test";

// Needs `just up` (Keycloak profile) and `just api`; `just web-e2e` starts both checks and runs this.
export default defineConfig({
  testDir: "./e2e",
  timeout: 90_000,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://localhost:5173",
    launchOptions: process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM, args: ["--no-sandbox"] } : {},
  },
  webServer: {
    command: "npx vite --host localhost",
    url: "http://localhost:5173",
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
