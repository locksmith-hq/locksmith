import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist" },
  // `just up` + `just api`: same-origin API calls reach the control plane (used by `just web-e2e`).
  // LOCKSMITH_API_URL=http://127.0.0.1:8088 sends them through the B5 api-proxy (Rust or NestJS by route).
  server: {
    port: 5173,
    strictPort: true,
    proxy: { "/v1": process.env["LOCKSMITH_API_URL"] ?? "http://127.0.0.1:8080" },
  },
  test: { exclude: ["e2e/**", "node_modules/**"], environment: "jsdom", setupFiles: ["./src/setup.ts"], globals: true },
});
