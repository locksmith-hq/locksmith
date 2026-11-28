import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist" },
  server: { port: 5173, strictPort: true },
  test: { exclude: ["e2e/**", "node_modules/**"], environment: "jsdom", setupFiles: ["./src/setup.ts"], globals: true },
});
