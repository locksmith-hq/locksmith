import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vitest/config";

// The kit is read from source, so the site never waits for its build.
const ui = resolve(import.meta.dirname, "../ui");

export default defineConfig({
  plugins: [tailwindcss()],
  build: {
    rollupOptions: {
      // shadcn, Radix and lucide mark their modules "use client"; that means nothing in a client-only bundle.
      onwarn(w, warn) {
        if (w.code !== "MODULE_LEVEL_DIRECTIVE" && w.code !== "SOURCEMAP_ERROR") warn(w);
      },
    },
  },
  test: { environment: "jsdom", setupFiles: ["./src/setup.ts"] },
  resolve: {
    dedupe: ["react", "react-dom"],
    alias: [
      { find: /^@locksmith-hq\/ui\/styles$/, replacement: `${ui}/styles/index.css` },
      { find: /^@locksmith-hq\/ui\/styles\/(.+)$/, replacement: `${ui}/styles/$1` },
      { find: /^@locksmith-hq\/ui\/([^/]+)$/, replacement: `${ui}/src/$1/index.tsx` },
    ],
  },
});
