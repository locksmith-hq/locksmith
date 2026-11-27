import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

// The packages are read from source, so the site never waits for a package build.
const packages = resolve(import.meta.dirname, "../packages");

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
  resolve: {
    dedupe: ["react", "react-dom"],
    alias: [
      { find: /^@locksmith-hq\/styles$/, replacement: `${packages}/styles/index.css` },
      { find: /^@locksmith-hq\/styles\/(.+)$/, replacement: `${packages}/styles/$1` },
      { find: /^@locksmith-hq\/([^/]+)$/, replacement: `${packages}/$1/src/index.tsx` },
    ],
  },
});
