import { build } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

await build({
  root: import.meta.dirname,
  configFile: false,
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist", emptyOutDir: true },
});
