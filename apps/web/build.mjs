import { build } from 'vite';
import react from '@vitejs/plugin-react';

await build({
  root: import.meta.dirname,
  configFile: false,
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
});
