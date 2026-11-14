import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = join(import.meta.dirname, 'dist');
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, 'index.html'), '<h1>Locksmith ui</h1>\n');
