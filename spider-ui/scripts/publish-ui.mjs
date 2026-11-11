// Copies the built UI (dist/) into the Python package so `python -m spider serve` can serve it.
import { cpSync, rmSync, existsSync, readdirSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', 'dist');
const target = join(here, '..', '..', 'spider', 'static_ui');
if (!existsSync(dist)) { console.error('dist/ not found. Run `npm run build:http` first.'); process.exit(1); }
rmSync(target, { recursive: true, force: true });
cpSync(dist, target, { recursive: true });
for (const f of readdirSync(join(target, 'assets'))) if (f.endsWith('.map')) unlinkSync(join(target, 'assets', f));
console.log('Published UI to spider/static_ui');
