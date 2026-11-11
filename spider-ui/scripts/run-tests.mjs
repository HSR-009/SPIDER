/** `npm test` harness for the dependency-free frontend test source.
 *
 * Bundles src/tests/frontend.test.ts with esbuild (already required by vite,
 * so no additional dependency is added) into a fresh temporary directory and
 * runs it under Node with real network and native addons disabled. The test
 * module itself never auto-runs and contains no network calls; this harness
 * invokes runFrontendTests(), prints one JSON line per result plus a summary,
 * and exits non-zero when any assertion fails or the module fails to load.
 */
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const frontendRoot = fileURLToPath(new URL('..', import.meta.url));
const require = createRequire(import.meta.url);

let esbuild;
try {
  esbuild = require('esbuild');
} catch {
  console.error('npm test needs frontend dependencies. Run "npm install" inside frontend/ first (see the project README).');
  process.exit(2);
}

const temp = await mkdtemp(path.join(tmpdir(), 'spider-frontend-tests-'));
try {
  const bundle = path.join(temp, 'frontend-tests.cjs');
  await esbuild.build({
    entryPoints: [path.join(frontendRoot, 'src', 'tests', 'frontend.test.ts')],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node20',
    jsx: 'automatic',
    tsconfig: path.join(frontendRoot, 'tsconfig.json'),
    outfile: bundle,
    logLevel: 'warning',
    legalComments: 'none',
  });
  const runner = path.join(temp, 'run-tests.cjs');
  await writeFile(runner, [
    '// Generated harness runner. No real network: the transport is replaced.',
    'globalThis.fetch = async () => { throw new Error("Real network is disabled in the test harness"); };',
    'const { runFrontendTests } = require(' + JSON.stringify(bundle) + ');',
    'runFrontendTests().then(results => {',
    '  for (const result of results) console.log(JSON.stringify(result));',
    '  const failed = results.filter(result => !result.passed);',
    '  console.log(JSON.stringify({ tests: results.length, passed: results.length - failed.length, failed: failed.length }));',
    '  if (failed.length) process.exitCode = 1;',
    '}).catch(error => { console.error(error); process.exitCode = 1; });',
    '',
  ].join('\n'), 'utf8');
  // --no-addons keeps the harness from loading native modules; the bundled
  // tests are self-contained and need none.
  const executed = spawnSync(process.execPath, ['--no-addons', runner], { stdio: 'inherit', cwd: temp, timeout: 120000 });
  if (executed.error) {
    console.error('Test runner failed to start:', executed.error.message);
    process.exitCode = 1;
  } else if (executed.status !== 0) {
    console.error('Frontend tests did not pass.');
    process.exitCode = executed.status ?? 1;
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  await rm(temp, { recursive: true, force: true });
}
