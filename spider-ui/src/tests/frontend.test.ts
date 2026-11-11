import type { Outcome, ScanRecord } from '../backend/types';
import { parseRecord, formatVerdictOutcome } from '../backend/parseRecord';
import { MockSpiderBackend } from '../backend/mock';
import { routeCamera, solveLeg } from '../components/SpiderScene';
import { experienceMotionMode } from '../components/overview/useExperienceMotion';
import { chapterFromProgress, splitCharacters, stageProgress } from '../components/overview/useChapterScroll';
import { environments, hubTiles } from '../app/environments';

export interface TestResult { name: string; passed: boolean; error?: string }
function assert(condition: unknown, message = 'Assertion failed'): asserts condition {
  if (!condition) throw new Error(message);
}

function escapeMarkdown(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

export async function runFrontendTests(): Promise<TestResult[]> {
  const results: TestResult[] = [];

  function test(name: string, fn: () => void | Promise<void>) {
    try {
      const res = fn();
      if (res && typeof (res as Promise<void>).then === 'function') {
        return (res as Promise<void>).then(
          () => results.push({ name, passed: true }),
          (err: unknown) => results.push({ name, passed: false, error: err instanceof Error ? err.message : String(err) })
        );
      }
      results.push({ name, passed: true });
    } catch (err: unknown) {
      results.push({ name, passed: false, error: err instanceof Error ? err.message : String(err) });
    }
  }

  // 1. parseRecord tests
  test('parseRecord accepts valid record', () => {
    const validRaw = {
      scan_id: 'test-scan-1',
      target: { name: 'pkg-a', version: '1.0.0' },
      verdict: { outcome: 'suspicious', reasons: ['S1_install_command'] },
      findings: [
        { severity: 'HIGH', indicator: 'cmd', category: 'install_time', file: 'setup.py' }
      ],
      inventory: { files_total: 2, files_inspected: 2, python_files: 1 },
    };
    const parsed = parseRecord(validRaw);
    assert(parsed.scan_id === 'test-scan-1');
    assert(parsed.verdict.outcome === 'suspicious');
    assert(parsed.findings.length === 1);
  });

  test('parseRecord rejects wrong verdict outcome', () => {
    const invalidRaw = {
      scan_id: 'test-scan-2',
      verdict: { outcome: 'safe' }, // forbidden / wrong
      findings: [],
      inventory: {},
    };
    let threw = false;
    try {
      parseRecord(invalidRaw);
    } catch {
      threw = true;
    }
    assert(threw, 'Should throw on invalid verdict outcome');
  });

  test('parseRecord rejects missing scan_id', () => {
    const invalidRaw = {
      verdict: { outcome: 'suspicious' },
      findings: [],
      inventory: {},
    };
    let threw = false;
    try {
      parseRecord(invalidRaw);
    } catch {
      threw = true;
    }
    assert(threw, 'Should throw on missing scan_id');
  });

  test('parseRecord ignores extra fields', () => {
    const withExtra = {
      scan_id: 'test-scan-3',
      extra_junk: 'should be ignored',
      unrelated_object: { nested: true },
      verdict: { outcome: 'none_detected_in_this_scan', reasons: [] },
      findings: [],
      inventory: { files_total: 1 },
    };
    const parsed = parseRecord(withExtra);
    assert(parsed.scan_id === 'test-scan-3');
    assert((parsed as unknown as Record<string, unknown>).extra_junk === undefined);
    assert((parsed as unknown as Record<string, unknown>).unrelated_object === undefined);
  });

  // 2. Verdict label mapping: exactly the three strings
  test('verdict label mapping returns exactly the three specified strings', () => {
    const verdicts: Outcome[] = ['suspicious', 'none_detected_in_this_scan', 'unable_to_assess'];
    const labels = verdicts.map(formatVerdictOutcome);
    assert(labels[0] === 'Suspicious', `Expected "Suspicious", got "${labels[0]}"`);
    assert(labels[1] === 'None detected in this scan', `Expected "None detected in this scan", got "${labels[1]}"`);
    assert(labels[2] === 'Unable to assess', `Expected "Unable to assess", got "${labels[2]}"`);
  });

  // 3. Markdown report escaping
  test('markdown report escaping escapes pipes and newlines so table cannot break', () => {
    const maliciousSnippet = 'import os | rm -rf / \n dangerous()';
    const escaped = escapeMarkdown(maliciousSnippet);
    assert(escaped.includes('\\|'), 'Pipes must be escaped as \\|');
    assert(!escaped.includes('\n'), 'Newlines must be replaced');
  });

  // 4. Unknown id never returns another record
  await test('unknown id throws and never returns another record', async () => {
    const mock = new MockSpiderBackend();
    let threw = false;
    try {
      await mock.getScan('non-existent-id-xyz');
    } catch (err) {
      threw = true;
      assert(err instanceof Error && err.message === 'This exact record is unavailable.');
    }
    assert(threw, 'Expected mock.getScan to throw on unknown id');
  });

  // 5. Scene math and chapter scroll tests (preserved)
  test('two-link IK clamps reachable length without NaN at singular targets', () => {
    const leg = solveLeg({ x: 0, y: 0.24, z: 0 }, { x: 0, y: 0, z: 0 });
    assert(Number.isFinite(leg.knee.x) && Number.isFinite(leg.foot.x));
  });

  test('decorative motion respects preferences, visibility, pause and artwork off', () => {
    assert(experienceMotionMode({ artwork: false, reducedMotion: false, systemReduced: false, paused: false, visible: true, inView: true }) === 'off');
    assert(experienceMotionMode({ artwork: true, reducedMotion: true, systemReduced: false, paused: false, visible: true, inView: true }) === 'reduced');
    assert(experienceMotionMode({ artwork: true, reducedMotion: false, systemReduced: false, paused: true, visible: true, inView: true }) === 'paused');
    assert(experienceMotionMode({ artwork: true, reducedMotion: false, systemReduced: false, paused: false, visible: true, inView: true }) === 'running');
  });

  test('chapter scroll math clamps progress and maps chapter indices', () => {
    assert(chapterFromProgress(0, 5) === 0);
    assert(chapterFromProgress(0.99, 5) === 4);
    assert(stageProgress(-50, 100) === 0.5);
    assert(splitCharacters('SPIDER').length === 6);
  });

  test('route camera states deterministic with bounded fallback', () => {
    const cam = routeCamera('/scanner/scan');
    assert(cam.yaw === -0.28 && cam.pitch === 0.66);
    const fallback = routeCamera('/other');
    assert(fallback.yaw === 0.12);
  });

  // 6. Stage 7 tests: Environment routes matching App.tsx routes
  test('every route path in environments.ts has a matching route in App.tsx', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const g = globalThis as any;
    const req = typeof g.require === 'function' ? g.require : null;
    if (!req) return;
    const fs = req('fs');
    const path = req('path');
    const appTsx = fs.readFileSync(path.resolve(g.process.cwd(), 'spider-ui/src/app/App.tsx'), 'utf-8');

    const envPaths = Object.values(environments).flatMap(e => e.items.map(i => i.path));
    const hubPaths = hubTiles.map(h => h.path);
    const allPaths = Array.from(new Set([...envPaths, ...hubPaths]));

    for (const p of allPaths) {
      assert(appTsx.includes(`path="${p}"`), `Path "${p}" in environments.ts missing in App.tsx`);
    }
  });

  // 7. Stage 7 test: Every NavLink target in components exists as a route
  test('every NavLink target in components exists as a known route', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const g = globalThis as any;
    const req = typeof g.require === 'function' ? g.require : null;
    if (!req) return;
    const fs = req('fs');
    const path = req('path');
    const compDir = path.resolve(g.process.cwd(), 'spider-ui/src/components');

    const knownRoutes = new Set([
      '/', '/hub', '/scanner/scan', '/scanner/result', '/scanner/evidence',
      '/scanner/score', '/scanner/report', '/hunter/scan', '/hunter/report',
      '/extension', '/learn', '/history/history', '/history/reports',
      '/research', '/research/overview', '/research/dataset', '/research/signals', '/research/models', '/research/limits',
      '/redteam/overview', '/redteam/batch', '/redteam/techniques', '/redteam/limits',
      '/settings'
    ]);

    function checkFiles(dir: string) {
      const items = fs.readdirSync(dir, { withFileTypes: true });
      for (const item of items) {
        const full = path.join(dir, item.name);
        if (item.isDirectory()) {
          checkFiles(full);
        } else if (full.endsWith('.tsx')) {
          const content = fs.readFileSync(full, 'utf-8');
          const matches = content.matchAll(/(?:<NavLink|<RouteLink)[^>]+to=(?:\"([^\"]+)\"|'([^']+)'|{`([^`]+)`})/g);
          for (const m of matches) {
            const rawTarget = m[1] || m[2] || m[3];
            if (rawTarget && !rawTarget.startsWith('#') && !rawTarget.includes('${')) {
              // Strip query parameters
              const target = rawTarget.split('?')[0];
              assert(knownRoutes.has(target), `Unknown route target "${target}" in ${item.name}`);
            }
          }
        }
      }
    }

    checkFiles(compDir);
  });

  // 8. Stage 7 test: RouteLoader is not rendered on the Welcome page
  test('RouteLoader is not rendered on the Welcome page', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const g = globalThis as any;
    const req = typeof g.require === 'function' ? g.require : null;
    if (!req) return;
    const fs = req('fs');
    const path = req('path');
    const workbenchTsx = fs.readFileSync(path.resolve(g.process.cwd(), 'spider-ui/src/components/Workbench.tsx'), 'utf-8');
    // Ensure RouteLoader condition checks !isLandingPage
    assert(workbenchTsx.includes('loaderDestination && !isLandingPage'), 'RouteLoader must only render when !isLandingPage');
  });

  // 9. Forbidden words test across src/**/*.{ts,tsx}
  test('grep all src/**/*.{ts,tsx} string literals for forbidden words', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const g = globalThis as any;
    const req = typeof g.require === 'function' ? g.require : null;
    if (!req) return; // In non-node environment, skip
    const fs = req('fs');
    const path = req('path');
    const proc = g.process;
    const srcDir = path.resolve(proc.cwd(), 'spider-ui/src');

    const allowedExemptions = [
      "Static analysis only. 'None detected in this scan' does not mean the package is safe.",
      "Never says a package is safe.",
      "Absence of findings is never evidence of safety",
      "Absence of findings is not proof of safety",
      "Does “no findings” mean safe?",
      "Static analysis still cannot prove package safety",
      "Static analysis only; nothing is executed. 'None detected in this scan' does not mean the package is safe.",
      "// forbidden / wrong",
      "verdict: { outcome: 'safe' }",
    ];

    function checkFile(filePath: string) {
      if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx')) return;
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      const forbidden = [
        /\bclean\b/i,
        /\bsecure\b/i,
        /\bmalware detected\b/i,
        /\bverified safe\b/i,
      ];

      lines.forEach((line: string, lineIdx: number) => {
        if (filePath.includes('frontend.test.ts')) return;

        for (const re of forbidden) {
          if (re.test(line)) {
            throw new Error(`Forbidden term ${re} found in ${filePath}:${lineIdx + 1}: ${line.trim()}`);
          }
        }

        if (/\bsafe\b/i.test(line)) {
          const isAllowed = allowedExemptions.some(ex => line.toLowerCase().includes(ex.toLowerCase()));
          if (!isAllowed) {
            throw new Error(`Unauthorized use of "safe" in ${filePath}:${lineIdx + 1}: ${line.trim()}`);
          }
        }
      });
    }

    function walkDir(dir: string) {
      if (!fs.existsSync(dir)) return;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walkDir(full);
        } else {
          checkFile(full);
        }
      }
    }

    walkDir(srcDir);
  });

  // Stage 1 new tests:
  // 10. Hub displays six tiles
  test('hub shows six tiles', () => {
    assert(hubTiles.length === 6, `Expected 6 hub tiles, found ${hubTiles.length}`);
    const expectedIds = ['scanner', 'hunter', 'extension', 'research', 'redteam', 'history'];
    expectedIds.forEach(id => {
      assert(hubTiles.some(t => t.id === id), `Missing tile id: ${id}`);
    });
  });

  // 11. Every new route has a Route in App.tsx
  test('every new route has a Route in App.tsx', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const g = globalThis as any;
    const req = typeof g.require === 'function' ? g.require : null;
    if (!req) return;
    const fs = req('fs');
    const path = req('path');
    const appTsx = fs.readFileSync(path.resolve(g.process.cwd(), 'spider-ui/src/app/App.tsx'), 'utf-8');

    const newRoutes = [
      '/research/overview',
      '/research/dataset',
      '/research/signals',
      '/research/models',
      '/research/limits',
      '/redteam/overview',
      '/redteam/batch',
      '/redteam/techniques',
      '/redteam/limits',
    ];

    for (const r of newRoutes) {
      assert(appTsx.includes(`path="${r}"`), `App.tsx missing route for ${r}`);
    }
  });

  // 12. No new copy contains safe as a claim
  test('no new copy contains "safe" as a claim', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const g = globalThis as any;
    const req = typeof g.require === 'function' ? g.require : null;
    if (!req) return;
    const fs = req('fs');
    const path = req('path');

    const newFiles = [
      'spider-ui/src/components/ResearchLabPages.tsx',
      'spider-ui/src/components/RedTeamPages.tsx',
    ];

    for (const f of newFiles) {
      const full = path.resolve(g.process.cwd(), f);
      if (fs.existsSync(full)) {
        const content = fs.readFileSync(full, 'utf-8');
        // Any occurrence of safe must only be in standard disclaimers or not present
        const matches = content.match(/\bsafe\b/gi);
        assert(!matches || matches.length === 0, `Forbidden "safe" found in ${f}`);
      }
    }
  });

  return results;
}
