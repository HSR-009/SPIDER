import type { HuntResult, ScanRecord, SpiderBackend } from './types';
import { parseRecord } from './parseRecord';
import resultsData from './results.json';

const STORAGE_KEY_SCANS = 'spider_mock_scans';
const STORAGE_KEY_HUNT = 'spider_mock_hunt';

const SAMPLE_RECORDS: (ScanRecord & { sample?: boolean })[] = [
  {
    scan_id: 'sample-installhook',
    target: { name: 'demo-installhook' },
    created_at: '2026-03-28T10:14:00Z',
    verdict: { outcome: 'suspicious', reasons: ['S1_install_command'], review_recommended: false },
    inventory: { files_total: 2, files_inspected: 2, python_files: 2, parse_failures: [], uninspected: [] },
    findings: [
      { severity: 'HIGH', indicator: 'setuptools.command.install', category: 'install_time', file: 'setup.py', span: { start_line: 4 }, explanation: 'Custom setuptools install command detected' },
      { severity: 'HIGH', indicator: 'install_command_override', category: 'install_time', file: 'setup.py', span: { start_line: 7 }, explanation: 'install command overrides run()' },
      { severity: 'HIGH', indicator: 'os.system', category: 'command_execution', file: 'setup.py', span: { start_line: 10 }, explanation: 'os.system() call detected' },
      { severity: 'LOW', indicator: 'setuptools.setup', category: 'install_time', file: 'setup.py', span: { start_line: 13 }, explanation: 'setuptools.setup() call detected' },
      { severity: 'MEDIUM', indicator: 'setuptools.setup.cmdclass', category: 'install_time', file: 'setup.py', span: { start_line: 13 }, explanation: 'setup(cmdclass=...) overrides build commands' },
    ],
  },
  {
    scan_id: 'sample-httpclient',
    target: { name: 'demo-httpclient' },
    created_at: '2026-03-28T10:20:00Z',
    verdict: { outcome: 'none_detected_in_this_scan', reasons: [], review_recommended: false },
    inventory: { files_total: 3, files_inspected: 2, python_files: 1, parse_failures: [], uninspected: [] },
    findings: [],
  },
  {
    scan_id: 'sample-native-only',
    sample: true,
    target: { name: 'demo-native' },
    created_at: '2026-03-28T10:25:00Z',
    verdict: { outcome: 'unable_to_assess', reasons: ['uninspected_ratio'], review_recommended: false },
    inventory: { files_total: 4, files_inspected: 1, python_files: 1, parse_failures: [], uninspected: ['core.so', 'core.pyd', 'lib.dll'] },
    findings: [],
  },
];

const SAMPLE_HUNT: HuntResult & { sample?: boolean } = {
  sample: true,
  hunt_id: 'sample-hunt',
  created_at: '2026-03-28T10:30:00Z',
  distributions_count: 42,
  roots: ['~/.venv/lib/python3.x/site-packages'],
  items: [
    {
      severity: 'HIGH',
      artifact: 'fixture.pth',
      reason: 'Startup hook: import line runs at interpreter start',
      path: '~/.venv/lib/python3.x/site-packages/fixture.pth',
      evidence_snippet: "import os; os.system('...')",
      priority: 90,
    },
    {
      severity: 'MEDIUM',
      artifact: 'sitecustomize.py',
      reason: 'Startup file present',
      path: '~/.venv/lib/python3.x/site-packages/sitecustomize.py',
      priority: 50,
    },
    {
      severity: 'LOW',
      artifact: 'demo-pkg 0.1.0',
      reason: 'Entry point registered by an installed package',
      priority: 10,
    },
  ],
  coverage: {
    counts: {
      skipped_too_large: 0,
      missing_in_RECORD: 0,
      inspection_timed_out: 0,
      file_list_unavailable: 0,
    },
  },
  limitations: ['Static inspection of installed files only; nothing is executed.'],
};

function loadStoredScans(): ScanRecord[] {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      const raw = window.localStorage.getItem(STORAGE_KEY_SCANS);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          return parsed.map(item => parseRecord(item));
        }
      }
    }
  } catch {
    // localStorage unavailable or corrupted; fallback to in-memory defaults
  }
  return SAMPLE_RECORDS.map(r => parseRecord(r));
}

function saveStoredScans(scans: ScanRecord[]): void {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(STORAGE_KEY_SCANS, JSON.stringify(scans));
    }
  } catch {
    // ignore quota/security exceptions
  }
}

export class MockSpiderBackend implements SpiderBackend {
  private scans: ScanRecord[];
  private lastHunt: HuntResult;

  constructor() {
    this.scans = loadStoredScans();
    this.lastHunt = SAMPLE_HUNT;
  }

  async scan(
    input: File | { path: string },
    onProgress?: (p: { stage: string; done?: number; total?: number }) => void,
  ): Promise<{ scan_id: string }> {
    const isFile = typeof File !== 'undefined' && input instanceof File;
    const name = isFile ? (input as File).name : (input as { path: string }).path;

    // Simulate 1.5s progress in 3 steps
    onProgress?.({ stage: 'unpacking', done: 1, total: 3 });
    await new Promise(r => setTimeout(r, 500));
    onProgress?.({ stage: 'ast_inspection', done: 2, total: 3 });
    await new Promise(r => setTimeout(r, 500));
    onProgress?.({ stage: 'evaluating_verdict', done: 3, total: 3 });
    await new Promise(r => setTimeout(r, 500));

    const scan_id = `scan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
    const cleanName = name.replace(/^.*[\\/]/, '');
    const isSuspicious = /malicious|evil|bad|hook|attack/i.test(cleanName);

    const record: ScanRecord = {
      scan_id,
      target: { name: cleanName, version: '1.0.0', hash_verified: true },
      created_at: new Date().toISOString(),
      verdict: isSuspicious
        ? {
            outcome: 'suspicious',
            reasons: ['S1_install_command'],
            review_recommended: true,
            limitations: ['Static analysis only; nothing is executed.'],
          }
        : {
            outcome: 'none_detected_in_this_scan',
            reasons: [],
            review_recommended: false,
            limitations: ['Static analysis only; nothing is executed.'],
          },
      findings: isSuspicious
        ? [
            {
              severity: 'HIGH',
              indicator: 'install_command_override',
              category: 'install_time',
              file: 'setup.py',
              span: { start_line: 5 },
              explanation: 'Custom install hook detected in setup.py',
              snippet: 'cmdclass={"install": CustomInstall}',
            },
          ]
        : [],
      inventory: {
        files_total: 3,
        files_inspected: 3,
        python_files: 2,
        parse_failures: [],
        uninspected: [],
      },
    };

    this.scans = [record, ...this.scans];
    saveStoredScans(this.scans);
    return { scan_id };
  }

  async getScan(id: string): Promise<ScanRecord> {
    const found = this.scans.find(s => s.scan_id === id);
    if (!found) {
      throw new Error('This exact record is unavailable.');
    }
    return parseRecord(found);
  }

  async listScans(): Promise<ScanRecord[]> {
    return this.scans.map(s => parseRecord(s));
  }

  async hunterRoots(): Promise<string[]> {
    return [
      '~/.venv/lib/python3.x/site-packages',
      '/usr/local/lib/python3.x/dist-packages',
      'C:\\Python311\\Lib\\site-packages',
    ];
  }

  async hunt(
    opts: { roots?: string[] },
    onProgress?: (p: { stage: string }) => void,
  ): Promise<HuntResult> {
    onProgress?.({ stage: 'discovering_environments' });
    await new Promise(r => setTimeout(r, 500));
    onProgress?.({ stage: 'inspecting_startup_hooks' });
    await new Promise(r => setTimeout(r, 500));
    onProgress?.({ stage: 'collecting_distributions' });
    await new Promise(r => setTimeout(r, 500));

    const roots = opts.roots && opts.roots.length > 0 ? opts.roots : ['~/.venv/lib/python3.x/site-packages'];
    const result: HuntResult = {
      ...SAMPLE_HUNT,
      hunt_id: `hunt-${Date.now().toString(36)}`,
      created_at: new Date().toISOString(),
      roots,
    };
    this.lastHunt = result;
    return result;
  }

  async getResults(): Promise<unknown> {
    return resultsData;
  }
}

