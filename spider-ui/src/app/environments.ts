export type EnvId = 'scanner' | 'hunter' | 'extension' | 'learn' | 'history' | 'research' | 'redteam' | 'settings';

export interface EnvItem {
  path: string;
  label: string;
  icon: 'scanner' | 'workspace' | 'evidence' | 'explain' | 'reports' | 'environment' | 'findings' | 'history' | 'settings' | 'shield' | 'models' | 'overview' | 'lab';
  description: string;
}

export interface Environment {
  id: EnvId;
  name: string;
  tagline: string;
  icon: 'scanner' | 'workspace' | 'evidence' | 'explain' | 'reports' | 'environment' | 'findings' | 'history' | 'settings' | 'shield' | 'models' | 'overview' | 'lab';
  status: 'Ready' | 'Preview' | 'Coming soon' | 'Guide';
  includes: string[];
  items: EnvItem[];
}

export const hubTiles = [
  {
    id: 'scanner',
    name: 'Package Scanner',
    tagline: 'Check one package before you trust it.',
    status: 'Ready' as const,
    path: '/scanner/scan',
    includes: ['Archive upload', 'AST evidence', 'Score', 'Verdict', 'Report'],
  },
  {
    id: 'hunter',
    name: 'Environment Hunter',
    tagline: 'Look for threats already installed.',
    status: 'Ready' as const,
    path: '/hunter/scan',
    includes: ['Roots picker', 'Scan', 'Findings & coverage'],
  },
  {
    id: 'extension',
    name: 'SPIDER Extension',
    tagline: 'Check a package before you install it.',
    status: 'Coming soon' as const,
    path: '/extension',
    includes: ['Download', 'How it works', 'Planned setup'],
  },
  {
    id: 'research',
    name: 'Research Lab',
    tagline: 'Corpus benchmarks, signals, and limits.',
    status: 'Preview' as const,
    path: '/research/overview',
    includes: ['Corpus data', 'Signal distributions', 'Model review', 'Limits'],
  },
  {
    id: 'redteam',
    name: 'Red Team',
    tagline: 'Adversarial evasion testing.',
    status: 'Preview' as const,
    path: '/redteam/overview',
    includes: ['Synthetic batch', 'Evasion techniques', 'Limits'],
  },
  {
    id: 'history',
    name: 'History and Reports',
    tagline: 'Every scan and every export in one place.',
    status: 'Ready' as const,
    path: '/history/history',
    includes: ['Saved scans', 'Reopen by ID', 'Export reports'],
  },
];

export const environments: Record<string, { id: string; name: string; tagline: string; items: EnvItem[] }> = {
  scanner: {
    id: 'scanner',
    name: 'Package Scanner',
    tagline: 'Check one package before you trust it.',
    items: [
      { path: '/scanner/scan', label: 'Scan', icon: 'scanner', description: 'Upload archive or folder' },
      { path: '/scanner/result', label: 'Result', icon: 'workspace', description: 'Verdict and summary' },
      { path: '/scanner/evidence', label: 'Evidence', icon: 'evidence', description: 'Findings table' },
      { path: '/scanner/score', label: 'Score', icon: 'explain', description: 'Model score status' },
      { path: '/scanner/report', label: 'Report', icon: 'reports', description: 'Export JSON or Markdown' },
    ],
  },
  hunter: {
    id: 'hunter',
    name: 'Environment Hunter',
    tagline: 'Look for threats already installed.',
    items: [
      { path: '/hunter/scan', label: 'Scan', icon: 'environment', description: 'Inspect local Python environments' },
      { path: '/hunter/report', label: 'Report', icon: 'findings', description: 'Hunter findings and coverage' },
    ],
  },
  history: {
    id: 'history',
    name: 'History and Reports',
    tagline: 'Every scan and every export in one place.',
    items: [
      { path: '/history/history', label: 'History', icon: 'history', description: 'Saved scan records' },
      { path: '/history/reports', label: 'Reports', icon: 'reports', description: 'Export saved scans' },
    ],
  },
  extension: {
    id: 'extension',
    name: 'SPIDER Extension',
    tagline: 'Check a package before you install it.',
    items: [
      { path: '/extension', label: 'Extension', icon: 'shield', description: 'Download and how it works' },
    ],
  },
  learn: {
    id: 'learn',
    name: 'How packages attack',
    tagline: 'How a malicious package gets in and what it does.',
    items: [
      { path: '/learn', label: 'Guide', icon: 'evidence', description: 'Attack vectors in four steps' },
    ],
  },
  research: {
    id: 'research',
    name: 'Research Lab',
    tagline: 'Measured numbers and limits.',
    items: [
      { path: '/research', label: 'Results', icon: 'models', description: 'Corpus, validation, and evasion results' },
      { path: '/research/overview', label: 'Overview', icon: 'overview', description: 'Corpus scale and scope' },
      { path: '/research/dataset', label: 'Dataset', icon: 'workspace', description: 'Corpus numbers and distributions' },
      { path: '/research/signals', label: 'Signals', icon: 'evidence', description: 'Signal rates and size confounder' },
      { path: '/research/models', label: 'Models', icon: 'models', description: 'Model metrics review state' },
      { path: '/research/limits', label: 'Limits', icon: 'explain', description: 'Static analysis boundaries' },
    ],
  },
  redteam: {
    id: 'redteam',
    name: 'Red Team',
    tagline: 'Controlled static evasion testing.',
    items: [
      { path: '/redteam/overview', label: 'Overview', icon: 'overview', description: 'Controlled static analysis scope' },
      { path: '/redteam/batch', label: 'Batch', icon: 'evidence', description: '12-sample adversarial verification batch' },
      { path: '/redteam/techniques', label: 'Techniques', icon: 'lab', description: 'Evasion technique glossary' },
      { path: '/redteam/limits', label: 'Limits', icon: 'explain', description: 'Payload caveats and attack boundaries' },
    ],
  },
  settings: {
    id: 'settings',
    name: 'Settings',
    tagline: 'Theme and motion preferences.',
    items: [
      { path: '/settings', label: 'Settings', icon: 'settings', description: 'Preferences' },
    ],
  },
};

export function environmentFor(path: string): { id: string; name: string; tagline: string; items: EnvItem[] } | undefined {
  if (path.startsWith('/scanner')) return environments.scanner;
  if (path.startsWith('/hunter')) return environments.hunter;
  if (path.startsWith('/history')) return environments.history;
  if (path === '/extension') return environments.extension;
  if (path === '/learn') return environments.learn;
  if (path.startsWith('/research')) return environments.research;
  if (path.startsWith('/redteam')) return environments.redteam;
  if (path === '/settings') return environments.settings;
  return undefined;
}
