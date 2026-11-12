// types.ts  (shape of SPIDER's real scan records; do not add fields)
export type Outcome = 'suspicious' | 'none_detected_in_this_scan' | 'unable_to_assess';
export interface Finding { severity: string; indicator: string; category: string; file: string;
  span?: { start_line?: number }; explanation?: string; snippet?: string }
export interface ScanRecord {
  scan_id: string;
  target?: { name?: string; version?: string; hash_verified?: boolean | null };
  created_at?: string;
  verdict: { outcome: Outcome; reasons: string[]; review_recommended?: boolean; limitations?: string[] };
  findings: Finding[];
  inventory: { files_total?: number; files_inspected?: number; python_files?: number;
    parse_failures?: unknown[]; uninspected?: unknown[] };
  ml?: { model: string; malicious_probability: number; calibrated?: boolean };
}
export interface HuntItem { severity: string; priority?: number; artifact: string; reason: string;
  path?: string; evidence_snippet?: string; allowlisted?: boolean; dist?: string; version?: string; sha256?: string; }
export interface HuntResult { hunt_id: string; created_at: string; roots: string[];
  distributions_count: number; items: HuntItem[];
  coverage?: { counts?: Record<string, number>; errors?: unknown[] }; limitations?: string[] }
export interface SpiderBackend {
  scan(input: File | { path: string }, onProgress?: (p: {stage: string; done?: number; total?: number}) => void): Promise<{ scan_id: string }>;
  getScan(id: string): Promise<ScanRecord>;       // throws NotFound, never substitutes
  listScans(): Promise<ScanRecord[]>;
  hunterRoots(): Promise<string[]>;
  hunt(opts: { roots?: string[] }, onProgress?: (p: {stage: string}) => void): Promise<HuntResult>;
  allow?(sha256: string, note?: string): Promise<void>;
  explain?(scan_id: string, finding_index?: number): Promise<{ explanation: string; context?: string }>;
  getResults(): Promise<unknown>;                 // results.json shape
}

