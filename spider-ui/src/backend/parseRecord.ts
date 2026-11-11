import type { Outcome, ScanRecord } from './types';

export class NotFoundError extends Error {
  constructor(message: string = 'Record unavailable') {
    super(message);
    this.name = 'NotFoundError';
  }
}

const VALID_OUTCOMES: ReadonlySet<Outcome> = new Set([
  'suspicious',
  'none_detected_in_this_scan',
  'unable_to_assess',
]);

/**
 * Checks only:
 * - scan_id is a non-empty string
 * - verdict.outcome is one of the three allowed outcomes
 * - findings is an array
 * - inventory is an object
 * Unknown extra fields are ignored. Throws or returns null if invalid.
 */
export function parseRecord(raw: unknown): ScanRecord {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Record unavailable');
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj.scan_id !== 'string' || !obj.scan_id.trim()) {
    throw new Error('Record unavailable');
  }
  if (!obj.verdict || typeof obj.verdict !== 'object') {
    throw new Error('Record unavailable');
  }
  const verdictObj = obj.verdict as Record<string, unknown>;
  if (!VALID_OUTCOMES.has(verdictObj.outcome as Outcome)) {
    throw new Error('Record unavailable');
  }
  if (!Array.isArray(obj.findings)) {
    throw new Error('Record unavailable');
  }
  if (!obj.inventory || typeof obj.inventory !== 'object' || Array.isArray(obj.inventory)) {
    throw new Error('Record unavailable');
  }

  // Construct ScanRecord cleanly with known fields, ignoring unknown extra properties
  return {
    scan_id: obj.scan_id as string,
    target: obj.target as ScanRecord['target'],
    created_at: typeof obj.created_at === 'string' ? obj.created_at : undefined,
    verdict: {
      outcome: verdictObj.outcome as Outcome,
      reasons: Array.isArray(verdictObj.reasons) ? (verdictObj.reasons as string[]) : [],
      review_recommended: typeof verdictObj.review_recommended === 'boolean' ? verdictObj.review_recommended : undefined,
      limitations: Array.isArray(verdictObj.limitations) ? (verdictObj.limitations as string[]) : undefined,
    },
    findings: obj.findings as ScanRecord['findings'],
    inventory: obj.inventory as ScanRecord['inventory'],
    ml: obj.ml as ScanRecord['ml'],
  };
}

export function formatVerdictOutcome(outcome: Outcome): string {
  switch (outcome) {
    case 'suspicious':
      return 'Suspicious';
    case 'none_detected_in_this_scan':
      return 'None detected in this scan';
    case 'unable_to_assess':
      return 'Unable to assess';
  }
}

