import type { HuntResult, ScanRecord, SpiderBackend } from './types';
import { parseRecord } from './parseRecord';

export class HttpSpiderBackend implements SpiderBackend {
  private base: string;

  constructor(base: string = '') {
    this.base = base;
  }

  async scan(
    input: File | { path: string },
    onProgress?: (p: { stage: string; done?: number; total?: number }) => void,
  ): Promise<{ scan_id: string }> {
    // TODO: wire to the SPIDER API (/api/scan)
    onProgress?.({ stage: 'uploading' });
    const formData = new FormData();
    if (typeof File !== 'undefined' && input instanceof File) {
      formData.append('archive', input);
    } else {
      formData.append('path', (input as { path: string }).path);
    }

    const res = await fetch(`${this.base}/api/scan`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) throw new Error(`Scan request failed: ${res.statusText}`);
    const data = await res.json();
    return { scan_id: data.scan_id };
  }

  async getScan(id: string): Promise<ScanRecord> {
    // TODO: wire to the SPIDER API (/api/scans/:id)
    const res = await fetch(`${this.base}/api/scans/${encodeURIComponent(id)}`);
    if (!res.ok) {
      if (res.status === 404) throw new Error('This exact record is unavailable.');
      throw new Error(`Failed to fetch scan: ${res.statusText}`);
    }
    const data = await res.json();
    return parseRecord(data);
  }

  async listScans(): Promise<ScanRecord[]> {
    // TODO: wire to the SPIDER API (/api/scans)
    const res = await fetch(`${this.base}/api/scans`);
    if (!res.ok) throw new Error(`Failed to list scans: ${res.statusText}`);
    const data = await res.json();
    if (!Array.isArray(data)) throw new Error('Invalid scan list from server');
    return data.map(item => parseRecord(item));
  }

  async hunterRoots(): Promise<string[]> {
    // TODO: wire to the SPIDER API (/api/hunter/roots)
    const res = await fetch(`${this.base}/api/hunter/roots`);
    if (!res.ok) throw new Error(`Failed to get roots: ${res.statusText}`);
    return res.json();
  }

  async hunt(
    opts: { roots?: string[] },
    onProgress?: (p: { stage: string }) => void,
  ): Promise<HuntResult> {
    // TODO: wire to the SPIDER API (/api/hunt)
    onProgress?.({ stage: 'hunting' });
    const res = await fetch(`${this.base}/api/hunt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opts),
    });
    if (!res.ok) throw new Error(`Hunt failed: ${res.statusText}`);
    return res.json();
  }

  async allow(sha256: string, note?: string): Promise<void> {
    // TODO: wire to the SPIDER API (/api/hunter/allow)
    const res = await fetch(`${this.base}/api/hunter/allow`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sha256, note }),
    });
    if (!res.ok) throw new Error(`Allow request failed: ${res.statusText}`);
  }

  async getResults(): Promise<unknown> {
    // TODO: wire to the SPIDER API (/api/results)
    const res = await fetch(`${this.base}/api/results`);
    if (!res.ok) throw new Error(`Failed to get research results: ${res.statusText}`);
    return res.json();
  }
}

