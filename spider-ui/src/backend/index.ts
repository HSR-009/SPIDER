import type { SpiderBackend } from './types';
import { MockSpiderBackend } from './mock';
import { HttpSpiderBackend } from './http';

const mode = (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_BACKEND || 'mock';

export const isMockBackend = mode === 'mock';
export const backend: SpiderBackend = mode === 'http' ? new HttpSpiderBackend() : new MockSpiderBackend();

export * from './types';
export * from './parseRecord';

