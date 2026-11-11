import { create } from 'zustand';
import type { HuntResult, ScanRecord } from '../backend/types';
import { backend } from '../backend';

export interface WorkbenchStoreState {
  // Current scanner record
  currentRecord: ScanRecord | null;
  currentRecordLoading: boolean;
  currentRecordError: string | null;

  // Tracked scanning progress
  isScanning: boolean;
  scanProgress: { stage: string; done?: number; total?: number } | null;
  scanError: string | null;

  // Hunter state
  hunterRoots: string[];
  selectedRoots: string[];
  customRoot: string;
  isHunting: boolean;
  huntProgress: { stage: string } | null;
  lastHuntResult: HuntResult | null;
  huntError: string | null;

  // History state
  history: ScanRecord[];
  historyLoading: boolean;
  historyError: string | null;

  // Display / preferences
  reducedMotion: boolean;
  quality: 'auto' | 'high' | 'medium' | 'low' | 'off';

  // Actions
  setReducedMotion: (reduced: boolean) => void;
  setQuality: (quality: 'auto' | 'high' | 'medium' | 'low' | 'off') => void;
  loadScanRecord: (id: string) => Promise<ScanRecord | null>;
  startScan: (input: File | { path: string }) => Promise<string | null>;
  loadHistory: () => Promise<void>;
  loadHunterRoots: () => Promise<void>;
  toggleRootSelection: (root: string) => void;
  setCustomRoot: (path: string) => void;
  startHunt: (customRoots?: string[]) => Promise<HuntResult | null>;
}

export const useWorkbenchStore = create<WorkbenchStoreState>((set, get) => ({
  currentRecord: null,
  currentRecordLoading: false,
  currentRecordError: null,

  isScanning: false,
  scanProgress: null,
  scanError: null,

  hunterRoots: [],
  selectedRoots: [],
  customRoot: '',
  isHunting: false,
  huntProgress: null,
  lastHuntResult: null,
  huntError: null,

  history: [],
  historyLoading: false,
  historyError: null,

  reducedMotion: false,
  quality: 'auto',

  setReducedMotion: (reducedMotion) => set({ reducedMotion }),
  setQuality: (quality) => set({ quality }),

  loadScanRecord: async (id: string) => {
    set({ currentRecordLoading: true, currentRecordError: null });
    try {
      const record = await backend.getScan(id);
      set({ currentRecord: record, currentRecordLoading: false });
      return record;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Record unavailable';
      set({ currentRecord: null, currentRecordLoading: false, currentRecordError: msg });
      return null;
    }
  },

  startScan: async (input: File | { path: string }) => {
    set({ isScanning: true, scanProgress: { stage: 'starting' }, scanError: null });
    try {
      const { scan_id } = await backend.scan(input, (progress) => {
        set({ scanProgress: progress });
      });
      const record = await backend.getScan(scan_id);
      set({
        isScanning: false,
        scanProgress: null,
        currentRecord: record,
      });
      // Refresh history silently
      void get().loadHistory();
      return scan_id;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Scan failed';
      set({ isScanning: false, scanProgress: null, scanError: msg });
      return null;
    }
  },

  loadHistory: async () => {
    set({ historyLoading: true, historyError: null });
    try {
      const records = await backend.listScans();
      set({ history: records, historyLoading: false });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load history';
      set({ historyLoading: false, historyError: msg });
    }
  },

  loadHunterRoots: async () => {
    try {
      const roots = await backend.hunterRoots();
      set({ hunterRoots: roots, selectedRoots: roots });
    } catch {
      // ignore
    }
  },

  toggleRootSelection: (root: string) => {
    const { selectedRoots } = get();
    if (selectedRoots.includes(root)) {
      set({ selectedRoots: selectedRoots.filter(r => r !== root) });
    } else {
      set({ selectedRoots: [...selectedRoots, root] });
    }
  },

  setCustomRoot: (customRoot: string) => set({ customRoot }),

  startHunt: async (customRoots?: string[]) => {
    set({ isHunting: true, huntProgress: { stage: 'starting' }, huntError: null });
    try {
      const roots = customRoots && customRoots.length > 0
        ? customRoots
        : get().selectedRoots;
      const result = await backend.hunt({ roots }, (p) => {
        set({ huntProgress: p });
      });
      set({
        isHunting: false,
        huntProgress: null,
        lastHuntResult: result,
      });
      return result;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Hunter scan failed';
      set({ isHunting: false, huntProgress: null, huntError: msg });
      return null;
    }
  },
}));
