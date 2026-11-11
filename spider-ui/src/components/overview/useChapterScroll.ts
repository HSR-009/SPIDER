import { useEffect, useRef, useState, type RefObject } from 'react';

/** Pure scroll math for the entry stage. Native scroll only: no scroll
 * hijacking, no IntersectionObserver dependency, no timers beyond rAF. */
export function chapterFromProgress(progress: number, count: number): number {
  if (!Number.isFinite(progress) || !Number.isFinite(count) || count < 1) return 0;
  const bounded = Math.min(1, Math.max(0, progress));
  return Math.min(count - 1, Math.floor(bounded * count));
}

export function stageProgress(top: number, travel: number): number {
  if (!Number.isFinite(top) || !Number.isFinite(travel) || travel <= 0) return 0;
  return Math.min(1, Math.max(0, -top / travel));
}

export function splitCharacters(text: string): string[] {
  return Array.from(text);
}

export interface ChapterScrollState { index: number; blend: number; progress: number }

/** Sticky-track progress: the page scrolls natively while the stage stays pinned. */
export function useChapterScroll(count: number): ChapterScrollState & { trackRef: RefObject<HTMLDivElement> } {
  const trackRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<ChapterScrollState>({ index: 0, blend: 0, progress: 0 });
  useEffect(() => {
    let frame = 0;
    const measure = () => {
      frame = 0;
      const track = trackRef.current;
      if (!track) return;
      const travel = track.offsetHeight - window.innerHeight;
      const progress = stageProgress(track.getBoundingClientRect().top, travel);
      const scaled = progress * count;
      const index = chapterFromProgress(progress, count);
      setState({ index, blend: scaled - index, progress });
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(measure); };
    measure();
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    return () => {
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      if (frame) cancelAnimationFrame(frame);
    };
  }, [count]);
  return { trackRef, ...state };
}
