import { useEffect, useRef, useState } from 'react';

interface ExperienceMotionState {
  artwork: boolean;
  reducedMotion: boolean;
  systemReduced: boolean;
  paused: boolean;
  visible: boolean;
  inView: boolean;
}

export function experienceMotionMode(state: ExperienceMotionState) {
  if (!state.artwork) return 'off';
  if (state.reducedMotion || state.systemReduced) return 'reduced';
  if (state.paused) return 'paused';
  return state.visible && state.inView ? 'running' : 'suspended';
}

/** Browser visibility controls decoration only, never job tracking or scan state.
 * inView starts true so throttled environments that never deliver an observer
 * callback still run the hero animation; a real off-screen callback suspends it. */
export function useExperienceMotion(artwork: boolean, reducedMotion: boolean) {
  const heroRef = useRef<HTMLElement>(null);
  const [paused, setPaused] = useState(false);
  const [visible, setVisible] = useState(() => typeof document !== 'undefined' && !document.hidden);
  const [inView, setInView] = useState(true);
  const [systemReduced, setSystemReduced] = useState(() => typeof window === 'undefined' || window.matchMedia('(prefers-reduced-motion: reduce)').matches || window.matchMedia('(forced-colors: active)').matches);

  useEffect(() => {
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const contrast = window.matchMedia('(forced-colors: active)');
    const onPreference = () => setSystemReduced(motion.matches || contrast.matches);
    const onVisibility = () => setVisible(!document.hidden);
    onPreference();
    onVisibility();
    motion.addEventListener('change', onPreference);
    contrast.addEventListener('change', onPreference);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      motion.removeEventListener('change', onPreference);
      contrast.removeEventListener('change', onPreference);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  useEffect(() => {
    const hero = heroRef.current;
    if (!hero || !artwork) { setInView(false); return; }
    if (typeof IntersectionObserver === 'undefined') { setInView(true); return; }
    const observer = new IntersectionObserver(entries => {
      const entry = entries.find(item => item.target === hero);
      if (entry) setInView(entry.isIntersecting);
    });
    observer.observe(hero);
    return () => observer.disconnect();
  }, [artwork]);

  return { heroRef, paused, togglePause: () => setPaused(value => !value), mode: experienceMotionMode({ artwork, reducedMotion, systemReduced, paused, visible, inView }) };
}
