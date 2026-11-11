import { useEffect, useState } from 'react';
import { useWorkbenchStore } from '../../state/workbench';

export function AnimatedNumber({ value }: { value: number }) {
  const reducedMotion = useWorkbenchStore((state) => state.reducedMotion);
  const [current, setCurrent] = useState(reducedMotion ? value : 0);

  useEffect(() => {
    if (reducedMotion) {
      setCurrent(value);
      return;
    }

    let start = 0;
    const duration = 750;
    const startTime = performance.now();

    const frame = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCurrent(Math.round(eased * value));

      if (progress < 1) {
        requestAnimationFrame(frame);
      }
    };

    const handle = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(handle);
  }, [value, reducedMotion]);

  return <span>{current.toLocaleString()}</span>;
}

