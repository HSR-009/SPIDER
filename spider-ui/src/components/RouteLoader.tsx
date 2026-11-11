import { useEffect, useState } from 'react';
import { SpiderMark } from './SpiderMark';
import { useWorkbenchStore } from '../state/workbench';

interface RouteLoaderProps {
  destinationName: string;
  onFinish?: () => void;
}

export function RouteLoader({ destinationName, onFinish }: RouteLoaderProps) {
  const reducedMotion = useWorkbenchStore((s) => s.reducedMotion);
  const [fading, setFading] = useState(false);

  useEffect(() => {
    // Show for 750ms then start fading out
    const duration = reducedMotion ? 150 : 750;
    const fadeTimer = setTimeout(() => {
      setFading(true);
    }, duration);

    // Call onFinish when fade transition finishes (150ms later)
    const finishTimer = setTimeout(() => {
      onFinish?.();
    }, duration + 150);

    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(finishTimer);
    };
  }, [reducedMotion, onFinish]);

  return (
    <div
      className={`route-loader ${fading ? 'route-loader--fading' : ''}`}
      role="status"
      aria-live="polite"
    >
      <SpiderMark className="route-loader__mark" />
      <span className="route-loader__label">Opening {destinationName}</span>
    </div>
  );
}

