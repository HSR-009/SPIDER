import { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useWorkbenchStore } from '../state/workbench';
import { SpiderMark } from './SpiderMark';

export type Quality = 'auto' | 'high' | 'medium' | 'low' | 'off';
export type Vec3 = { x: number; y: number; z: number };
export const clamp = (value: number, low: number, high: number) => Math.min(high, Math.max(low, value));
const mix = (a: number, b: number, t: number) => a + (b - a) * t;
const blend = (a: Vec3, b: Vec3, t: number): Vec3 => ({ x: mix(a.x, b.x, t), y: mix(a.y, b.y, t), z: mix(a.z, b.z, t) });
const distance = (a: Vec3, b: Vec3) => Math.hypot(a.x - b.x, a.y - b.y, a.z - b.z);

/** Two-link triangle with clamped reach. A third visible tarsus stays on the web. */
export function solveLeg(hip: Vec3, target: Vec3, upper = 0.48, lower = 0.56): { knee: Vec3; foot: Vec3 } {
  const raw = distance(hip, target), d = clamp(raw, Math.abs(upper - lower) + 0.001, upper + lower - 0.001);
  const direction = raw < 1e-8 ? { x: 1, y: 0, z: 0 } : { x: (target.x - hip.x) / raw, y: (target.y - hip.y) / raw, z: (target.z - hip.z) / raw };
  const foot = { x: hip.x + direction.x * d, y: hip.y + direction.y * d, z: hip.z + direction.z * d };
  const along = (upper * upper - lower * lower + d * d) / (2 * d);
  const bend = Math.sqrt(Math.max(0, upper * upper - along * along));
  const horizontal = Math.hypot(direction.x, direction.z);
  const normal = horizontal < 1e-8 ? { x: 1, y: 0, z: 0 } : { x: -direction.x * direction.y / horizontal, y: horizontal, z: -direction.z * direction.y / horizontal };
  return { knee: { x: hip.x + direction.x * along + normal.x * bend, y: hip.y + direction.y * along + normal.y * bend, z: hip.z + direction.z * along + normal.z * bend }, foot };
}

type Camera = { yaw: number; pitch: number; zoom: number; x: number };
export function routeCamera(path: string): Camera {
  if (path === '/scanner' || path.startsWith('/scanner/')) return { yaw: -0.28, pitch: 0.66, zoom: 0.92, x: 0 };
  if (path.startsWith('/hunter/')) return { yaw: 0.6, pitch: 0.55, zoom: 0.78, x: 0.18 };
  if (path === '/research') return { yaw: -0.5, pitch: 0.75, zoom: 0.82, x: -0.15 };
  if (path.startsWith('/history/')) return { yaw: 0.4, pitch: 0.9, zoom: 0.9, x: 0.25 };
  return { yaw: 0.12, pitch: 0.72, zoom: 0.88, x: 0 };
}

function budget(quality: Quality) {
  return quality === 'low' ? { rings: 4, spokes: 12, fps: 20, dpr: 1, hairs: 0 } : quality === 'medium' ? { rings: 6, spokes: 18, fps: 30, dpr: 1.5, hairs: 12 } : { rings: 8, spokes: 24, fps: 45, dpr: 2, hairs: 28 };
}

/** Persistent projected Canvas 2D, not WebGL, not a volumetric material renderer. */
export function SpiderScene() {
  const { pathname } = useLocation();
  const reducedMotion = useWorkbenchStore(s => s.reducedMotion);
  const quality = useWorkbenchStore(s => s.quality);
  const isScanning = useWorkbenchStore(s => s.isScanning);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const latest = useRef({ pathname, isScanning });
  latest.current = { pathname, isScanning };
  const [fallback, setFallback] = useState(false);
  const [effective, setEffective] = useState('medium');
  const invalidate = useRef<() => void>(() => undefined);

  useEffect(() => invalidate.current(), [pathname, isScanning]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || quality === 'off') { setFallback(true); return; }
    let ctx: CanvasRenderingContext2D | null = null;
    try { ctx = canvas.getContext('2d', { alpha: true }); } catch { /* DOM fallback */ }
    if (!ctx) { setFallback(true); return; }
    setFallback(false);
    const context = ctx;
    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const contrastQuery = window.matchMedia('(forced-colors: active)');
    const tier: Quality = quality === 'auto' ? 'medium' : quality;
    let limits = budget(tier), motion = !reducedMotion && !motionQuery.matches && !contrastQuery.matches;
    let width = 1, height = 1, ratio = 1, frame = 0, disposed = false, contextLost = false, visible = !document.hidden, inView = true;
    let previous = 0, time = 0, cost = 0, samples = 0;
    let camera = routeCamera(latest.current.pathname);
    let body: Vec3 = { x: 0, y: 0.24, z: 0 };
    let pointer = { x: 0, y: 0 }, ripple = 0, rippleAge = 0, eventKey = '';
    let gaitGroup = 0, gaitTime = 1;
    const feet: Vec3[] = Array.from({ length: 8 }, (_, i) => ({ x: (i < 4 ? -1 : 1) * (0.62 + 0.1 * Math.sin(i % 4)), y: 0, z: ((i % 4) - 1.5) * 0.37 }));
    let starts = feet.map(v => ({ ...v })), ends = feet.map(v => ({ ...v }));
    setEffective(tier);

    function project(v: Vec3) {
      const cy = Math.cos(camera.yaw), sy = Math.sin(camera.yaw), cp = Math.cos(camera.pitch), sp = Math.sin(camera.pitch);
      const x = v.x * cy - v.z * sy;
      const z = v.x * sy + v.z * cy;
      const y = v.y * cp - z * sp;
      const depth = v.y * sp + z * cp;
      const perspective = 4 / Math.max(2.5, 4 + depth);
      const scale = Math.min(width / 4.5, height / 2.25) * camera.zoom * perspective;
      return { x: width * 0.5 + x * scale + camera.x * width * 0.12, y: height * 0.56 - y * scale, scale, depth };
    }

    function line(points: Vec3[], color: string, weight = 1) {
      context.beginPath(); points.forEach((v, i) => { const p = project(v); if (i === 0) context.moveTo(p.x, p.y); else context.lineTo(p.x, p.y); });
      context.strokeStyle = color; context.lineWidth = weight; context.stroke();
    }

    function oval(position: Vec3, rx: number, ry: number, tint: string) {
      const p = project(position), x = rx * p.scale, y = ry * p.scale;
      const gradient = context.createRadialGradient(p.x - x * 0.3, p.y - y * 0.3, 1, p.x, p.y, Math.max(x, y));
      gradient.addColorStop(0, tint); gradient.addColorStop(0.38, '#302637'); gradient.addColorStop(1, '#09070d');
      context.fillStyle = gradient; context.strokeStyle = '#986680'; context.lineWidth = 1;
      context.beginPath(); context.ellipse(p.x, p.y, x, y, -camera.yaw * 0.2, 0, Math.PI * 2); context.fill(); context.stroke();
    }

    function draw(dt: number) {
      context.setTransform(ratio, 0, 0, ratio, 0, 0); context.clearRect(0, 0, width, height);
      const snapshot = latest.current;
      const target = routeCamera(snapshot.pathname);
      const ease = motion ? 1 - Math.exp(-dt * 4) : 1;
      camera.yaw = mix(camera.yaw, target.yaw, ease);
      camera.pitch = mix(camera.pitch, target.pitch, ease);
      camera.zoom = mix(camera.zoom, target.zoom, ease);
      camera.x = mix(camera.x, target.x, ease);

      if (motion) {
        time += dt;
        gaitTime += dt * 1.5;
        if (gaitTime >= 1) {
          gaitTime = 0;
          gaitGroup = 1 - gaitGroup;
          starts = feet.map(v => ({ ...v }));
          for (let i = 0; i < 8; i++) {
            if ((i % 2) === gaitGroup) {
              const sign = i < 4 ? -1 : 1;
              const slot = i % 4;
              ends[i] = {
                x: sign * (0.62 + 0.08 * Math.sin(time + slot)),
                y: 0,
                z: (slot - 1.5) * 0.37 + 0.05 * Math.cos(time * 0.8),
              };
            }
          }
        }
        for (let i = 0; i < 8; i++) {
          if ((i % 2) === gaitGroup) {
            const stepT = gaitTime;
            const lift = Math.sin(stepT * Math.PI) * 0.06;
            feet[i] = {
              x: mix(starts[i].x, ends[i].x, stepT),
              y: lift,
              z: mix(starts[i].z, ends[i].z, stepT),
            };
          }
        }
      }

      // Draw web background rings
      for (let r = 1; r <= limits.rings; r++) {
        const rad = (r / limits.rings) * 1.2;
        const pts: Vec3[] = [];
        for (let s = 0; s <= limits.spokes; s++) {
          const angle = (s / limits.spokes) * Math.PI * 2;
          pts.push({ x: Math.cos(angle) * rad, y: -0.05, z: Math.sin(angle) * rad });
        }
        line(pts, 'rgba(164, 120, 180, 0.12)', 1);
      }

      // Spider body & legs
      const bodyColor = '#50385c';
      for (let i = 0; i < 8; i++) {
        const side = i < 4 ? -1 : 1;
        const hip: Vec3 = { x: side * 0.1, y: body.y + 0.02, z: ((i % 4) - 1.5) * 0.08 };
        const leg = solveLeg(hip, feet[i]);
        line([hip, leg.knee, leg.foot], 'rgba(196, 150, 210, 0.7)', 1.5);
      }
      oval(body, 0.12, 0.16, bodyColor);
      oval({ x: body.x, y: body.y, z: body.z + 0.18 }, 0.08, 0.08, '#6a4a75');
    }

    function render(timestamp: number) {
      if (disposed) return;
      if (!previous) previous = timestamp;
      const dt = Math.min((timestamp - previous) / 1000, 0.1);
      previous = timestamp;
      draw(dt);
      frame = requestAnimationFrame(render);
    }

    function resize() {
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      width = Math.max(1, rect.width);
      height = Math.max(1, rect.height);
      ratio = window.devicePixelRatio || 1;
      canvas.width = width * ratio;
      canvas.height = height * ratio;
    }

    resize();
    window.addEventListener('resize', resize);
    frame = requestAnimationFrame(render);

    return () => {
      disposed = true;
      cancelAnimationFrame(frame);
      window.removeEventListener('resize', resize);
    };
  }, [quality, reducedMotion]);

  if (fallback) {
    return <div className="spider-scene spider-scene--fallback"><SpiderMark className="spider-mark--fallback" /></div>;
  }

  return (
    <div className="spider-scene" aria-hidden="true">
      <canvas ref={canvasRef} className="spider-canvas" />
    </div>
  );
}
