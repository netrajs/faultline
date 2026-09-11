import { useEffect, useRef } from 'react';

import { prefersReducedMotion } from '@/theme/motion';
import './StarField.css';

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  hue: 'cyan' | 'cyanBright' | 'purple';
}

const PARTICLE_COUNT = 64;
const LINK_DISTANCE = 150;
const LINK_DISTANCE_SQ = LINK_DISTANCE * LINK_DISTANCE;

function readColor(name: string, fallback: string): string {
  if (typeof getComputedStyle !== 'function') return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

function makeParticle(width: number, height: number): Particle {
  // Slower particles are drawn smaller and dimmer, faster ones larger and
  // brighter -- the same depth cue real parallax star drift relies on,
  // without an actual third dimension to compute.
  const speed = 0.05 + Math.random() * 0.16;
  const angle = Math.random() * Math.PI * 2;
  const hues: Particle['hue'][] = ['cyan', 'cyan', 'cyanBright', 'purple'];
  const hue = hues[Math.floor(Math.random() * hues.length)] ?? 'cyan';
  return {
    x: Math.random() * width,
    y: Math.random() * height,
    vx: Math.cos(angle) * speed,
    vy: Math.sin(angle) * speed,
    radius: 1 + speed * 8,
    hue,
  };
}

/**
 * An ambient, always-on drifting field behind the whole app -- the same
 * network-graph motif as the intro video and the dashboard's static SVG,
 * but continuous and app-wide rather than a one-time or single-page moment.
 * Canvas rather than DOM nodes so ~64 slowly-drifting points plus their
 * occasional connecting lines cost one repaint a frame instead of dozens of
 * animated elements. Frozen to a single static frame under
 * prefers-reduced-motion, matching how every other animation in the app
 * behaves under that setting.
 */
export function StarField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduced = prefersReducedMotion();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let width = window.innerWidth;
    let height = window.innerHeight;
    let particles: Particle[] = [];
    let colors: Record<Particle['hue'], string>;

    const readColors = () => ({
      cyan: readColor('--accent-cyan', '#0284c7'),
      cyanBright: readColor('--accent-cyan-bright', '#38bdf8'),
      purple: readColor('--accent-purple', '#7c3aed'),
    });

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const init = () => {
      colors = readColors();
      resize();
      particles = Array.from({ length: PARTICLE_COUNT }, () => makeParticle(width, height));
    };

    const drawFrame = () => {
      ctx.clearRect(0, 0, width, height);

      // Links first, so the dots paint cleanly over their own connecting lines.
      for (let i = 0; i < particles.length; i += 1) {
        for (let j = i + 1; j < particles.length; j += 1) {
          const a = particles[i]!;
          const b = particles[j]!;
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const distSq = dx * dx + dy * dy;
          if (distSq > LINK_DISTANCE_SQ) continue;
          const alpha = (1 - distSq / LINK_DISTANCE_SQ) * 0.16;
          ctx.strokeStyle = colors.cyan;
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      for (const p of particles) {
        ctx.globalAlpha = 0.35 + p.radius * 0.05;
        ctx.fillStyle = colors[p.hue];
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
    };

    const step = () => {
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        // Wrap at the edges with a little slack so a particle doesn't pop
        // back into view mid-canvas -- it drifts fully off before returning.
        if (p.x < -20) p.x = width + 20;
        if (p.x > width + 20) p.x = -20;
        if (p.y < -20) p.y = height + 20;
        if (p.y > height + 20) p.y = -20;
      }
      drawFrame();
      frame = requestAnimationFrame(step);
    };

    let frame = 0;
    init();
    if (reduced) {
      drawFrame();
    } else {
      frame = requestAnimationFrame(step);
    }

    const onResize = () => {
      const prevWidth = width;
      const prevHeight = height;
      resize();
      // Rescale existing positions rather than regenerating the field, so a
      // resize doesn't reset every particle's drift.
      const sx = width / prevWidth;
      const sy = height / prevHeight;
      for (const p of particles) {
        p.x *= sx;
        p.y *= sy;
      }
      if (reduced) drawFrame();
    };
    window.addEventListener('resize', onResize);

    return () => {
      window.removeEventListener('resize', onResize);
      if (frame) cancelAnimationFrame(frame);
    };
  }, []);

  return <canvas ref={canvasRef} className="star-field" aria-hidden="true" />;
}
