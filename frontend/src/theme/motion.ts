/**
 * Mirrors tokens.css's duration/easing custom properties for framer-motion.
 *
 * tokens.css collapses its own durations under `prefers-reduced-motion:
 * reduce`, but that only affects CSS transitions/animations -- framer-motion
 * reads numbers from JS, so this layer re-implements the same collapse by
 * checking the media query directly. Values are read from the live computed
 * style rather than duplicated as literals, so retuning a duration in
 * tokens.css never has to be echoed here by hand.
 */

export type DurationToken = 'instant' | 'fast' | 'base' | 'slow';

const CSS_VAR: Record<DurationToken, string> = {
  instant: '--duration-instant',
  fast: '--duration-fast',
  base: '--duration-base',
  slow: '--duration-slow',
};

// Used only if the stylesheet has not painted yet (e.g. a unit-less environment).
const FALLBACK_MS: Record<DurationToken, number> = { instant: 90, fast: 160, base: 240, slow: 500 };
const FALLBACK_STAGGER_MS = 80;

export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function readMsVar(varName: string, fallbackMs: number): number {
  if (typeof window === 'undefined' || typeof getComputedStyle !== 'function') return fallbackMs;
  const raw = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
  const parsed = parseFloat(raw);
  return Number.isFinite(parsed) ? parsed : fallbackMs;
}

/** Duration in seconds, ready to hand to a framer-motion `transition`. */
export function duration(token: DurationToken): number {
  if (prefersReducedMotion()) return 0.001;
  return readMsVar(CSS_VAR[token], FALLBACK_MS[token]) / 1000;
}

/** Per-child stagger delay in seconds, for `staggerChildren`. */
export function staggerStep(): number {
  if (prefersReducedMotion()) return 0;
  return readMsVar('--stagger-step', FALLBACK_STAGGER_MS) / 1000;
}

export const easeOutExpo = [0.16, 1, 0.3, 1] as const;
export const easeStandard = [0.4, 0, 0.2, 1] as const;

/** Entrance used by cards, list rows and panels throughout the app. */
export function fadeInUp(delay = 0) {
  return {
    initial: { opacity: 0, y: 12 },
    animate: { opacity: 1, y: 0, transition: { duration: duration('base'), ease: easeOutExpo, delay } },
    exit: { opacity: 0, y: -8, transition: { duration: duration('fast'), ease: easeStandard } },
  };
}

/** Simple crossfade, used for route transitions and swapped panel content. */
export function fade(delay = 0) {
  return {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: duration('base'), ease: easeStandard, delay } },
    exit: { opacity: 0, transition: { duration: duration('fast'), ease: easeStandard } },
  };
}

/** Wraps a list of children so each staggers in after the last. */
export function staggerContainer(step = staggerStep()) {
  return {
    initial: {},
    animate: { transition: { staggerChildren: step } },
  };
}
