/**
 * Writes domain colour onto the document as CSS custom properties, once, at
 * startup.
 *
 * tokens.css deliberately contains no risk-tier, node-kind or edge-type
 * colour: those are configuration (D12), sourced from MySQL through
 * /api/config/risk-tiers and /api/config/vocabularies, never literals in this
 * codebase. This module is the one place that bridges the two: it fetches the
 * config rows and sets `--risk-color-<code>`, `--risk-bg-<code>`,
 * `--node-color-<code>` and `--edge-color-<code>` on <html>, so any component
 * can reference `var(--risk-color-critical, var(--state-neutral))` without
 * knowing where the value came from.
 *
 * If the API is unreachable or nothing has been seeded yet, this fails
 * silently into the neutral chrome tokens already defined in tokens.css --
 * it never invents a colour to fill the gap.
 */

import { apiGet } from '@/api/client';
import type { RiskTierConfig, Vocabularies } from '@/api/types';

const THEME_SOURCE_ATTR = 'data-theme-source';

function setVar(root: HTMLElement, name: string, value: string | null | undefined): void {
  if (!value) return;
  root.style.setProperty(name, value);
}

/** CSS custom property names use the raw config code, so components can build
 * the var name themselves (`--risk-color-${tierCode}`) without a lookup table. */
export function riskColorVar(code: string): string {
  return `var(--risk-color-${code}, var(--state-neutral))`;
}

export function riskBgVar(code: string): string {
  return `var(--risk-bg-${code}, var(--bg-sunken))`;
}

export function nodeColorVar(code: string): string {
  return `var(--node-color-${code}, var(--state-neutral))`;
}

export function edgeColorVar(code: string): string {
  return `var(--edge-color-${code}, var(--state-neutral))`;
}

export async function applyRuntimeTheme(): Promise<void> {
  const root = document.documentElement;
  try {
    const [riskTiers, vocab] = await Promise.all([
      apiGet<RiskTierConfig[]>('/config/risk-tiers'),
      apiGet<Vocabularies>('/config/vocabularies'),
    ]);

    for (const tier of riskTiers) {
      setVar(root, `--risk-color-${tier.code}`, tier.ui_color);
      setVar(root, `--risk-bg-${tier.code}`, tier.ui_bg_color);
    }
    for (const kind of vocab.node_kinds) {
      setVar(root, `--node-color-${kind.code}`, kind.ui_color);
    }
    for (const edge of vocab.edge_types) {
      setVar(root, `--edge-color-${edge.code}`, edge.ui_color);
    }

    root.setAttribute(THEME_SOURCE_ATTR, 'api');
  } catch (error) {
    // No backend reachable, or the reference tables are not seeded yet.
    // Every consumer falls back to a neutral token, so the interface still
    // renders correctly -- just without domain colour until this succeeds.
    root.setAttribute(THEME_SOURCE_ATTR, 'unavailable');
    // eslint-disable-next-line no-console
    console.warn('[faultline] runtime theme unavailable; using neutral fallback tokens.', error);
  }
}
