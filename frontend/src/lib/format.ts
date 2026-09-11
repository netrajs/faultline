/** Small formatting helpers shared across screens. Never invents a value -- only reshapes one already returned by the API. */

export function formatScore(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return value.toFixed(digits);
}

export function formatPercent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return `${(value * 100).toFixed(digits)}%`;
}

export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return value.toLocaleString();
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return '—';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

/** Shortens a long content-hash id for display; the full value stays available via title. */
export function shortId(id: string | null | undefined, keep = 10): string {
  if (!id) return '—';
  if (id.length <= keep * 2 + 1) return id;
  return `${id.slice(0, keep)}…${id.slice(-4)}`;
}

export function formatBeta(beta: number | null | undefined): string {
  if (beta === null || beta === undefined || Number.isNaN(beta)) return '—';
  const sign = beta > 0 ? '+' : '';
  return `${sign}${beta.toFixed(2)}`;
}

export function isTruthy(flag: 0 | 1 | boolean | null | undefined): boolean {
  return flag === 1 || flag === true;
}
