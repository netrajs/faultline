/**
 * Thin fetch wrapper shared by every typed query hook.
 *
 * The base URL is a Vite env var, never a literal: in development the value
 * is left at its default ('/api') and Vite's dev-server proxy (see
 * vite.config.ts) forwards it to the API process, so the browser only ever
 * talks to one origin. In a built deployment, VITE_API_BASE_URL can point at
 * a different origin entirely without touching source.
 */

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '/api').replace(/\/+$/, '');

export type QueryParamValue = string | number | boolean | undefined | null;

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(message: string, status: number, detail?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

/** True when this looks like the API being entirely unreachable (no server, no network, CORS). */
export function isNetworkError(error: unknown): boolean {
  return !(error instanceof ApiError);
}

function buildQuery(params?: Record<string, QueryParamValue>): string {
  if (!params) return '';
  const usp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    usp.set(key, String(value));
  }
  const qs = usp.toString();
  return qs ? `?${qs}` : '';
}

async function parseErrorBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

function messageFromDetail(detail: unknown, fallback: string): string {
  if (detail && typeof detail === 'object' && 'detail' in detail) {
    const value = (detail as { detail: unknown }).detail;
    if (typeof value === 'string') return value;
  }
  return fallback;
}

export async function apiGet<T>(path: string, params?: Record<string, QueryParamValue>): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}${buildQuery(params)}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    const detail = await parseErrorBody(response);
    throw new ApiError(messageFromDetail(detail, response.statusText), response.status, detail);
  }

  return (await response.json()) as T;
}

export async function apiPost<T>(path: string, body?: unknown, params?: Record<string, QueryParamValue>): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}${buildQuery(params)}`, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (!response.ok) {
    const detail = await parseErrorBody(response);
    throw new ApiError(messageFromDetail(detail, response.statusText), response.status, detail);
  }

  return (await response.json()) as T;
}
