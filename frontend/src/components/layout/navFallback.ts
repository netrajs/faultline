import type { NavItem } from '@/api/types';

/**
 * Used only when /api/config/nav cannot be reached at all (no backend, no
 * network) -- chrome that keeps the shell navigable during an outage, not a
 * substitute for the DB-resident navigation. It is deliberately limited to
 * the routes this build actually implements.
 */
export const FALLBACK_NAV_ITEMS: NavItem[] = [
  { code: 'dashboard', label: 'Dashboard', route: '/', icon: 'chart-bar', description: 'Current risk posture at a glance.', sort_order: 1 },
  { code: 'paths', label: 'Attack paths', route: '/paths', icon: 'route', description: 'Discovered paths, ranked, with their derivations.', sort_order: 2 },
  { code: 'graph', label: 'Graph', route: '/graph', icon: 'topology-star-3', description: 'Explore the identity and asset graph.', sort_order: 3 },
];

/** Routes this build actually renders, used to decide whether a nav item is live or a stub. */
export const IMPLEMENTED_ROUTES = new Set(['/', '/paths', '/graph']);

export function findActiveNavItem(pathname: string, items: NavItem[]): NavItem | undefined {
  if (items.length === 0) return undefined;
  const exact = items.find((item) => item.route === pathname);
  if (exact) return exact;
  // Nested routes (e.g. /paths/:pathId) belong to their parent's nav entry.
  const byPrefix = items
    .filter((item) => item.route !== '/' && pathname.startsWith(item.route))
    .sort((a, b) => b.route.length - a.route.length)[0];
  return byPrefix;
}
