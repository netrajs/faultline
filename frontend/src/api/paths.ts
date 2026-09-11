import { useQuery } from '@tanstack/react-query';

import { apiGet } from './client';
import type { ChokepointsResponse, PathDetailResponse, PathListResponse, PathNode } from './types';

export interface PathFilters {
  tier?: string;
  crownJewelsOnly?: boolean;
  maxHops?: number;
  runId?: number;
  limit?: number;
  offset?: number;
}

export function usePaths(filters: PathFilters = {}) {
  const { tier, crownJewelsOnly, maxHops, runId, limit = 50, offset = 0 } = filters;
  return useQuery({
    queryKey: ['paths', { tier, crownJewelsOnly, maxHops, runId, limit, offset }],
    queryFn: () =>
      apiGet<PathListResponse>('/paths', {
        tier,
        crown_jewels_only: crownJewelsOnly,
        max_hops: maxHops,
        run_id: runId,
        limit,
        offset,
      }),
    retry: 1,
  });
}

export function usePathDetail(pathId: string | undefined, runId?: number) {
  return useQuery({
    queryKey: ['path-detail', pathId, runId],
    queryFn: () => apiGet<PathDetailResponse>(`/paths/${encodeURIComponent(pathId as string)}`, { run_id: runId }),
    enabled: Boolean(pathId),
    retry: 1,
  });
}

export function usePathNodes(pathId: string | undefined, runId?: number) {
  return useQuery({
    queryKey: ['path-nodes', pathId, runId],
    queryFn: () => apiGet<PathNode[]>(`/paths/${encodeURIComponent(pathId as string)}/nodes`, { run_id: runId }),
    enabled: Boolean(pathId),
    retry: 1,
  });
}

export function useChokepoints(limit = 20) {
  return useQuery({
    queryKey: ['chokepoints', limit],
    queryFn: () => apiGet<ChokepointsResponse>('/chokepoints', { limit }),
    retry: 1,
  });
}

/** Builds a node_id -> display label lookup from a path's node list. */
export function nodeLabelMap(nodes: PathNode[] | undefined): Map<string, PathNode> {
  const map = new Map<string, PathNode>();
  for (const node of nodes ?? []) map.set(node.node_id, node);
  return map;
}
