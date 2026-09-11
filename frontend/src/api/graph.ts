/**
 * Response shapes and query hooks for /api/graph/* (see backend/app/routers/graph.py).
 *
 * Mirrors the raw Cypher/SQL row dicts the backend returns, same as paths.ts
 * and risk.ts -- no renaming layer between the wire shape and the type here.
 */

import { useMutation, useQuery } from '@tanstack/react-query';

import { apiGet, apiPost } from './client';

// ---------------------------------------------------------------------------
// /api/graph/version
// ---------------------------------------------------------------------------

export interface GraphVersion {
  id: number;
  label: string;
  origin: string;
  seed: number | null;
  generator_version: string | null;
  canonical_hash: string;
  node_count: number;
  edge_count: number;
  created_at: string | null;
}

// ---------------------------------------------------------------------------
// /api/graph/stats
// ---------------------------------------------------------------------------

export interface GraphStats {
  graph_version: number;
  node_count: number;
  edge_count: number;
  crown_jewels: number;
  by_kind: Record<string, number>;
  by_edge_type: Record<string, number>;
}

// ---------------------------------------------------------------------------
// /api/graph/nodes, /api/graph/node/{id}
// ---------------------------------------------------------------------------

export interface GraphNodeItem {
  node_id: string;
  kind: string;
  name: string;
  display_name: string | null;
  is_crown_jewel: boolean;
  criticality: string | null;
  classification: string | null;
  attrs: Record<string, unknown>;
}

export interface GraphNodesResponse {
  items: GraphNodeItem[];
  total: number;
  graph_version: number;
}

export interface GraphNodeEdge {
  edge_id: string;
  edge_type: string;
  src_id: string;
  dst_id: string;
  attrs: Record<string, unknown>;
  neighbour_id: string;
  neighbour_name: string;
  neighbour_kind: string;
  neighbour_crown_jewel: boolean;
}

export interface GraphNodeDetail {
  node: GraphNodeItem;
  edges: GraphNodeEdge[];
  graph_version: number;
}

// ---------------------------------------------------------------------------
// /api/graph/subgraph
// ---------------------------------------------------------------------------

export interface GraphSubgraphNode {
  node_id: string;
  kind: string;
  name: string;
  is_crown_jewel: boolean;
  criticality: string | null;
}

export interface GraphSubgraphEdge {
  edge_id: string;
  edge_type: string;
  src_id: string;
  dst_id: string;
}

export interface GraphSubgraphResponse {
  nodes: GraphSubgraphNode[];
  edges: GraphSubgraphEdge[];
  graph_version: number;
  center: string;
  depth: number;
}

// ---------------------------------------------------------------------------
// /api/graph/saved-queries
// ---------------------------------------------------------------------------

export interface SavedQuery {
  code: string;
  label: string;
  description: string;
  cypher: string;
  purpose: string;
  parameters: string;
  sort_order: number;
}

export type SavedQueryRow = Record<string, unknown>;

export interface SavedQueryRunResponse {
  code: string;
  label: string;
  purpose: string;
  graph_version: number;
  rows: SavedQueryRow[];
  row_count: number;
  truncated: boolean;
}

// ---------------------------------------------------------------------------
// /api/graph/contrast
// ---------------------------------------------------------------------------

export interface ContrastRejectionReason {
  reason_code: string;
  count: number;
  example: string;
}

export interface ContrastResponse {
  graph_version: number;
  analysis_run_id?: number;
  naive_candidate_count: number;
  engine_path_count: number | null;
  rejected_count?: number;
  crown_jewels_reached?: number;
  discovery_ms?: number | null;
  rejection_reasons?: ContrastRejectionReason[];
  message?: string;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useGraphVersion() {
  return useQuery({
    queryKey: ['graph', 'version'],
    queryFn: () => apiGet<GraphVersion>('/graph/version'),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}

export function useGraphStats() {
  return useQuery({
    queryKey: ['graph', 'stats'],
    queryFn: () => apiGet<GraphStats>('/graph/stats'),
    retry: 1,
  });
}

export interface GraphNodeFilters {
  kind?: string;
  q?: string;
  crownJewelsOnly?: boolean;
  limit?: number;
  offset?: number;
}

export function useGraphNodes(filters: GraphNodeFilters = {}) {
  const { kind, q, crownJewelsOnly, limit = 50, offset = 0 } = filters;
  return useQuery({
    queryKey: ['graph', 'nodes', { kind, q, crownJewelsOnly, limit, offset }],
    queryFn: () =>
      apiGet<GraphNodesResponse>('/graph/nodes', {
        kind,
        q,
        crown_jewels_only: crownJewelsOnly,
        limit,
        offset,
      }),
    retry: 1,
  });
}

export function useNodeDetail(nodeId: string | undefined) {
  return useQuery({
    queryKey: ['graph', 'node', nodeId],
    queryFn: () => apiGet<GraphNodeDetail>(`/graph/node/${encodeURIComponent(nodeId as string)}`),
    enabled: Boolean(nodeId),
    retry: 1,
  });
}

export function useSubgraph(center: string | undefined, depth = 1, limit = 300) {
  return useQuery({
    queryKey: ['graph', 'subgraph', center, depth, limit],
    queryFn: () => apiGet<GraphSubgraphResponse>('/graph/subgraph', { center, depth, limit }),
    enabled: Boolean(center),
    retry: 1,
  });
}

export function useSavedQueries() {
  return useQuery({
    queryKey: ['graph', 'saved-queries'],
    queryFn: () => apiGet<SavedQuery[]>('/graph/saved-queries'),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}

export function useRunSavedQuery() {
  return useMutation({
    mutationFn: ({ code, limit = 200 }: { code: string; limit?: number }) =>
      apiPost<SavedQueryRunResponse>(`/graph/saved-queries/${encodeURIComponent(code)}/run`, undefined, { limit }),
  });
}

export function useContrast() {
  return useQuery({
    queryKey: ['graph', 'contrast'],
    queryFn: () => apiGet<ContrastResponse>('/graph/contrast'),
    retry: 1,
  });
}
