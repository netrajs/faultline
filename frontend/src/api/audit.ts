/**
 * Response shapes and query hooks for /api/audit/* (see backend/app/routers/audit.py).
 *
 * Mirrors the raw row dicts the backend returns, same convention as graph.ts
 * and paths.ts -- no renaming layer between the wire shape and the type here.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiGet, apiPost } from './client';

// ---------------------------------------------------------------------------
// /api/audit/actions
// ---------------------------------------------------------------------------

export interface AuditAction {
  code: string;
  label: string;
  description: string;
  is_mutation: 0 | 1;
  ui_color: string;
  sort_order: number;
}

// ---------------------------------------------------------------------------
// /api/audit/entries
// ---------------------------------------------------------------------------

export interface AuditEntry {
  seq: number;
  action_code: string;
  actor: string;
  target_kind: string | null;
  target_id: string | null;
  payload: Record<string, unknown>;
  graph_version_id: number | null;
  scoring_version: string | null;
  risk_before: number | null;
  risk_after: number | null;
  salt_hex: string;
  leaf_hash_hex: string;
  prev_hash_hex: string | null;
  entry_hash_hex: string;
  created_at: string;
}

export interface AuditEntriesResponse {
  items: AuditEntry[];
  total: number;
}

export interface AuditEntryFilters {
  actionCode?: string;
  actor?: string;
  targetKind?: string;
  targetId?: string;
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// /api/audit/checkpoints, /api/audit/anchor
// ---------------------------------------------------------------------------

export type AnchorMode = 'anvil' | 'base-sepolia' | 'polygon-amoy' | 'replay';
export type AnchorStatus = 'pending' | 'confirmed' | 'failed' | 'recorded';

export interface AnchorReceipt {
  id: number;
  checkpoint_epoch: number;
  mode: AnchorMode;
  chain_id: number | null;
  contract_address: string | null;
  tx_hash: string | null;
  block_number: number | null;
  block_timestamp: string | null;
  gas_used: number | null;
  explorer_url: string | null;
  status: AnchorStatus;
  error_text: string | null;
  created_at: string;
  confirmed_at: string | null;
}

export interface Checkpoint {
  epoch: number;
  tree_size: number;
  root_hex: string;
  created_at: string;
  receipts: AnchorReceipt[];
}

export interface CheckpointsResponse {
  items: Checkpoint[];
  total: number;
}

export interface AnchorResponse {
  checkpoint: { epoch: number; tree_size: number; root: string; created_at: string };
  receipt: {
    id: number;
    checkpoint_epoch: number;
    mode: AnchorMode;
    chain_id: number | null;
    contract_address: string | null;
    tx_hash: string | null;
    block_number: number | null;
    block_timestamp: string | null;
    gas_used: number | null;
    explorer_url: string | null;
    status: AnchorStatus;
    created_at: string;
    confirmed_at: string | null;
  };
}

// ---------------------------------------------------------------------------
// /api/audit/verify, /api/audit/verify/history
// ---------------------------------------------------------------------------

export interface VerificationReport {
  checked_at: string;
  entries_checked: number;
  chain_intact: boolean;
  first_divergent_seq: number | null;
  anchor_epoch: number | null;
  anchor_matched: boolean | null;
  inclusion_proof_ok: boolean | null;
  consistency_proof_ok: boolean | null;
  tamper_window_seconds: number | null;
  detail: Record<string, unknown>;
}

export interface VerificationHistoryRow extends VerificationReport {
  id: number;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useAuditActions() {
  return useQuery({
    queryKey: ['audit', 'actions'],
    queryFn: () => apiGet<AuditAction[]>('/audit/actions'),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}

export function useAuditEntries(filters: AuditEntryFilters = {}) {
  const { actionCode, actor, targetKind, targetId, limit = 25, offset = 0 } = filters;
  return useQuery({
    queryKey: ['audit', 'entries', { actionCode, actor, targetKind, targetId, limit, offset }],
    queryFn: () =>
      apiGet<AuditEntriesResponse>('/audit/entries', {
        action_code: actionCode,
        actor,
        target_kind: targetKind,
        target_id: targetId,
        limit,
        offset,
      }),
    retry: 1,
  });
}

export function useCheckpoints(limit = 50) {
  return useQuery({
    queryKey: ['audit', 'checkpoints', limit],
    queryFn: () => apiGet<CheckpointsResponse>('/audit/checkpoints', { limit }),
    retry: 1,
  });
}

export function useRunAnchor() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (mode?: AnchorMode) => apiPost<AnchorResponse>('/audit/anchor', undefined, { mode }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit', 'checkpoints'] });
      queryClient.invalidateQueries({ queryKey: ['audit', 'verify'] });
    },
  });
}

export function useRunVerification() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => apiGet<VerificationReport>('/audit/verify'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit', 'verify', 'history'] });
    },
  });
}

export function useVerificationHistory(limit = 20) {
  return useQuery({
    queryKey: ['audit', 'verify', 'history', limit],
    queryFn: () => apiGet<VerificationHistoryRow[]>('/audit/verify/history', { limit }),
    retry: 1,
  });
}
