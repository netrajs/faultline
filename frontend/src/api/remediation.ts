/**
 * Response shapes and query hooks for /api/remediation/* (see
 * backend/app/routers/remediation.py).
 *
 * Mirrors the raw row dicts the backend returns, same convention as audit.ts
 * and paths.ts -- no renaming layer between the wire shape and the type here.
 *
 * Chokepoints deliberately have no hook of their own: /api/chokepoints in
 * paths.py already reads the same table for the same run, and `useChokepoints`
 * there is what this screen consumes. POST /remediation/analyze is the writer
 * that fills it.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiGet, apiPost } from './client';

// ---------------------------------------------------------------------------
// Shared provenance envelope
// ---------------------------------------------------------------------------

/** Every response carries the run it came from: recommendations are only comparable within one. */
export interface RemediationRunEnvelope {
  analysis_run_id: number;
  graph_version_id: number;
  scoring_version: string;
  threat_model_code: string;
  total_paths: number;
  crown_jewels_reached: number;
  max_risk_score: number | null;
}

// ---------------------------------------------------------------------------
// /api/remediation/recommendations
// ---------------------------------------------------------------------------

export interface Recommendation {
  id: number;
  analysis_run_id: number;
  fix_type_code: string;
  fix_label: string;
  fix_description: string;
  mutation_kind: string;
  mutation_target_attr: string | null;
  effort_label: string;
  disruption_label: string;
  requires_approval: 0 | 1;
  d3fend_id: string | null;
  target_kind: 'edge' | 'node';
  target_id: string;
  title: string;
  rationale: string;
  risk_before: number;
  risk_after: number | null;
  paths_eliminated: number | null;
  total_paths: number;
  path_coverage: number | null;
  effort_value: number;
  disruption_value: number;
  priority_score: number | null;
  /** 0 while the numbers are the coverage pass's estimate, 1 once a simulation measured them. */
  is_measured: 0 | 1;
  state_code: string;
  state_label: string;
  state_color: string;
  is_terminal: 0 | 1;
  created_at: string;
  dependency_count: number;
  simulation_id: number | null;
}

export interface RecommendationsResponse extends RemediationRunEnvelope {
  items: Recommendation[];
  /** False when the ranking has never been computed for this run -- distinct from "ranked, nothing applied". */
  has_ranking: boolean;
}

// ---------------------------------------------------------------------------
// /api/remediation/recommendations/{id}
// ---------------------------------------------------------------------------

export interface RecommendationDetailRow extends Recommendation {
  mutation_value: string | null;
  graph_version_id: number;
  threat_model_code: string;
  scoring_version: string;
  max_hops: number;
  top_k_per_pair: number;
}

export type DependencySeverity = 'info' | 'warning' | 'blocking';

export interface RecommendationDependency {
  seq: number;
  kind: string;
  affected_node_id: string | null;
  description: string;
  severity: DependencySeverity;
}

export interface Simulation {
  id: number;
  recommendation_id: number;
  baseline_run_id: number;
  simulated_run_id: number;
  paths_removed: number;
  paths_added: number;
  paths_rescored: number;
  risk_before: number;
  risk_after: number;
  crown_jewels_before: number;
  crown_jewels_after: number;
  /** sha256 over the sorted predicted removed/added path ids, committed to before reality is consulted. */
  prediction_hash: string;
  created_at: string;
  /** Present only on the response to the simulate call that just ran. */
  duration_ms?: number;
  truncated?: boolean;
  child_graph_version?: number;
}

export type PathChangeKind = 'removed' | 'added' | 'rescored';

export interface SimulationDelta {
  path_id: string;
  change_kind: PathChangeKind;
  risk_before: number | null;
  risk_after: number | null;
  source_node_id: string | null;
  target_node_id: string | null;
  source_name: string | null;
  target_name: string | null;
  hop_count: number | null;
  risk_tier_code: string | null;
  target_is_crown_jewel: 0 | 1 | null;
}

export interface AllowedTransition {
  to_state: string;
  label: string;
  needs_approval: boolean;
  /** The transition wants an approval AND this fix type is disruptive enough to need a real one. */
  requires_approver: boolean;
}

export interface AppliedFix {
  id: number;
  simulation_id: number | null;
  applied_by: string;
  graph_version_before: number;
  graph_version_after: number;
  verification_run_id: number | null;
  fidelity_exact_match: 0 | 1 | null;
  fidelity_jaccard: number | null;
  unexpected_paths: number | null;
  state_code: string;
  applied_at: string;
  verified_at: string | null;
}

/** One analysis_run row, enough to show what the counterfactual was searched under. */
export interface RunSummary {
  id: number;
  graph_version_id: number;
  purpose: string;
  max_hops: number;
  top_k_per_pair: number;
  path_count: number;
  rejected_count: number;
  crown_jewels_reached: number;
  max_risk_score: number | null;
  duration_ms: number | null;
  status: string;
  started_at: string;
}

export type SimulationRunStatus = 'queued' | 'running' | 'complete' | 'failed';

/**
 * Whether the API process is re-deriving right now. Distinct from `simulation`,
 * which is the stored result: a recommendation can have an old result and a run
 * in flight, or a run that failed and no result at all. Null means nothing has
 * been started from the current server process.
 */
export interface SimulationRun {
  status: SimulationRunStatus;
  started_at: string;
  finished_at: string | null;
  elapsed_ms: number;
  error: string | null;
  simulation_id: number | null;
}

export interface SimulationJobAck {
  recommendation_id: number;
  simulation_run: SimulationRun;
  note: string;
}

export interface RecommendationDetail {
  recommendation: RecommendationDetailRow;
  dependencies: RecommendationDependency[];
  simulation: Simulation | null;
  simulation_run: SimulationRun | null;
  /** Null until a simulation exists. Both sides carry their own search limits, which are identical by construction. */
  runs: { baseline: RunSummary | null; simulated: RunSummary | null } | null;
  deltas: SimulationDelta[];
  delta_total: number;
  delta_limit: number;
  transitions: AllowedTransition[];
  applied_fix: AppliedFix[];
  /** Present only on the response to the apply call that just ran. */
  applied?: {
    applied_fix_id: number;
    applied_by: string;
    approved_by: string | null;
    route: string[];
    mutation: string;
    graph_version_before: number;
    graph_version_after: number;
    graph_version_after_is_active: boolean;
    node_count: number;
    edge_count: number;
  };
}

// ---------------------------------------------------------------------------
// /api/remediation/lifecycle, /analyze, /applied
// ---------------------------------------------------------------------------

export interface RemediationState {
  code: string;
  label: string;
  description: string;
  is_terminal: boolean;
  ui_color: string;
  sort_order: number;
}

export interface RemediationTransition {
  from_state: string;
  to_state: string;
  label: string;
  needs_approval: boolean;
}

export interface LifecycleResponse {
  states: RemediationState[];
  transitions: RemediationTransition[];
  initial_state: string;
}

export interface AnalyzeResponse extends RemediationRunEnvelope {
  chokepoints_ranked: number;
  recommendations_written: number;
  recommendations_total: number;
  /** Exact minimum vertex cut over the discovered paths -- the one number in the ranking that is not an approximation. */
  min_cut_size: number;
  min_cut_vertices: string[];
}

export interface AppliedFixesResponse extends RemediationRunEnvelope {
  items: (AppliedFix & { recommendation_id: number; title: string; fix_type_code: string })[];
}

export interface ApplyRequest {
  recommendationId: number;
  applied_by: string;
  approved_by?: string | null;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useRecommendations(runId?: number, limit = 100) {
  return useQuery({
    queryKey: ['remediation', 'recommendations', runId, limit],
    queryFn: () => apiGet<RecommendationsResponse>('/remediation/recommendations', { run_id: runId, limit }),
    retry: 1,
  });
}

/** How often the detail is re-read while a re-derivation is in flight. */
const SIMULATION_POLL_MS = 3000;

/**
 * The detail, and -- while the API is re-deriving this fix -- a poll for it.
 * The re-derivation takes minutes by design (see the router's docstring), so
 * the result arrives on a later read of this same endpoint rather than as the
 * response to the request that started it.
 */
export function useRecommendationDetail(recommendationId: number | undefined) {
  return useQuery({
    queryKey: ['remediation', 'recommendation', recommendationId],
    queryFn: () => apiGet<RecommendationDetail>(`/remediation/recommendations/${recommendationId as number}`),
    enabled: Boolean(recommendationId),
    retry: 1,
    refetchInterval: (query) => {
      const status = query.state.data?.simulation_run?.status;
      return status === 'queued' || status === 'running' ? SIMULATION_POLL_MS : false;
    },
  });
}

export function useRemediationLifecycle() {
  return useQuery({
    queryKey: ['remediation', 'lifecycle'],
    queryFn: () => apiGet<LifecycleResponse>('/remediation/lifecycle'),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}

export function useAppliedFixes(runId?: number) {
  return useQuery({
    queryKey: ['remediation', 'applied', runId],
    queryFn: () => apiGet<AppliedFixesResponse>('/remediation/applied', { run_id: runId }),
    retry: 1,
  });
}

/** Ranks the run's chokepoints and writes its recommendations. A write, which is why it is a POST and never implicit in a read. */
export function useAnalyzeRun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { run_id?: number; limit?: number } = {}) =>
      apiPost<AnalyzeResponse>('/remediation/analyze', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remediation'] });
      queryClient.invalidateQueries({ queryKey: ['chokepoints'] });
    },
  });
}

/**
 * Starts a re-derivation of the whole graph with one fix applied. Returns as
 * soon as the job is accepted, not when it finishes: minutes, not milliseconds,
 * and the router's module docstring says why the fast shortcut is refused.
 * Invalidating the detail is what starts `useRecommendationDetail` polling.
 */
export function useSimulateRecommendation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (recommendationId: number) =>
      apiPost<SimulationJobAck>(`/remediation/recommendations/${recommendationId}/simulate`),
    onSuccess: (_data, recommendationId) => {
      queryClient.invalidateQueries({ queryKey: ['remediation', 'recommendation', recommendationId] });
    },
  });
}

/**
 * Called once when a re-derivation finishes: the ranked list, the run list and
 * the audit log all changed, and none of them was polling.
 */
export function useSimulationSettled() {
  const queryClient = useQueryClient();
  return () => {
    queryClient.invalidateQueries({ queryKey: ['remediation', 'recommendations'] });
    queryClient.invalidateQueries({ queryKey: ['runs'] });
    queryClient.invalidateQueries({ queryKey: ['audit'] });
  };
}

export function useApplyFix() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ recommendationId, applied_by, approved_by }: ApplyRequest) =>
      apiPost<RecommendationDetail>(`/remediation/recommendations/${recommendationId}/apply`, {
        applied_by,
        approved_by: approved_by || null,
      }),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['remediation'] });
      queryClient.invalidateQueries({ queryKey: ['remediation', 'recommendation', variables.recommendationId] });
      queryClient.invalidateQueries({ queryKey: ['audit'] });
    },
  });
}
