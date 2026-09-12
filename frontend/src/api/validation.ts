/**
 * Response shapes and query hooks for /api/validation/* (see backend/app/routers/validation.py).
 *
 * Mirrors the raw dicts the backend returns, same convention as audit.ts and
 * paths.ts -- no renaming layer between the wire shape and the type here.
 *
 * Two of these three endpoints are expensive by nature: the differential runs an
 * exhaustive reference search, and the property suite runs a hundred-odd
 * searches. So they are given long stale times and are never refetched on
 * focus, and the seeded-graph case of the differential is opt-in rather than
 * part of the default page load.
 */

import { useQuery } from '@tanstack/react-query';

import { apiGet } from './client';

// ---------------------------------------------------------------------------
// /api/validation/differential
// ---------------------------------------------------------------------------

export interface DifferentialDisagreement {
  found_by: 'engine' | 'reference';
  target_node_id: string;
  hop_count: number;
  steps: string[];
}

export interface DifferentialCase {
  code: string;
  title: string;
  mechanism: string;
  threat_model_code: string;
  node_count: number;
  edge_count: number;
  max_hops: number;
  engine_path_count: number;
  reference_path_count: number;
  reference_comparable_count: number;
  agreed_count: number;
  label_only_count: number;
  engine_ms: number;
  reference_ms: number;
  reference_states_expanded: number;
  engine_truncated: boolean;
  error: string | null;
  agrees: boolean;
  engine_only: DifferentialDisagreement[];
  reference_only: DifferentialDisagreement[];
}

export interface DifferentialReport {
  model_origin: 'database' | 'seed_file';
  model_detail: string;
  duration_ms: number;
  cases_total: number;
  cases_agreeing: number;
  agreed_total: number;
  comparable_total: number;
  /** Null rather than 1.0 when nothing was comparable -- see the backend module docstring. */
  agreement_rate: number | null;
  disagreement_count: number;
  seeded_graph_case: string | null;
  seeded_graph_bound: string | null;
  cases: DifferentialCase[];
}

// ---------------------------------------------------------------------------
// /api/validation/metrics
// ---------------------------------------------------------------------------

export type MatchLevel = 'edge_sequence' | 'node_sequence';

export type CaseOutcome =
  | 'true_positive'
  | 'false_positive'
  | 'true_negative'
  | 'false_negative'
  | 'not_evaluated';

export interface EvaluationCase {
  kind: 'scenario' | 'decoy' | 'twin';
  reference_code: string;
  outcome: CaseOutcome;
  matched_path_id: string | null;
  detail: string;
}

export interface LevelScore {
  match_level: MatchLevel;
  /** Null where the denominator is empty. A ratio over nothing is not zero. */
  precision: number | null;
  recall: number | null;
  f1: number | null;
  decoy_rejection: number | null;
  twin_acceptance: number | null;
  reported_findings: number;
  unlabelled_findings: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  not_evaluated: number;
  scenarios_recovered: number;
  scenarios_total: number;
  decoy_counts: Partial<Record<CaseOutcome, number>>;
  twin_counts: Partial<Record<CaseOutcome, number>>;
  cases: EvaluationCase[];
}

export interface RankingScore {
  paths_ranked: number;
  paths_unscoreable: number;
  concordant: number;
  discordant: number;
  kendall_tau: number | null;
  ndcg_at_k: number | null;
  k: number;
}

export interface CalibrationBin {
  lower: number;
  upper: number;
  count: number;
  mean_predicted: number | null;
  mean_true: number | null;
}

export interface CalibrationScore {
  samples: number;
  hops_unscoreable: number;
  expected_calibration_error: number | null;
  brier_score: number | null;
  bins: CalibrationBin[];
}

export interface MetricDefinition {
  code: string;
  label: string;
  description: string;
  interpretation: string;
  family: 'discovery' | 'ranking' | 'calibration' | 'remediation' | 'performance';
  higher_is_better: 0 | 1;
  format: 'fraction' | 'percent' | 'count' | 'milliseconds' | 'score';
  sort_order: number;
}

export interface MetricsReport {
  analysis_run_id: number;
  graph_version_id: number;
  threat_model_code: string;
  scoring_version: string;
  seed: number;
  generator_version: string;
  paths_reported: number;
  duration_ms: number;
  levels: LevelScore[];
  ranking: RankingScore;
  calibration: CalibrationScore;
  definitions: MetricDefinition[];
}

// ---------------------------------------------------------------------------
// /api/validation/invariants
// ---------------------------------------------------------------------------

export type InvariantStatus = 'pass' | 'fail' | 'not_exercised';

export interface InvariantOutcome {
  number: number;
  code: string;
  /** Verbatim from docs/RULES.md §7. */
  statement: string;
  /** How the suite checks it, including anything it deliberately does not check. */
  method: string;
  status: InvariantStatus;
  cases_checked: number;
  failures: string[];
  duration_ms: number;
}

export interface InvariantReport {
  passing: number;
  failing: number;
  total: number;
  total_cases: number;
  duration_ms: number;
  model_origin: 'database' | 'seed_file';
  model_detail: string;
  graph_nodes: number;
  graph_edges: number;
  max_hops: number;
  threat_model_code: string;
  perturbations: string[];
  outcomes: InvariantOutcome[];
  from_cache: boolean;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * The differential harness. `includeSeededGraph` adds the bounded neighbourhood
 * of the real generated graph, which costs roughly a second against tens of
 * milliseconds for the hand-built worlds -- so it is a separate query key and
 * the screen asks for it only when the reader does.
 */
export function useDifferentialReport(includeSeededGraph = false) {
  return useQuery({
    queryKey: ['validation', 'differential', includeSeededGraph],
    queryFn: () =>
      apiGet<DifferentialReport>('/validation/differential', {
        include_seeded_graph: includeSeededGraph,
      }),
    staleTime: 10 * 60 * 1000,
    retry: 1,
  });
}

export function useValidationMetrics(runId?: number) {
  return useQuery({
    queryKey: ['validation', 'metrics', runId ?? 'latest'],
    queryFn: () => apiGet<MetricsReport>('/validation/metrics', { run: runId }),
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
}

export function useInvariantReport() {
  return useQuery({
    queryKey: ['validation', 'invariants'],
    queryFn: () => apiGet<InvariantReport>('/validation/invariants'),
    staleTime: 10 * 60 * 1000,
    retry: 1,
  });
}

// ---------------------------------------------------------------------------
// Shared readers
// ---------------------------------------------------------------------------

export const MATCH_LEVEL_LABELS: Record<MatchLevel, string> = {
  edge_sequence: 'Exact route',
  node_sequence: 'Right places',
};

export function levelAt(report: MetricsReport | undefined, level: MatchLevel): LevelScore | undefined {
  return report?.levels.find((entry) => entry.match_level === level);
}

/** The seeded `metric_definition` row for a metric code, so labels and hover text come from the API. */
export function definitionFor(
  report: MetricsReport | undefined,
  code: string,
): MetricDefinition | undefined {
  return report?.definitions.find((entry) => entry.code === code);
}
