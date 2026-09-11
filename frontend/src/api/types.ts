/**
 * Response shapes for the FastAPI routers under backend/app/routers.
 *
 * These mirror the raw SQL row dicts the backend returns (snake_case,
 * MySQL TINYINT(1) flags as 0/1) rather than an idealised client model, so
 * there is exactly one place a field name can drift from the API: nowhere,
 * because there is no renaming layer to drift.
 */

/** MySQL TINYINT(1); the driver returns it as 0/1, not a JSON boolean. */
export type IntBool = 0 | 1;

// ---------------------------------------------------------------------------
// /api/health
// ---------------------------------------------------------------------------

export interface HealthGraphVersion {
  id: number;
  label: string;
  node_count: number;
  edge_count: number;
  canonical_hash: string;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  stores: { mysql: boolean; neo4j: boolean };
  errors: Record<string, string>;
  graph_version: HealthGraphVersion | null;
}

// ---------------------------------------------------------------------------
// /api/runs
// ---------------------------------------------------------------------------

export interface RunSummary {
  id: number;
  graph_version_id: number;
  scoring_version: string;
  threat_model_code: string;
  purpose: string;
  path_count: number;
  rejected_count: number;
  crown_jewels_reached: number;
  max_risk_score: number | null;
  duration_ms: number | null;
  status: string;
  started_at: string | null;
  finished_at: string | null;
}

// ---------------------------------------------------------------------------
// /api/paths
// ---------------------------------------------------------------------------

export interface PathSummary {
  path_id: string;
  source_node_id: string;
  target_node_id: string;
  hop_count: number;
  p_success: number;
  neg_log_success: number;
  p_undetected: number | null;
  bottleneck_p: number | null;
  bottleneck_hop: number | null;
  impact_score: number;
  risk_score: number;
  risk_tier_code: string;
  target_is_crown_jewel: IntBool;
  rank_in_run: number;
}

export interface PathListResponse {
  items: PathSummary[];
  total: number;
  analysis_run_id: number;
  graph_version_id: number;
  scoring_version: string;
}

export interface PathScoreFactor {
  hop_no: number;
  seq: number;
  factor_kind: string;
  factor_code: string;
  factor_label: string;
  observed_value: string | number | null;
  beta: number | null;
  p_after: number | null;
}

export interface PathHopCapability {
  hop_no: number;
  capability_code: string;
  about_node_id: string | null;
  is_newly_gained: IntBool;
}

export interface PathHop {
  hop_no: number;
  src_node_id: string;
  dst_node_id: string;
  edge_id: string;
  technique_code: string;
  technique_name: string;
  attack_id: string | null;
  attack_name: string | null;
  attack_url: string | null;
  phase: string | null;
  rule_id: number;
  rule_code: string;
  rule_description: string;
  p_succ: number;
  detectability: number | null;
  neg_log_contribution: number;
  factors: PathScoreFactor[];
  capabilities: PathHopCapability[];
}

export interface PathDetailResponse {
  path: PathSummary;
  hops: PathHop[];
  analysis_run_id: number;
  graph_version_id: number;
  scoring_version: string;
}

export interface PathNode {
  node_id: string;
  kind_code: string;
  name: string;
  display_name: string | null;
  is_crown_jewel: IntBool;
  criticality_code: string | null;
}

// ---------------------------------------------------------------------------
// /api/rejections
// ---------------------------------------------------------------------------

export interface RejectedCandidate {
  id: number;
  src_node_id: string;
  dst_node_id: string;
  edge_id: string | null;
  rule_id: number;
  rule_code: string;
  precondition_seq: number | null;
  reason_code: string;
  reason_text: string;
  observed_value: string | null;
  decoy_code: string | null;
  hop_depth: number;
}

export interface RejectionReasonCount {
  reason_code: string;
  count: number;
  example: string;
}

export interface RejectionsResponse {
  items: RejectedCandidate[];
  total: number;
  by_reason: RejectionReasonCount[];
  analysis_run_id: number;
}

// ---------------------------------------------------------------------------
// /api/chokepoints
// ---------------------------------------------------------------------------

export interface Chokepoint {
  rank_in_run: number;
  kind: string;
  target_id: string;
  paths_covered: number;
  coverage_fraction: number;
  cumulative_fraction: number;
  optimality_bound: number | null;
}

export interface ChokepointsResponse {
  items: Chokepoint[];
  analysis_run_id: number;
  total_paths: number;
}

// ---------------------------------------------------------------------------
// /api/risk/summary, /api/risk/top
// ---------------------------------------------------------------------------

export interface RiskTierCount {
  code: string;
  label: string;
  ui_color: string;
  sort_order: number;
  count: number;
}

export interface CrownJewelExposure {
  target_node_id: string;
  name: string;
  path_count: number;
  max_risk: number;
}

export interface RiskSummary {
  analysis_run_id: number;
  graph_version_id: number;
  scoring_version: string;
  threat_model: string;
  total_paths: number;
  rejected_count: number;
  max_risk: number | null;
  crown_jewels_reached: number;
  discovery_ms: number | null;
  by_tier: RiskTierCount[];
  crown_jewel_exposure: CrownJewelExposure[];
}

export interface TopRisk {
  path_id: string;
  source_node_id: string;
  source_name: string | null;
  target_node_id: string;
  target_name: string | null;
  hop_count: number;
  p_success: number;
  risk_score: number;
  risk_tier_code: string;
  target_is_crown_jewel: IntBool;
}

// ---------------------------------------------------------------------------
// /api/config/*
// ---------------------------------------------------------------------------

export interface NavItem {
  code: string;
  label: string;
  route: string;
  icon: string;
  description: string;
  sort_order: number;
}

export interface RiskTierConfig {
  code: string;
  label: string;
  min_score: number;
  max_score: number;
  ui_color: string;
  ui_bg_color: string;
  action_text: string;
  sort_order: number;
}

export interface NodeKindConfig {
  code: string;
  label: string;
  description: string;
  category: string;
  ui_color: string;
  ui_shape: string;
  ui_size_min: number;
  ui_size_max: number;
  ui_size_by: string;
  ui_icon: string;
  sort_order: number;
}

export interface EdgeTypeConfig {
  code: string;
  label: string;
  description: string;
  is_directed: IntBool;
  ui_color: string;
  ui_line_style: string;
  ui_width: number;
  ui_animated: IntBool;
  sort_order: number;
}

export interface VocabularyEntry {
  code: string;
  label: string;
  description: string;
  sort_order: number;
}

export interface Vocabularies {
  node_kinds: NodeKindConfig[];
  edge_types: EdgeTypeConfig[];
  criticality: VocabularyEntry[];
  classifications: VocabularyEntry[];
}
