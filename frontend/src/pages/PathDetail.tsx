import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { ApiError } from '@/api/client';
import { nodeLabelMap, usePathDetail, usePathNodes } from '@/api/paths';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { RiskTierBadge } from '@/components/ui/RiskTierBadge';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { HopCard } from '@/components/paths/HopCard';
import { PathFlowDiagram } from '@/components/paths/PathFlowDiagram';
import { formatPercent, formatScore, isTruthy, shortId } from '@/lib/format';
import { fadeInUp } from '@/theme/motion';
import './PathDetail.css';

export function PathDetail() {
  const { pathId } = useParams<{ pathId: string }>();
  const detail = usePathDetail(pathId);
  const nodes = usePathNodes(pathId);
  // Defaults to the weakest link -- the hop that did the most to shape this
  // path's risk score is the one worth reading first.
  const [selectedHopNo, setSelectedHopNo] = useState<number | null>(null);

  if (detail.isLoading) {
    return (
      <div className="path-detail">
        <LoadingState variant="cards" rows={1} />
        <LoadingState variant="list" rows={3} />
      </div>
    );
  }

  if (detail.isError) {
    const error = detail.error;
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState icon="route-off" title="Path not found" description={error.message}>
          <Link className="pill-button" to="/paths">
            Back to attack paths
          </Link>
        </EmptyState>
      );
    }
    return (
      <ErrorState
        message={
          error instanceof ApiError
            ? error.message
            : 'The API could not be reached. Confirm the backend is running and CORS allows this origin.'
        }
      />
    );
  }

  const data = detail.data;
  if (!data) return null;

  const labelLookup = nodeLabelMap(nodes.data);
  const nodeLabel = (nodeId: string) => labelLookup.get(nodeId);
  const sourceLabel = nodeLabel(data.path.source_node_id)?.display_name ?? nodeLabel(data.path.source_node_id)?.name;
  const targetLabel = nodeLabel(data.path.target_node_id)?.display_name ?? nodeLabel(data.path.target_node_id)?.name;

  const activeHopNo = selectedHopNo ?? data.path.bottleneck_hop ?? data.hops[0]?.hop_no ?? 1;
  const activeHop = data.hops.find((hop) => hop.hop_no === activeHopNo) ?? data.hops[0];

  return (
    <div className="path-detail">
      <Link to="/paths" className="path-detail__back">
        <Icon name="arrow-narrow-left" /> All attack paths
      </Link>

      <GlassPanel padding="lg" raised className="path-detail__summary" {...fadeInUp()}>
        <div className="path-detail__route">
          <span title={data.path.source_node_id}>{sourceLabel ?? shortId(data.path.source_node_id)}</span>
          <Icon name="arrow-narrow-right" />
          <span title={data.path.target_node_id}>
            {targetLabel ?? shortId(data.path.target_node_id)}
            {isTruthy(data.path.target_is_crown_jewel) && <Icon name="crown" className="path-detail__crown" />}
          </span>
        </div>

        <div className="path-detail__badges">
          <RiskTierBadge code={data.path.risk_tier_code} />
          <span className="path-detail__id" title={data.path.path_id}>
            {shortId(data.path.path_id, 8)}
          </span>
        </div>

        <div className="path-detail__metrics">
          <div className="path-detail__metric">
            <span className="path-detail__metric-label">Risk score</span>
            <span className="path-detail__metric-value">{formatScore(data.path.risk_score)} / 10</span>
          </div>
          <div className="path-detail__metric">
            <span className="path-detail__metric-label">P(success)</span>
            <span className="path-detail__metric-value">{formatPercent(data.path.p_success)}</span>
          </div>
          <div className="path-detail__metric">
            <span className="path-detail__metric-label">Impact</span>
            <span className="path-detail__metric-value">{formatScore(data.path.impact_score)}</span>
          </div>
          <div className="path-detail__metric">
            <span className="path-detail__metric-label">Hops</span>
            <span className="path-detail__metric-value">{data.path.hop_count}</span>
          </div>
          <div className="path-detail__metric">
            <span className="path-detail__metric-label">Weakest link</span>
            <span className="path-detail__metric-value">
              {formatPercent(data.path.bottleneck_p)}
              {data.path.bottleneck_hop !== null && (
                <span className="path-detail__metric-sub"> at hop {data.path.bottleneck_hop}</span>
              )}
            </span>
          </div>
          <div className="path-detail__metric">
            <span className="path-detail__metric-label">Rank in run</span>
            <span className="path-detail__metric-value">#{data.path.rank_in_run}</span>
          </div>
        </div>

        <p className="path-detail__provenance">
          Run #{data.analysis_run_id} · graph version {data.graph_version_id} · scoring {data.scoring_version}
        </p>
      </GlassPanel>

      <section className="path-detail__flow" aria-label="Attack path diagram">
        <h2 className="path-detail__section-title">How the attacker gets there</h2>
        <p className="path-detail__section-hint">
          Every step this path takes, in order. Redder steps are easier for an attacker to pull
          off; bluer steps are harder. Click any step to see exactly how it works, below.
        </p>
        <PathFlowDiagram
          hops={data.hops}
          nodeLabel={nodeLabel}
          targetIsCrownJewel={isTruthy(data.path.target_is_crown_jewel)}
          selectedHopNo={activeHopNo}
          onSelectHop={setSelectedHopNo}
        />
      </section>

      {activeHop && <HopCard hop={activeHop} nodeLabel={nodeLabel} />}
    </div>
  );
}
