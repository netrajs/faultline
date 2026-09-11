import { ApiError } from '@/api/client';
import { useRiskSummary, useTopRisks } from '@/api/risk';
import { useRuns } from '@/api/runs';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { StatCard } from '@/components/dashboard/StatCard';
import { RiskTierBreakdown } from '@/components/dashboard/RiskTierBreakdown';
import { TopRisksList } from '@/components/dashboard/TopRisksList';
import { formatCount, formatDuration, formatScore } from '@/lib/format';
import './Dashboard.css';

export function Dashboard() {
  const summary = useRiskSummary();
  const topRisks = useTopRisks(5);
  const runs = useRuns(5);

  if (summary.isLoading) {
    return (
      <div className="dashboard">
        <LoadingState variant="cards" rows={4} />
        <LoadingState variant="list" rows={4} />
      </div>
    );
  }

  if (summary.isError) {
    const error = summary.error;
    const isNoRun = error instanceof ApiError && error.status === 404;

    if (isNoRun) {
      const hasRunHistory = (runs.data?.length ?? 0) > 0;
      return (
        <EmptyState
          icon="chart-bar"
          title="No completed discovery run yet"
          description={error.message}
        >
          {hasRunHistory && (
            <div className="dashboard__run-history">
              <span className="dashboard__run-history-title">Recorded runs</span>
              <ul>
                {runs.data!.map((run) => (
                  <li key={run.id}>
                    <span className="dashboard__run-id">#{run.id}</span>
                    <span>{run.threat_model_code}</span>
                    <span className="dashboard__run-status" data-status={run.status}>
                      {run.status}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
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
        detail={error instanceof Error ? error.stack : undefined}
      />
    );
  }

  const data = summary.data;
  if (!data) return null;

  return (
    <div className="dashboard">
      <div className="dashboard__stats">
        <StatCard icon="route" label="Total paths" value={formatCount(data.total_paths)} accent="cyan" delay={0} />
        <StatCard
          icon="ban"
          label="Rejected candidates"
          value={formatCount(data.rejected_count)}
          sublabel="Precondition failures the engine refused"
          accent="rose"
          delay={0.04}
        />
        <StatCard
          icon="crown"
          label="Crown jewels reached"
          value={formatCount(data.crown_jewels_reached)}
          accent="purple"
          delay={0.08}
        />
        <StatCard
          icon="gauge"
          label="Max risk score"
          value={data.max_risk !== null ? `${formatScore(data.max_risk)} / 10` : '—'}
          accent="amber"
          delay={0.12}
        />
        <StatCard
          icon="clock"
          label="Discovery time"
          value={formatDuration(data.discovery_ms)}
          sublabel={`scoring ${data.scoring_version} · threat model ${data.threat_model}`}
          accent="emerald"
          delay={0.16}
        />
      </div>

      <div className="dashboard__grid">
        <GlassPanel padding="lg" className="dashboard__panel">
          <h2 className="dashboard__panel-title">Risk tier breakdown</h2>
          {data.by_tier.length > 0 ? (
            <RiskTierBreakdown tiers={data.by_tier} />
          ) : (
            <p className="dashboard__panel-empty">No tiers configured.</p>
          )}
        </GlassPanel>

        <GlassPanel padding="lg" className="dashboard__panel">
          <h2 className="dashboard__panel-title">Crown jewel exposure</h2>
          {data.crown_jewel_exposure.length > 0 ? (
            <ul className="dashboard__crown-list">
              {data.crown_jewel_exposure.map((jewel) => (
                <li key={jewel.target_node_id}>
                  <span className="dashboard__crown-name">{jewel.name}</span>
                  <span className="dashboard__crown-meta">
                    {formatCount(jewel.path_count)} path{jewel.path_count === 1 ? '' : 's'} · max{' '}
                    {formatScore(jewel.max_risk)}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="dashboard__panel-empty">No crown jewel is reachable in this run.</p>
          )}
        </GlassPanel>
      </div>

      <GlassPanel padding="lg" className="dashboard__panel">
        <h2 className="dashboard__panel-title">Top risks</h2>
        {topRisks.isLoading && <LoadingState variant="list" rows={5} />}
        {topRisks.isError && (
          <p className="dashboard__panel-empty">Could not load the top-risk list.</p>
        )}
        {topRisks.data && topRisks.data.length > 0 && <TopRisksList risks={topRisks.data} />}
        {topRisks.data && topRisks.data.length === 0 && (
          <p className="dashboard__panel-empty">No paths were discovered in this run.</p>
        )}
      </GlassPanel>
    </div>
  );
}
