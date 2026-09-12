import { useEffect, useState } from 'react';

import { ApiError } from '@/api/client';
import {
  useAnalyzeRun,
  useApplyFix,
  useRecommendationDetail,
  useRecommendations,
  useSimulateRecommendation,
  useSimulationSettled,
  type RecommendationDetail,
} from '@/api/remediation';
import { ChokepointRanking } from '@/components/remediation/ChokepointRanking';
import { DependencyPanel } from '@/components/remediation/DependencyPanel';
import { RecommendationTable } from '@/components/remediation/RecommendationTable';
import { SimulationDiff } from '@/components/remediation/SimulationDiff';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { VideoLoadingOverlay } from '@/components/ui/VideoLoadingOverlay';
import { formatCount, formatDuration, formatScore, isTruthy } from '@/lib/format';
import { fadeInUp } from '@/theme/motion';
import './Remediation.css';

export function Remediation() {
  const [selectedId, setSelectedId] = useState<number | undefined>(undefined);
  const recommendations = useRecommendations();
  const analyze = useAnalyzeRun();

  const items = recommendations.data?.items ?? [];

  // Open on the top-ranked fix rather than an empty panel; a reader who has
  // never seen this screen should land on the thing it is telling them to do
  // first. Only until they pick something else.
  useEffect(() => {
    const first = items[0];
    if (!first) return;
    // Also re-points at the top row when a re-rank has replaced the selected
    // recommendation, rather than leaving the panel on an id that no longer exists.
    if (selectedId === undefined || !items.some((item) => item.id === selectedId)) {
      setSelectedId(first.id);
    }
  }, [items, selectedId]);

  if (recommendations.isLoading) return <LoadingState variant="list" rows={6} />;

  if (recommendations.isError) {
    const error = recommendations.error;
    if (error instanceof ApiError && error.status === 404) {
      return <EmptyState icon="shield-check" title="Nothing to recommend against yet" description={error.message} />;
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

  const data = recommendations.data;
  if (!data) return null;

  return (
    <div className="remediation">
      <GlassPanel padding="lg" className="remediation__header" {...fadeInUp()}>
        <div className="remediation__intro">
          <h2 className="remediation__title">Remediation</h2>
          <p className="remediation__lede">
            The same {formatCount(data.total_paths)} attack paths on the other screens, turned
            around: which single change cuts the most of them, what it costs, what else it breaks,
            and &mdash; before you touch anything &mdash; what the graph would actually look like
            afterwards.
          </p>
        </div>

        <dl className="remediation__figures">
          <div>
            <dt>Attack paths</dt>
            <dd>{formatCount(data.total_paths)}</dd>
          </div>
          <div>
            <dt>Crown jewels reached</dt>
            <dd className={data.crown_jewels_reached > 0 ? 'remediation__figure--alarm' : undefined}>
              {formatCount(data.crown_jewels_reached)}
            </dd>
          </div>
          <div>
            <dt>Worst path</dt>
            <dd>
              {formatScore(data.max_risk_score, 2)}
              <span className="remediation__figure-suffix">/ 10</span>
            </dd>
          </div>
          <div>
            <dt>Fixes ranked</dt>
            <dd>{formatCount(items.length)}</dd>
          </div>
        </dl>

        <div className="remediation__actions">
          <button
            type="button"
            className="pill-button pill-button--primary"
            onClick={() => analyze.mutate({})}
            disabled={analyze.isPending}
          >
            <Icon name={analyze.isPending ? 'loader-2' : 'refresh'} className={analyze.isPending ? 'remediation__spin' : ''} />
            {analyze.isPending ? 'Ranking…' : data.has_ranking ? 'Re-rank fixes' : 'Rank fixes'}
          </button>
          <span className="remediation__actions-hint">
            Re-ranking rewrites the ranking for this run from the current graph. Anything already
            simulated, approved or applied is left alone &mdash; it has results and an audit trail
            hanging off it.
          </span>
        </div>

        {analyze.isError && (
          <ErrorState
            title="Ranking failed"
            message={analyze.error instanceof ApiError ? analyze.error.message : 'Could not reach the API to rank fixes.'}
          />
        )}

        {analyze.data && (
          <p className="remediation__analyze-result">
            <Icon name="circle-check" className="remediation__analyze-icon" />
            Ranked {formatCount(analyze.data.chokepoints_ranked)} chokepoints and wrote{' '}
            {formatCount(analyze.data.recommendations_written)} new recommendation(s)
            {analyze.data.recommendations_total !== analyze.data.recommendations_written &&
              ` (${formatCount(analyze.data.recommendations_total)} on this run in total)`}
            . It would take <strong>{formatCount(analyze.data.min_cut_size)}</strong> node
            removal(s) to sever every discovered path &mdash; that figure is an exact minimum cut,
            not an approximation, and it is the floor any selection is measured against.
          </p>
        )}

        <footer className="remediation__provenance">
          Run {data.analysis_run_id} · graph version {data.graph_version_id} · scoring{' '}
          {data.scoring_version} · threat model {data.threat_model_code}
        </footer>
      </GlassPanel>

      {items.length === 0 ? (
        <EmptyState
          icon="shield-check"
          title={data.has_ranking ? 'Nothing in the fix catalogue applies here' : 'Fixes have not been ranked for this run'}
          description={
            data.has_ranking
              ? 'The chokepoints for this run were found, but no fix in the catalogue would actually change any of them — a fix is only offered where the target records the attribute it writes and records a different value, so nothing here is offered as a change that would do nothing.'
              : 'The chokepoint cut and the ranked fix list are written by an explicit pass, not computed silently on read. Run it with the button above.'
          }
        />
      ) : (
        <>
          <GlassPanel padding="lg" className="remediation__list" {...fadeInUp()}>
            <h3 className="remediation__section-title">Ranked fixes</h3>
            <RecommendationTable items={items} selectedId={selectedId} onSelect={setSelectedId} />
            <details className="remediation__chokepoints">
              <summary>The cut these came from</summary>
              <ChokepointRanking />
            </details>
          </GlassPanel>

          <SelectedFix recommendationId={selectedId} />
        </>
      )}
    </div>
  );
}

function SelectedFix({ recommendationId }: { recommendationId: number | undefined }) {
  const detail = useRecommendationDetail(recommendationId);
  const simulate = useSimulateRecommendation();
  const apply = useApplyFix();
  const onSimulationSettled = useSimulationSettled();
  const [appliedBy, setAppliedBy] = useState('');
  const [approvedBy, setApprovedBy] = useState('');
  const [confirming, setConfirming] = useState(false);

  // A different fix is a different decision: nobody's name should carry over
  // from the last one they signed for.
  useEffect(() => {
    setConfirming(false);
    apply.reset();
    simulate.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recommendationId]);

  // The detail polls itself while a re-derivation is in flight; everything else
  // on the page is stale the moment it lands, and nothing else is watching.
  const runStatus = detail.data?.simulation_run?.status;
  useEffect(() => {
    if (runStatus === 'complete') onSimulationSettled();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runStatus, recommendationId]);

  if (!recommendationId) return null;
  if (detail.isLoading) return <LoadingState variant="list" rows={4} />;
  if (detail.isError) {
    return (
      <ErrorState
        message={detail.error instanceof ApiError ? detail.error.message : 'This recommendation could not be loaded.'}
      />
    );
  }
  if (!detail.data) return null;

  const data: RecommendationDetail = detail.data;
  const fix = data.recommendation;
  // Both gates are read off the transitions the table allows from where this
  // recommendation currently is, not from a list of state names written here.
  // Re-simulating something already simulated is the one case the table does
  // not have an edge for and the service does: it is the same state, so there
  // is no transition to take.
  const run = data.simulation_run;
  const isRunning = run?.status === 'queued' || run?.status === 'running';
  const canSimulate =
    fix.state_code === 'simulated' || data.transitions.some((transition) => transition.to_state === 'simulated');
  const canApply =
    data.simulation !== null && !isTruthy(fix.is_terminal) && data.transitions.length > 0 && fix.state_code !== 'applied';
  const needsApprover = data.transitions.some((transition) => transition.requires_approver) || isTruthy(fix.requires_approval);

  return (
    <GlassPanel padding="lg" className="remediation__detail" raised {...fadeInUp()}>
      {/* Apply blocks: it materialises a whole graph version into both stores
          before it can answer, and the page has nothing to show in the
          meantime. Simulation does not get one — it returns as soon as the job
          is accepted, runs for minutes afterwards, and a full-screen overlay
          for that stretch would trap the reader on a page they are free to
          leave; the button and the running line say what is happening there. */}
      <VideoLoadingOverlay
        active={apply.isPending}
        label="Applying the fix and writing the new graph version…"
      />
      <header className="remediation__detail-header">
        <div>
          <span className="remediation__detail-eyebrow">
            {fix.fix_label}
            {fix.d3fend_id && <span className="remediation__d3fend">{fix.d3fend_id}</span>}
          </span>
          <h3 className="remediation__detail-title">{fix.title}</h3>
          <p className="remediation__detail-mutation">
            <Icon name="pencil-bolt" />
            {fix.mutation_kind === 'remove_edge' && `Removes edge ${fix.target_id}`}
            {fix.mutation_kind === 'remove_node' && `Removes node ${fix.target_id}`}
            {fix.mutation_kind.startsWith('set_') &&
              `Sets ${fix.target_kind} ${fix.target_id}.${fix.mutation_target_attr} = ${fix.mutation_value ?? '—'}`}
          </p>
        </div>
        <span
          className="remediation__detail-state"
          style={{ color: fix.state_color, borderColor: fix.state_color }}
        >
          {fix.state_label}
        </span>
      </header>

      <p className="remediation__rationale">{fix.rationale}</p>

      <div className="remediation__controls">
        {canSimulate && (
          <button
            type="button"
            className="pill-button pill-button--primary"
            onClick={() => simulate.mutate(fix.id)}
            disabled={simulate.isPending || isRunning || apply.isPending}
          >
            <Icon
              name={simulate.isPending || isRunning ? 'loader-2' : 'flask'}
              className={simulate.isPending || isRunning ? 'remediation__spin' : ''}
            />
            {isRunning
              ? run?.status === 'queued'
                ? 'Queued…'
                : 'Re-deriving…'
              : data.simulation
                ? 'Simulate again'
                : 'Simulate this fix'}
          </button>
        )}

        {canApply && (
          <div className="remediation__apply">
            <label className="remediation__field">
              <span>Applied by</span>
              <input
                type="text"
                value={appliedBy}
                onChange={(event) => setAppliedBy(event.target.value)}
                placeholder="Your name"
                disabled={apply.isPending}
              />
            </label>
            {needsApprover && (
              <label className="remediation__field">
                <span>Approved by</span>
                <input
                  type="text"
                  value={approvedBy}
                  onChange={(event) => setApprovedBy(event.target.value)}
                  placeholder="Approver's name"
                  disabled={apply.isPending}
                />
              </label>
            )}
            {confirming ? (
              <span className="remediation__confirm">
                <button
                  type="button"
                  className="pill-button remediation__danger"
                  onClick={() => {
                    apply.mutate({ recommendationId: fix.id, applied_by: appliedBy, approved_by: approvedBy });
                    setConfirming(false);
                  }}
                  disabled={apply.isPending || appliedBy.trim() === ''}
                >
                  <Icon name={apply.isPending ? 'loader-2' : 'check'} className={apply.isPending ? 'remediation__spin' : ''} />
                  {apply.isPending ? 'Applying…' : 'Yes, apply it'}
                </button>
                <button type="button" className="pill-button" onClick={() => setConfirming(false)} disabled={apply.isPending}>
                  Cancel
                </button>
              </span>
            ) : (
              <button
                type="button"
                className="pill-button"
                onClick={() => setConfirming(true)}
                disabled={apply.isPending || appliedBy.trim() === ''}
              >
                <Icon name="tool" />
                Apply this fix
              </button>
            )}
          </div>
        )}
      </div>

      <p className="remediation__controls-hint">
        {isRunning
          ? `Running for ${formatDuration(run?.elapsed_ms ?? 0)}. The entire path search is being re-run against the mutated graph under the baseline run's own limits, which takes a few minutes here — it is a second real search, not a recalculation of the first one, which is the only way the result can show paths this fix creates as well as the ones it removes. You can leave this page; nothing is written to the live graph by a simulation.`
          : !canSimulate && !canApply
            ? `This recommendation is ${fix.state_label.toLowerCase()}. From here the transition table allows: ${
                data.transitions.map((transition) => transition.label.toLowerCase()).join(', ') || 'nothing'
              }.`
            : data.simulation === null
              ? 'Simulating re-derives every attack path from scratch against the graph as it would be with this one change applied. It takes a couple of minutes and changes nothing. Nothing can be applied before it has been simulated either: the transition table has no route from “recommended” straight to “applied”, because applying without a prediction leaves nothing to verify the result against.'
              : `Applying performs the mutation for real: it writes a new graph version to both stores, along with the exact prior state needed to undo it, and records who did it in the audit log. The new version is left inactive, so the graph every other screen reads does not change underneath them.${
                needsApprover
                  ? ' The fix catalogue marks this one as needing a signature, so the approve step will not go through without a named approver — a stand-in for the on-chain approval the contract will eventually verify.'
                  : ''
              }`}
      </p>

      {simulate.isError && (
        <ErrorState
          title="Simulation refused"
          message={simulate.error instanceof ApiError ? simulate.error.message : 'Could not reach the API to simulate.'}
        />
      )}
      {run?.status === 'failed' && (
        <ErrorState
          title="Simulation failed"
          message="The re-derivation started but did not finish. Nothing was recorded against this recommendation, and its numbers are still the coverage pass's estimate."
          detail={run.error ?? undefined}
        />
      )}
      {apply.isError && (
        <ErrorState
          title="Apply refused"
          message={apply.error instanceof ApiError ? apply.error.message : 'Could not reach the API to apply this fix.'}
        />
      )}
      {apply.data?.applied && (
        <p className="remediation__applied">
          <Icon name="circle-check" className="remediation__analyze-icon" />
          Applied as fix {apply.data.applied.applied_fix_id}: {apply.data.applied.mutation}. Graph
          version {apply.data.applied.graph_version_before} &rarr;{' '}
          {apply.data.applied.graph_version_after} ({formatCount(apply.data.applied.node_count)}{' '}
          nodes, {formatCount(apply.data.applied.edge_count)} edges), written to both stores and{' '}
          <strong>left inactive</strong> so no other screen silently retargets at a graph nothing
          has been re-derived against.
        </p>
      )}

      <section className="remediation__block">
        <h4 className="remediation__block-title">Before and after</h4>
        <SimulationDiff detail={data} />
      </section>

      <section className="remediation__block">
        <h4 className="remediation__block-title">
          What else this touches
          <span className="remediation__block-count">{formatCount(data.dependencies.length)}</span>
        </h4>
        <DependencyPanel dependencies={data.dependencies} />
      </section>

      {data.applied_fix.length > 0 && (
        <section className="remediation__block">
          <h4 className="remediation__block-title">Applied</h4>
          <ul className="remediation__applied-list">
            {data.applied_fix.map((entry) => (
              <li key={entry.id}>
                <strong>{entry.applied_by}</strong> applied this on {entry.applied_at}, moving graph
                version {entry.graph_version_before} to {entry.graph_version_after}.
                {entry.verification_run_id === null
                  ? ' Not verified against the prediction yet.'
                  : ` Verified by run ${entry.verification_run_id}.`}
              </li>
            ))}
          </ul>
        </section>
      )}
    </GlassPanel>
  );
}
