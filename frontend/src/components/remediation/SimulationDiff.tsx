import { useMemo } from 'react';

import type { RecommendationDetail, SimulationDelta } from '@/api/remediation';
import { Icon } from '@/components/ui/Icon';
import { RiskTierBadge } from '@/components/ui/RiskTierBadge';
import { formatCount, formatDuration, formatScore, isTruthy, shortId } from '@/lib/format';
import './SimulationDiff.css';

const CHANGE_ORDER: SimulationDelta['change_kind'][] = ['removed', 'added', 'rescored'];

const CHANGE_LABEL: Record<SimulationDelta['change_kind'], string> = {
  removed: 'Paths that stop existing',
  added: 'Paths that appear',
  rescored: 'Paths that change score',
};

const CHANGE_ICON: Record<SimulationDelta['change_kind'], string> = {
  removed: 'circle-minus',
  added: 'circle-plus',
  rescored: 'arrows-up-down',
};

interface FigureProps {
  label: string;
  before: string;
  after: string;
  /** 'good' when the after value is an improvement, 'bad' when it is worse, undefined when neither. */
  direction?: 'good' | 'bad';
  hint?: string;
}

function Figure({ label, before, after, direction, hint }: FigureProps) {
  return (
    <div className="simulation-diff__figure">
      <span className="simulation-diff__figure-label">{label}</span>
      <span className="simulation-diff__figure-values">
        <span className="simulation-diff__figure-before">{before}</span>
        <Icon name="arrow-right" className="simulation-diff__figure-arrow" />
        <span
          className={
            direction ? `simulation-diff__figure-after simulation-diff__figure-after--${direction}` : 'simulation-diff__figure-after'
          }
        >
          {after}
        </span>
      </span>
      {hint && <span className="simulation-diff__figure-hint">{hint}</span>}
    </div>
  );
}

/**
 * The before/after view for one recommendation.
 *
 * Everything here was produced by re-deriving the whole graph from scratch
 * against the mutated snapshot (docs/SCOPE.md D6), which is why the diff runs
 * in both directions: a fix can create paths as well as remove them, and a view
 * that only counted removals would report a fix as a pure win while it opened
 * something new. Additions are shown as prominently as removals for exactly
 * that reason.
 */
export function SimulationDiff({ detail }: { detail: RecommendationDetail }) {
  const { simulation, deltas, runs } = detail;

  const grouped = useMemo(() => {
    const map = new Map<SimulationDelta['change_kind'], SimulationDelta[]>();
    for (const delta of deltas) {
      const bucket = map.get(delta.change_kind);
      if (bucket) bucket.push(delta);
      else map.set(delta.change_kind, [delta]);
    }
    return map;
  }, [deltas]);

  if (!simulation) {
    return (
      <div className="simulation-diff simulation-diff--pending">
        <Icon name="flask" className="simulation-diff__pending-icon" />
        <div>
          <h4 className="simulation-diff__pending-title">Not simulated yet</h4>
          <p className="simulation-diff__pending-body">
            The numbers on this fix are the coverage pass&rsquo;s estimate: <em>if</em> removing this
            target removes exactly the paths through it, this is what is left. Simulating replaces
            them with a measurement &mdash; the mutation is overlaid on the graph and every attack
            path is worked out again from scratch, so the result includes any path the fix{' '}
            <em>creates</em> as well as the ones it removes.
          </p>
        </div>
      </div>
    );
  }

  const pathsBefore = runs?.baseline?.path_count ?? null;
  const pathsAfter = runs?.simulated?.path_count ?? null;
  const crownDelta = simulation.crown_jewels_after - simulation.crown_jewels_before;
  const riskDelta = simulation.risk_after - simulation.risk_before;

  return (
    <div className="simulation-diff">
      <div className="simulation-diff__figures">
        <Figure
          label="Attack paths in total"
          before={pathsBefore === null ? '—' : formatCount(pathsBefore)}
          after={pathsAfter === null ? '—' : formatCount(pathsAfter)}
          direction={
            pathsBefore === null || pathsAfter === null || pathsAfter === pathsBefore
              ? undefined
              : pathsAfter < pathsBefore
                ? 'good'
                : 'bad'
          }
          hint={`${formatCount(simulation.paths_removed)} removed, ${formatCount(simulation.paths_added)} added`}
        />
        <Figure
          label="Crown jewels an attacker reaches"
          before={formatCount(simulation.crown_jewels_before)}
          after={formatCount(simulation.crown_jewels_after)}
          direction={crownDelta === 0 ? undefined : crownDelta < 0 ? 'good' : 'bad'}
          hint={crownDelta === 0 ? 'unchanged' : `${crownDelta > 0 ? '+' : ''}${crownDelta}`}
        />
        <Figure
          label="Worst path, out of 10"
          before={formatScore(simulation.risk_before, 2)}
          after={formatScore(simulation.risk_after, 2)}
          direction={Math.abs(riskDelta) < 0.005 ? undefined : riskDelta < 0 ? 'good' : 'bad'}
          hint={Math.abs(riskDelta) < 0.005 ? 'unchanged' : `${riskDelta > 0 ? '+' : ''}${riskDelta.toFixed(2)}`}
        />
        <div className="simulation-diff__figure">
          <span className="simulation-diff__figure-label">Paths rescored</span>
          <span className="simulation-diff__figure-values">
            <span className="simulation-diff__figure-after">{formatCount(simulation.paths_rescored)}</span>
          </span>
          <span className="simulation-diff__figure-hint">
            present in both runs, different score — no before/after to compare, the path itself is
            the thing that moved
          </span>
        </div>
      </div>

      <p className="simulation-diff__legend">
        Both columns are real search results, not two readings of one. The left is the baseline run;
        the right is a second, complete run against the graph as it would be with this one change
        applied &mdash; same hop cap ({runs?.simulated?.max_hops ?? '—'}), same top-k per pair (
        {runs?.simulated?.top_k_per_pair ?? '—'}), same scoring version, so nothing in the difference
        is an artefact of the settings. <strong>Green means the number moved in your favour</strong>,
        amber means it moved against you. A path is identified by a hash over its edge and rule
        sequence, so &ldquo;the same path&rdquo; in both runs means literally the same attack.
        {simulation.paths_added > 0 && (
          <>
            {' '}
            This fix <strong>opened {formatCount(simulation.paths_added)} route(s) that did not
            exist before</strong>. That is a finding, not an error: removing a grant can strip a
            restriction that was doing real work, and segmenting a network invites a compensating
            route. Where a run hits its expansion budget its path set is a lower bound, so an
            addition can also be a path the baseline had not yet reached.
          </>
        )}
      </p>

      <div className="simulation-diff__changes">
        {CHANGE_ORDER.map((kind) => {
          const rows = grouped.get(kind) ?? [];
          if (rows.length === 0) return null;
          return (
            <section key={kind} className={`simulation-diff__group simulation-diff__group--${kind}`}>
              <h4 className="simulation-diff__group-title">
                <Icon name={CHANGE_ICON[kind]} />
                {CHANGE_LABEL[kind]}
                <span className="simulation-diff__group-count">{formatCount(rows.length)}</span>
              </h4>
              <ul className="simulation-diff__list">
                {rows.map((row) => (
                  <li key={`${kind}-${row.path_id}`}>
                    <span className="simulation-diff__route">
                      <span className="simulation-diff__endpoint">{row.source_name ?? row.source_node_id ?? '—'}</span>
                      <Icon name="arrow-narrow-right" className="simulation-diff__route-arrow" />
                      <span className="simulation-diff__endpoint">{row.target_name ?? row.target_node_id ?? '—'}</span>
                      {isTruthy(row.target_is_crown_jewel ?? 0) && (
                        <Icon name="crown" className="simulation-diff__crown" />
                      )}
                    </span>
                    <span className="simulation-diff__meta">
                      {row.hop_count !== null && (
                        <span className="simulation-diff__hops">
                          {row.hop_count} {row.hop_count === 1 ? 'hop' : 'hops'}
                        </span>
                      )}
                      {row.risk_tier_code && <RiskTierBadge code={row.risk_tier_code} size="sm" />}
                      <span className="simulation-diff__scores">
                        {kind === 'rescored' ? (
                          <>
                            {formatScore(row.risk_before, 2)}
                            <Icon name="arrow-right" className="simulation-diff__figure-arrow" />
                            {formatScore(row.risk_after, 2)}
                          </>
                        ) : (
                          formatScore(kind === 'removed' ? row.risk_before : row.risk_after, 2)
                        )}
                      </span>
                      <span className="simulation-diff__path-id" title={row.path_id}>
                        {shortId(row.path_id, 8)}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>

      {detail.delta_total > detail.deltas.length && (
        <p className="simulation-diff__truncation">
          Showing {formatCount(detail.deltas.length)} of {formatCount(detail.delta_total)} changed
          paths.
        </p>
      )}

      <footer className="simulation-diff__provenance">
        Simulation {simulation.id} · baseline run {simulation.baseline_run_id} · counterfactual run{' '}
        {simulation.simulated_run_id}
        {runs?.simulated?.graph_version_id !== undefined &&
          ` · child graph version ${runs.simulated?.graph_version_id}`}
        {simulation.duration_ms !== undefined && ` · re-derived in ${formatDuration(simulation.duration_ms)}`}
        <span className="simulation-diff__hash" title={simulation.prediction_hash}>
          prediction {shortId(simulation.prediction_hash, 10)}
        </span>
      </footer>
      <p className="simulation-diff__hash-note">
        The prediction hash is taken over the removed and added path sets <em>before</em> the fix is
        applied for real. Verification recomputes it from the stored deltas, so a simulation cannot
        be quietly retro-fitted to whatever the apply step turned out to produce.
      </p>
    </div>
  );
}
