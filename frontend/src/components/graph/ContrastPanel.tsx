import type { ContrastResponse } from '@/api/graph';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { formatCount, formatDuration } from '@/lib/format';
import './ContrastPanel.css';

interface ContrastPanelProps {
  data: ContrastResponse;
}

/**
 * The naive-reachability count next to what the precondition-aware engine
 * actually reports -- the central claim of the product, run live.
 *
 * A reachability query treats every graph-permitted route as an attack path.
 * The engine only counts a route once every precondition along it actually
 * holds -- credential access, MFA, trust direction, account state -- and it
 * records the specific reason it refused every candidate that failed one.
 * The gap between the two numbers is the false positives a plain traversal
 * tool would have handed an analyst.
 */
export function ContrastPanel({ data }: ContrastPanelProps) {
  const hasRun = data.engine_path_count !== null;
  const rejectionReasons = data.rejection_reasons ?? [];
  const delta = hasRun ? data.naive_candidate_count - (data.engine_path_count as number) : null;

  return (
    <GlassPanel padding="lg" raised className="contrast-panel">
      <div className="contrast-panel__header">
        <span className="contrast-panel__eyebrow">The central claim</span>
        <h2 className="contrast-panel__title">Naive reachability vs. the engine</h2>
        <p className="contrast-panel__subtitle">
          A reachability query counts every route the graph permits. The engine only counts a route
          once every precondition along it actually holds, and records why it refused the rest.
        </p>
      </div>

      <div className="contrast-panel__figures">
        <div className="contrast-panel__figure">
          <span className="contrast-panel__figure-label">
            <Icon name="topology-star-3" /> Naive candidate count
          </span>
          <span className="contrast-panel__figure-value contrast-panel__figure-value--naive">
            {formatCount(data.naive_candidate_count)}
          </span>
          <span className="contrast-panel__figure-caption">every user-to-crown-jewel route the graph permits</span>
        </div>

        <div className="contrast-panel__vs" aria-hidden="true">
          <Icon name="arrow-narrow-right" />
        </div>

        <div className="contrast-panel__figure">
          <span className="contrast-panel__figure-label">
            <Icon name="shield-check" /> Engine-verified paths
          </span>
          {hasRun ? (
            <>
              <span className="contrast-panel__figure-value contrast-panel__figure-value--engine">
                {formatCount(data.engine_path_count)}
              </span>
              <span className="contrast-panel__figure-caption">
                {formatCount(data.rejected_count)} candidates rejected on a failed precondition
              </span>
            </>
          ) : (
            <>
              <span className="contrast-panel__figure-value contrast-panel__figure-value--pending">—</span>
              <span className="contrast-panel__figure-caption">no completed discovery run yet</span>
            </>
          )}
        </div>
      </div>

      {hasRun ? (
        <div className="contrast-panel__detail">
          <div className="contrast-panel__gap">
            <Icon name="filter-off" />
            <span>
              <strong>{formatCount(delta)}</strong> of the naive candidates were false positives the engine refused
              {typeof data.crown_jewels_reached === 'number' && (
                <> · <strong>{formatCount(data.crown_jewels_reached)}</strong> crown jewel
                  {data.crown_jewels_reached === 1 ? '' : 's'} actually reachable</>
              )}
              {typeof data.discovery_ms === 'number' && <> · discovered in {formatDuration(data.discovery_ms)}</>}
            </span>
          </div>

          {rejectionReasons.length > 0 && (
            <div className="contrast-panel__reasons">
              <span className="contrast-panel__reasons-title">Why candidates were refused</span>
              <ul>
                {rejectionReasons.map((reason) => (
                  <li key={reason.reason_code} className="contrast-panel__reason">
                    <span className="contrast-panel__reason-code">{reason.reason_code}</span>
                    <span className="contrast-panel__reason-count">{formatCount(reason.count)}</span>
                    <span className="contrast-panel__reason-example" title={reason.example}>
                      {reason.example}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : (
        <div className="contrast-panel__pending">
          <Icon name="info-circle" />
          <span>{data.message ?? 'No completed discovery run yet.'}</span>
        </div>
      )}
    </GlassPanel>
  );
}
