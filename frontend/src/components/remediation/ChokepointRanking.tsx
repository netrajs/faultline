import { useChokepoints } from '@/api/paths';
import { ErrorState, LoadingState } from '@/components/ui/StateViews';
import { ApiError } from '@/api/client';
import { formatCount, formatPercent } from '@/lib/format';
import './ChokepointRanking.css';

/**
 * The cut the recommendations were built from.
 *
 * Reads /api/chokepoints, the same endpoint the path routes already serve from
 * the same table -- POST /api/remediation/analyze is what writes those rows.
 * Folded into a disclosure rather than given its own screen: it is the working
 * behind the ranked list above, and D13's rule is to combine before adding.
 */
export function ChokepointRanking({ limit = 20 }: { limit?: number }) {
  const chokepoints = useChokepoints(limit);

  if (chokepoints.isLoading) return <LoadingState variant="list" rows={3} />;
  if (chokepoints.isError) {
    return (
      <ErrorState
        message={
          chokepoints.error instanceof ApiError
            ? chokepoints.error.message
            : 'The chokepoint ranking could not be loaded.'
        }
      />
    );
  }

  const items = chokepoints.data?.items ?? [];
  if (items.length === 0) {
    return (
      <p className="chokepoint-ranking__empty">
        No chokepoint ranking has been computed for this run yet.
      </p>
    );
  }

  return (
    <div className="chokepoint-ranking">
      <div className="chokepoint-ranking__scroll">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Kind</th>
              <th>Target</th>
              <th>Paths it sits on</th>
              <th>Share of all paths</th>
              <th>Cumulative with everything above</th>
              <th>Best a selection this size could do</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.rank_in_run}>
                <td className="chokepoint-ranking__rank">{item.rank_in_run}</td>
                <td className="chokepoint-ranking__kind">{item.kind}</td>
                <td className="chokepoint-ranking__target" title={item.target_id}>
                  {item.target_id}
                </td>
                <td className="chokepoint-ranking__number">
                  {formatCount(item.paths_covered)} of {formatCount(chokepoints.data?.total_paths ?? 0)}
                </td>
                <td className="chokepoint-ranking__number">{formatPercent(item.coverage_fraction, 0)}</td>
                <td className="chokepoint-ranking__number">{formatPercent(item.cumulative_fraction, 0)}</td>
                <td className="chokepoint-ranking__number">
                  {item.optimality_bound === null ? '—' : formatPercent(item.optimality_bound, 0)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="chokepoint-ranking__legend">
        A chokepoint here is a <strong>cut</strong>, not a popularity score: the question is which
        edges or nodes, if unavailable, leave an attacker with no route at all. Candidates are picked
        greedily by how many not-yet-covered paths each one sits on. Because path coverage is
        submodular, greedy is provably within about 63% of the best possible selection &mdash; so the
        last column reads the guarantee in the useful direction: given what greedy reached by this
        rank, <strong>no selection of this size could have exceeded that figure</strong>. A row
        reading &ldquo;covers 63%, best possible 100%&rdquo; is saying much less than it looks like
        it is. Calling this &ldquo;optimal&rdquo; would be a false claim, so the gap is shown instead
        of hidden.
      </p>
    </div>
  );
}
