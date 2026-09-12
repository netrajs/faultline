import { motion } from 'framer-motion';

import type { Recommendation } from '@/api/remediation';
import { Icon } from '@/components/ui/Icon';
import { formatCount, formatPercent, formatScore, isTruthy } from '@/lib/format';
import { fadeInUp, staggerContainer } from '@/theme/motion';
import './RecommendationTable.css';

interface RecommendationTableProps {
  items: Recommendation[];
  selectedId: number | undefined;
  onSelect: (id: number) => void;
}

/**
 * Every ranked fix in one table, not one card each (docs/SCOPE.md D13): the
 * whole point of a ranking is that the rows are compared against each other,
 * and a stack of cards makes the comparison impossible to do at a glance.
 * Clicking a row opens the shared detail panel below.
 */
export function RecommendationTable({ items, selectedId, onSelect }: RecommendationTableProps) {
  return (
    <div className="recommendation-table">
      <div className="recommendation-table__scroll">
        <table>
          <thead>
            <tr>
              <th className="recommendation-table__rank-head">#</th>
              <th>Fix</th>
              <th>What it changes</th>
              <th>Paths it cuts</th>
              <th>Highest risk left</th>
              <th>Cost</th>
              <th>Priority</th>
              <th>Basis</th>
              <th>State</th>
            </tr>
          </thead>
          <motion.tbody initial="initial" animate="animate" variants={staggerContainer()}>
            {items.map((item, index) => {
              const coverage = item.path_coverage;
              const selected = item.id === selectedId;
              return (
                <motion.tr
                  key={item.id}
                  variants={fadeInUp()}
                  className={selected ? 'recommendation-table__row--selected' : undefined}
                  onClick={() => onSelect(item.id)}
                  tabIndex={0}
                  role="button"
                  aria-pressed={selected}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onSelect(item.id);
                    }
                  }}
                >
                  <td className="recommendation-table__rank">{index + 1}</td>
                  <td className="recommendation-table__fix-cell">
                    <span className="recommendation-table__fix" title={item.fix_description}>
                      {item.fix_label}
                    </span>
                    {item.d3fend_id && (
                      <span className="recommendation-table__d3fend" title="D3FEND defensive technique">
                        {item.d3fend_id}
                      </span>
                    )}
                  </td>
                  <td className="recommendation-table__target">
                    {/* Both lines are truncated with the full value on `title`:
                        a generated title and a node id are each long enough to
                        take the row apart at a normal window width. */}
                    <span className="recommendation-table__target-title" title={item.title}>
                      {item.title}
                    </span>
                    <span className="recommendation-table__target-id" title={item.target_id}>
                      {item.target_kind} {item.target_id}
                    </span>
                  </td>
                  <td className="recommendation-table__coverage">
                    {item.paths_eliminated === null || coverage === null ? (
                      <span className="recommendation-table__unknown">not computed</span>
                    ) : (
                      <>
                        <span className="recommendation-table__bar">
                          <span
                            className="recommendation-table__bar-fill"
                            style={{ width: `${Math.max(2, coverage * 100)}%` }}
                          />
                        </span>
                        <span className="recommendation-table__coverage-value">
                          {formatCount(item.paths_eliminated)} of {formatCount(item.total_paths)}
                          <span className="recommendation-table__coverage-pct">{formatPercent(coverage, 0)}</span>
                        </span>
                      </>
                    )}
                  </td>
                  <td className="recommendation-table__risk">
                    <span className="recommendation-table__risk-before">{formatScore(item.risk_before, 2)}</span>
                    <Icon name="arrow-right" className="recommendation-table__arrow" />
                    <span
                      className={
                        item.risk_after !== null && item.risk_after < item.risk_before
                          ? 'recommendation-table__risk-after recommendation-table__risk-after--down'
                          : 'recommendation-table__risk-after'
                      }
                    >
                      {formatScore(item.risk_after, 2)}
                    </span>
                  </td>
                  <td className="recommendation-table__cost">
                    <span>{item.effort_label}</span>
                    <span className="recommendation-table__disruption">{item.disruption_label}</span>
                  </td>
                  <td className="recommendation-table__priority">{formatScore(item.priority_score, 1)}</td>
                  <td>
                    <span
                      className={`recommendation-table__basis recommendation-table__basis--${
                        isTruthy(item.is_measured) ? 'measured' : 'estimate'
                      }`}
                    >
                      {isTruthy(item.is_measured) ? 'Measured' : 'Estimate'}
                    </span>
                  </td>
                  <td>
                    <span
                      className="recommendation-table__state"
                      style={{ color: item.state_color, borderColor: item.state_color }}
                    >
                      {item.state_label}
                    </span>
                    {isTruthy(item.requires_approval) && (
                      <span
                        className="recommendation-table__approval"
                        title="The fix catalogue marks this one as needing a signature before it can be applied."
                      >
                        <Icon name="signature" />
                      </span>
                    )}
                  </td>
                </motion.tr>
              );
            })}
          </motion.tbody>
        </table>
      </div>

      <p className="recommendation-table__legend">
        Rows are ordered by <strong>priority</strong>, which is the benefit a fix buys divided by
        what it costs: 0.6 &times; the share of attack paths it cuts, plus 0.4 &times; how far it
        drops the worst remaining risk score, divided by its effort and disruption (disruption
        counts double &mdash; an afternoon of somebody&rsquo;s time is recoverable and an outage is
        not). Effort and disruption are read from the fix catalogue, so retuning what
        &ldquo;manual&rdquo; costs your team reorders this list without a rebuild.{' '}
        <strong>Estimate</strong> means the numbers come from the coverage pass &mdash; <em>if</em>{' '}
        removing this target removes exactly the paths through it, this is what is left.{' '}
        <strong>Measured</strong> means a simulation re-derived the whole graph and replaced them
        with what actually happened. The two are never shown as the same thing. A pen-nib icon marks
        a fix the catalogue says needs a signature before it can be applied.
      </p>
    </div>
  );
}
