import { useState } from 'react';

import { ApiError } from '@/api/client';
import type { DifferentialCase, DifferentialReport } from '@/api/validation';
import { useDifferentialReport } from '@/api/validation';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { ErrorState, LoadingState } from '@/components/ui/StateViews';
import { formatCount, formatDuration, formatPercent } from '@/lib/format';
import { fadeInUp } from '@/theme/motion';
import './DifferentialPanel.css';

/**
 * The fast engine against the exhaustive reference oracle, one row per graph.
 *
 * docs/SCOPE.md D13: nine worlds would otherwise be nine cards. They are the
 * same kind of thing measured the same way, so they are one table, and the
 * disagreements -- the only part that needs prose -- are listed once underneath
 * rather than repeated inside every row.
 */
export function DifferentialPanel() {
  const [includeSeeded, setIncludeSeeded] = useState(false);
  const query = useDifferentialReport(includeSeeded);
  const report = query.data;

  return (
    <GlassPanel padding="lg" className="differential" raised {...fadeInUp()}>
      <header className="differential__header">
        <Icon name="git-compare" className="differential__icon" />
        <div>
          <h2 className="differential__title">Two implementations, same rules</h2>
          <p className="differential__intro">
            The engine that runs this product is fast: it searches best-first, prunes states that
            can do nothing new, and stops at a hop limit. Alongside it is a second search written
            from the same written rules and deliberately made as dumb as possible &mdash; it tries
            every rule at every place and prunes nothing, so it is far too slow for real use but
            cannot share a shortcut with the fast one. Running both over the same small graphs and
            comparing what they found is the only check that catches the two of them meaning
            different things by the same rule.
          </p>
        </div>
        <label className="differential__toggle">
          <input
            type="checkbox"
            checked={includeSeeded}
            onChange={(event) => setIncludeSeeded(event.target.checked)}
          />
          <span>Include the real graph</span>
        </label>
      </header>

      {query.isLoading && <LoadingState variant="list" rows={5} />}

      {query.isError && (
        <ErrorState
          message={
            query.error instanceof ApiError
              ? query.error.message
              : 'The comparison could not be run. Confirm the backend is running.'
          }
        />
      )}

      {report && <Summary report={report} />}
      {report && <CaseTable report={report} />}
      {report && <Disagreements report={report} />}

      {report && (
        <p className="differential__legend">
          <strong>Agreed</strong> counts paths both searches found. <strong>Engine only</strong>{' '}
          and <strong>reference only</strong> are paths exactly one of them found, and each is
          written out in full below &mdash; a disagreement is reported here, never quietly
          reconciled, because deciding which side is right is a matter of reading the rules
          document. The reference deliberately enumerates more than the engine reports: routes with
          a step that contributed nothing, and routes that end merely next to the target rather
          than on it. Those are filtered out before comparing, which is why &ldquo;reference
          paths&rdquo; is larger than &ldquo;comparable&rdquo;.
        </p>
      )}

      {report && (
        <footer className="differential__provenance">
          Rules loaded from {report.model_origin === 'database' ? 'the database' : 'the seed files'}{' '}
          &middot; {report.model_detail} &middot; whole comparison in{' '}
          {formatDuration(report.duration_ms)}
          {report.seeded_graph_bound && ` · ${report.seeded_graph_bound}`}
        </footer>
      )}
    </GlassPanel>
  );
}

function Summary({ report }: { report: DifferentialReport }) {
  const clean = report.disagreement_count === 0;
  return (
    <div className={`differential__verdict differential__verdict--${clean ? 'clean' : 'split'}`}>
      <Icon name={clean ? 'shield-check' : 'alert-triangle'} />
      <span>
        {clean
          ? `Both searches found exactly the same ${formatCount(report.agreed_total)} paths across ${formatCount(report.cases_total)} graphs.`
          : `${formatCount(report.cases_agreeing)} of ${formatCount(report.cases_total)} graphs matched exactly. ${report.disagreement_count === 1 ? 'One path was' : `${formatCount(report.disagreement_count)} paths were`} found by only one of the two.`}
      </span>
      {report.agreement_rate !== null && (
        <span className="differential__rate">{formatPercent(report.agreement_rate)} agreement</span>
      )}
    </div>
  );
}

function CaseTable({ report }: { report: DifferentialReport }) {
  return (
    <div className="differential__table">
      <div className="differential__row differential__row--head">
        <span>Graph</span>
        <span>Size</span>
        <span>Engine</span>
        <span>Reference</span>
        <span>Comparable</span>
        <span>Agreed</span>
        <span>Verdict</span>
      </div>
      {report.cases.map((entry) => (
        <CaseRow key={entry.code} entry={entry} />
      ))}
    </div>
  );
}

function CaseRow({ entry }: { entry: DifferentialCase }) {
  const state = entry.error ? 'error' : entry.agrees ? 'agree' : 'differ';
  return (
    <div className={`differential__row differential__row--${state}`}>
      <span className="differential__case">
        <span className="differential__case-title">{entry.title}</span>
        <span className="differential__case-mechanism">{entry.mechanism}</span>
      </span>
      <span className="differential__figure">
        {formatCount(entry.node_count)} nodes
        <em>
          {formatCount(entry.edge_count)} edges, {entry.max_hops} hops
        </em>
      </span>
      <span className="differential__figure">
        {formatCount(entry.engine_path_count)}
        <em>{formatDuration(entry.engine_ms)}</em>
      </span>
      <span className="differential__figure">
        {formatCount(entry.reference_path_count)}
        <em>{formatCount(entry.reference_states_expanded)} states</em>
      </span>
      <span className="differential__figure">{formatCount(entry.reference_comparable_count)}</span>
      <span className="differential__figure">{formatCount(entry.agreed_count)}</span>
      <span className={`differential__verdict-cell differential__verdict-cell--${state}`}>
        <Icon name={state === 'agree' ? 'circle-check' : state === 'error' ? 'ban' : 'circle-x'} />
        {state === 'agree'
          ? 'identical'
          : state === 'error'
            ? 'refused'
            : `${entry.engine_only.length + entry.reference_only.length} differ`}
      </span>
    </div>
  );
}

function Disagreements({ report }: { report: DifferentialReport }) {
  const disputed = report.cases.filter(
    (entry) => entry.engine_only.length > 0 || entry.reference_only.length > 0 || entry.error,
  );
  if (disputed.length === 0) return null;

  return (
    <div className="differential__disputes">
      <h3 className="differential__disputes-title">Where they differed</h3>
      {disputed.map((entry) => (
        <div className="differential__dispute" key={entry.code}>
          <h4>{entry.title}</h4>
          {entry.error && <p className="differential__dispute-error">{entry.error}</p>}
          {[...entry.engine_only, ...entry.reference_only].map((item, index) => (
            <div className="differential__path" key={`${item.found_by}-${index}`}>
              <span
                className={`differential__found-by differential__found-by--${item.found_by}`}
              >
                {item.found_by === 'engine' ? 'engine only' : 'reference only'}
              </span>
              <ol className="differential__steps">
                {item.steps.map((step, stepIndex) => (
                  <li key={stepIndex}>{step}</li>
                ))}
              </ol>
              <span className="differential__target">reaches {item.target_node_id}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
