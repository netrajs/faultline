import { useState } from 'react';

import { ApiError } from '@/api/client';
import type { InvariantOutcome, InvariantReport } from '@/api/validation';
import { useInvariantReport } from '@/api/validation';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { ErrorState, LoadingState } from '@/components/ui/StateViews';
import { formatCount, formatDuration } from '@/lib/format';
import { fadeInUp } from '@/theme/motion';
import './InvariantGrid.css';

/**
 * The ten invariants, as one grid.
 *
 * docs/SCOPE.md D13 again: ten statements checked the same way are one grid,
 * not ten cards. Each row carries the invariant verbatim from the rules
 * document, the verdict, how many generated graphs it was checked against, and
 * -- expanded -- exactly how it was checked, including what a given row
 * deliberately does not cover. A green row that quietly checked nothing is
 * worse than a red one, so a row that was never exercised says so in its own
 * colour rather than passing.
 */
export function InvariantGrid() {
  const query = useInvariantReport();
  const report = query.data;

  return (
    <GlassPanel padding="lg" className="invariants" raised {...fadeInUp()}>
      <header className="invariants__header">
        <Icon name="checkup-list" className="invariants__icon" />
        <div>
          <h2 className="invariants__title">Ten things that must always be true</h2>
          <p className="invariants__intro">
            These are the rules the engine has to obey on <em>every</em> graph, not just the ones
            anyone thought to test: taking something away can never create an attack, hardening a
            control can never make one easier, every step of every reported attack has to hold up
            when replayed by the other search, and running the same analysis twice has to give the
            same answer down to the order of ties. Each is checked here against graphs generated on
            the spot by perturbing a known world &mdash; removing edges, applying hard blocks &mdash;
            rather than against a fixture written to pass.
          </p>
        </div>
      </header>

      {query.isLoading && <LoadingState variant="list" rows={5} />}

      {query.isError && (
        <ErrorState
          message={
            query.error instanceof ApiError
              ? query.error.message
              : 'The property suite could not be run. Confirm the backend is running.'
          }
        />
      )}

      {report && <Verdict report={report} />}

      {report && (
        <div className="invariants__grid">
          {report.outcomes.map((outcome) => (
            <InvariantRow key={outcome.number} outcome={outcome} />
          ))}
        </div>
      )}

      {report && (
        <>
          <p className="invariants__legend">
            <strong>Held</strong> means every generated graph satisfied the statement.{' '}
            <strong>Violated</strong> means at least one did not, and the counterexample is printed
            in the row &mdash; a violation is a bug in the engine, not in the check.{' '}
            <strong>Not exercised</strong> means no generated graph was of a kind this statement
            says anything about, which is not a pass. &ldquo;Checked against N graphs&rdquo; is how
            many perturbed worlds the statement was actually tried on.
          </p>
          <footer className="invariants__provenance">
            {formatCount(report.perturbations.length)} perturbations of one {report.graph_nodes}-node,{' '}
            {report.graph_edges}-edge world under {report.threat_model_code}, searched to{' '}
            {report.max_hops} hops &middot; {formatCount(report.total_cases)} checks in{' '}
            {formatDuration(report.duration_ms)} &middot; rules from{' '}
            {report.model_origin === 'database' ? 'the database' : 'the seed files'}
          </footer>
        </>
      )}
    </GlassPanel>
  );
}

function Verdict({ report }: { report: InvariantReport }) {
  const unexercised = report.outcomes.filter((o) => o.status === 'not_exercised').length;
  const clean = report.failing === 0 && unexercised === 0;
  return (
    <div className={`invariants__verdict invariants__verdict--${clean ? 'clean' : report.failing ? 'broken' : 'partial'}`}>
      <Icon name={clean ? 'shield-check' : 'alert-triangle'} />
      <span>
        {report.passing} of {report.total} held across {formatCount(report.total_cases)} generated
        graphs
        {report.failing > 0 && `, ${report.failing} violated`}
        {unexercised > 0 && `, ${unexercised} not exercised`}.
      </span>
    </div>
  );
}

function InvariantRow({ outcome }: { outcome: InvariantOutcome }) {
  const [open, setOpen] = useState(false);
  const label =
    outcome.status === 'pass' ? 'held' : outcome.status === 'fail' ? 'violated' : 'not exercised';

  return (
    <div className={`invariants__row invariants__row--${outcome.status}`}>
      <span className="invariants__number">{outcome.number}</span>

      <button
        type="button"
        className="invariants__statement"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <span>{outcome.statement}</span>
        <span className="invariants__toggle">
          <Icon name={open ? 'chevron-up' : 'chevron-down'} />
          how this is checked
        </span>
      </button>

      <span className="invariants__cases">
        {outcome.cases_checked === 0
          ? 'no graph applied'
          : `checked against ${formatCount(outcome.cases_checked)} graph${outcome.cases_checked === 1 ? '' : 's'}`}
        <em>{formatDuration(outcome.duration_ms)}</em>
      </span>

      <span className={`invariants__status invariants__status--${outcome.status}`}>
        <Icon
          name={
            outcome.status === 'pass'
              ? 'circle-check'
              : outcome.status === 'fail'
                ? 'circle-x'
                : 'minus'
          }
        />
        {label}
      </span>

      {open && <p className="invariants__method">{outcome.method}</p>}

      {outcome.failures.length > 0 && (
        <ul className="invariants__failures">
          {outcome.failures.map((failure, index) => (
            <li key={index}>{failure}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
