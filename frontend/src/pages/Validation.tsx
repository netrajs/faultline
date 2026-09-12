import { ApiError } from '@/api/client';
import type { MetricsReport } from '@/api/validation';
import { levelAt, useValidationMetrics } from '@/api/validation';
import { CalibrationChart } from '@/components/validation/CalibrationChart';
import { DifferentialPanel } from '@/components/validation/DifferentialPanel';
import { InvariantGrid } from '@/components/validation/InvariantGrid';
import { MetricsTable } from '@/components/validation/MetricsTable';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { formatCount, formatDuration } from '@/lib/format';
import { fadeInUp } from '@/theme/motion';
import './Validation.css';

/**
 * Measured accuracy, not asserted accuracy (docs/SCOPE.md D9).
 *
 * Three panels, three different faults. Scored against the generator's manifest
 * catches the engine being wrong about the world. Compared against a second,
 * deliberately slow implementation catches the two disagreeing about what the
 * rules mean. The property suite catches the engine contradicting itself, which
 * neither of the others can see.
 *
 * Each panel loads its own data and renders its own empty and error states.
 * Nothing here substitutes a zero for a number that could not be measured: a
 * ratio with an empty denominator reads "not measurable" and says why.
 */
export function Validation() {
  const metrics = useValidationMetrics();

  return (
    <div className="validation">
      <AccuracyPanel
        report={metrics.data}
        isLoading={metrics.isLoading}
        error={metrics.error}
      />
      <DifferentialPanel />
      <InvariantGrid />
    </div>
  );
}

interface AccuracyPanelProps {
  report: MetricsReport | undefined;
  isLoading: boolean;
  error: unknown;
}

function AccuracyPanel({ report, isLoading, error }: AccuracyPanelProps) {
  if (isLoading) return <LoadingState variant="list" rows={6} />;

  if (error) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <EmptyState
          icon="checkup-list"
          title="Nothing has been scored yet"
          description={error.message}
        />
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

  if (!report) return null;

  const strict = levelAt(report, 'edge_sequence');
  const loose = levelAt(report, 'node_sequence');
  const notEvaluated = strict?.not_evaluated ?? 0;

  return (
    <GlassPanel padding="lg" className="validation__accuracy" raised {...fadeInUp()}>
      <header className="validation__header">
        <Icon name="target-arrow" className="validation__icon" />
        <div>
          <h2 className="validation__title">Measured against a known answer</h2>
          <p className="validation__intro">
            The environment here is generated rather than real, and that is what makes this page
            possible: the generator knows where it put each attack and which lookalikes it planted
            to be refused, so the score below has a denominator. It never writes down the route
            &mdash; only the two ends of it and the single attribute that separates each decoy from
            its valid twin &mdash; so recovering an attack still means doing the work. Almost every
            tool in this space claims to find real attack paths; very few publish a precision
            figure, because on real infrastructure nobody knows what was missed.
          </p>
        </div>
      </header>

      {report.paths_reported === 0 ? (
        <EmptyState
          icon="circles"
          title="The run being scored reported no paths"
          description={`Analysis run ${report.analysis_run_id} completed against graph version ${report.graph_version_id} but found nothing, so there is nothing to score. Re-run discovery, or check the threat model it ran under.`}
        />
      ) : (
        <>
          <MetricsTable report={report} />

          <p className="validation__legend">
            <strong>Exact route</strong> asks whether the engine found the planted attack by the
            planted mechanism &mdash; the same edges, in the same order, within the number of steps
            the scenario was built with. <strong>Right places</strong> is the forgiving reading: it
            only asks whether the reported attack passes through the target at all. The gap between
            the two columns is how often the engine gets to the right place by a different route.
            The bar under each number is <strong>how good the number is, not how big it is</strong>{' '}
            &mdash; for the two where a lower value is better, a full bar means near zero. Kendall
            tau runs from &minus;1 to 1; everything else runs from 0 to 1. Where a number could not
            be measured at all the cell says so instead of showing a zero, because a ratio over an
            empty set is not a score.
          </p>

          {notEvaluated > 0 && (
            <p className="validation__caveat">
              <Icon name="alert-triangle" />
              <span>
                {formatCount(notEvaluated)} planted lookalike
                {notEvaluated === 1 ? '' : 's'} in this run were neither walked nor refused, so the
                search never reached them and they are excluded from the two rates above rather than
                counted as correctly handled. That matters most for the twins: a decoy-rejection
                rate is only evidence if the matching valid twins were also accepted, since an
                engine that reports nothing refuses every decoy perfectly.
              </span>
            </p>
          )}

          <section className="validation__calibration">
            <h3 className="validation__section-title">
              When it says seventy percent, does it happen seventy percent of the time?
            </h3>
            <p className="validation__section-intro">
              The engine never sees the probability the generator used to build an edge; it works
              its own estimate out from what is observable about that edge. Plotting one against
              the other is the only way to tell a model that ranks well from one whose numbers can
              be trusted &mdash; and a number that cannot be trusted is misleading in exactly the
              place it gets used, which is deciding what to fix first.
            </p>
            <CalibrationChart calibration={report.calibration} />
            <p className="validation__legend">
              Each dot is one band of the engine&rsquo;s own estimates. Across the bottom is what it
              predicted; up the side is what the generator actually used. The dashed diagonal is
              perfect agreement, the amber stub is the distance from it, and a bigger dot means more
              steps landed in that band. <strong>Below the line means over-confident</strong> &mdash;
              it claimed an attack was easier than it was.
              {report.calibration.hops_unscoreable > 0 &&
                ` ${formatCount(report.calibration.hops_unscoreable)} steps are left out because they
                  traverse no edge — kerberoasting needs no relationship in the graph — so the
                  generator never synthesised a probability for them.`}
            </p>
          </section>

          <footer className="validation__provenance">
            Analysis run {report.analysis_run_id} &middot; graph version {report.graph_version_id}{' '}
            (seed {report.seed}, generator {report.generator_version}) &middot;{' '}
            {report.threat_model_code} &middot; scoring {report.scoring_version} &middot;{' '}
            {formatCount(report.paths_reported)} reported paths, of which{' '}
            {formatCount(strict?.unlabelled_findings ?? 0)} correspond to nothing the manifest
            planted and are therefore left out of the score rather than counted against it
            {loose && ` · ${formatCount(loose.reported_findings)} distinct routes by node sequence`}{' '}
            &middot; scored in{' '}
            {report.duration_ms === 0 ? 'under a millisecond' : formatDuration(report.duration_ms)}
          </footer>
        </>
      )}
    </GlassPanel>
  );
}
