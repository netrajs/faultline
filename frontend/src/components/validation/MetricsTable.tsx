import type { LevelScore, MetricDefinition, MetricsReport } from '@/api/validation';
import { levelAt } from '@/api/validation';
import { Icon } from '@/components/ui/Icon';
import './MetricsTable.css';

/**
 * Every accuracy number the manifest supports, in one table.
 *
 * docs/SCOPE.md D13: five separate stat cards for precision, recall, F1,
 * Kendall-tau and NDCG would be five things to read and nothing to compare.
 * One table puts them side by side, with the two match levels as columns so
 * the gap between "found the exact route" and "reached the right places" is
 * read across a row rather than reconstructed from two panels.
 *
 * Labels and hover text come from the seeded `metric_definition` rows the API
 * returns, not from strings written here -- docs/SCOPE.md D12.
 */

type Row = {
  code: string;
  /** Null in a level column means this metric does not vary by match level. */
  values: [number | null, number | null] | { single: number | null };
  support: [string, string] | string;
  lowerIsBetter?: boolean;
  /** Kendall's tau runs -1 to 1; everything else here runs 0 to 1. */
  signed?: boolean;
};

function fraction(value: number | null): string {
  if (value === null || Number.isNaN(value)) return '—';
  return value.toFixed(3);
}

/** How full the bar is: how *good* the number is, which is not the same as how big it is. */
function goodness(value: number | null, lowerIsBetter: boolean, signed: boolean): number {
  if (value === null || Number.isNaN(value)) return 0;
  const unit = signed ? (Math.min(1, Math.max(-1, value)) + 1) / 2 : Math.min(1, Math.max(0, value));
  return lowerIsBetter ? 1 - unit : unit;
}

function ratio(numerator: number, denominator: number): string {
  return denominator === 0 ? 'nothing to score' : `${numerator} of ${denominator}`;
}

function positives(level: LevelScore): number {
  return level.true_positives + level.false_negatives;
}

function predicted(level: LevelScore): number {
  return level.true_positives + level.false_positives;
}

function evaluated(counts: Partial<Record<string, number>>, good: string): [number, number] {
  const total = Object.entries(counts)
    .filter(([outcome]) => outcome !== 'not_evaluated')
    .reduce((sum, [, n]) => sum + (n ?? 0), 0);
  return [counts[good] ?? 0, total];
}

interface MetricsTableProps {
  report: MetricsReport;
}

export function MetricsTable({ report }: MetricsTableProps) {
  const strict = levelAt(report, 'edge_sequence');
  const loose = levelAt(report, 'node_sequence');
  if (!strict || !loose) return null;

  const decoyStrict = evaluated(strict.decoy_counts, 'true_negative');
  const decoyLoose = evaluated(loose.decoy_counts, 'true_negative');
  const twinStrict = evaluated(strict.twin_counts, 'true_positive');
  const twinLoose = evaluated(loose.twin_counts, 'true_positive');

  const rows: Row[] = [
    {
      code: 'precision_edge',
      values: [strict.precision, loose.precision],
      support: [
        ratio(strict.true_positives, predicted(strict)),
        ratio(loose.true_positives, predicted(loose)),
      ],
    },
    {
      code: 'recall_edge',
      values: [strict.recall, loose.recall],
      support: [
        ratio(strict.true_positives, positives(strict)),
        ratio(loose.true_positives, positives(loose)),
      ],
    },
    {
      code: 'f1_edge',
      values: [strict.f1, loose.f1],
      support: ['harmonic mean of the two above', 'harmonic mean of the two above'],
    },
    {
      code: 'decoy_rejection',
      values: [strict.decoy_rejection, loose.decoy_rejection],
      support: [ratio(...decoyStrict), ratio(...decoyLoose)],
    },
    {
      code: 'twin_acceptance',
      values: [strict.twin_acceptance, loose.twin_acceptance],
      support: [ratio(...twinStrict), ratio(...twinLoose)],
    },
    {
      code: 'kendall_tau',
      values: { single: report.ranking.kendall_tau },
      support: `${report.ranking.concordant} pairs ordered the same way, ${report.ranking.discordant} the other way`,
      signed: true,
    },
    {
      code: 'ndcg_at_10',
      values: { single: report.ranking.ndcg_at_k },
      support: `over the top ${report.ranking.k} of ${report.ranking.paths_ranked} ranked paths`,
    },
    {
      code: 'calibration_error',
      values: { single: report.calibration.expected_calibration_error },
      support: `over ${report.calibration.samples} scored steps`,
      lowerIsBetter: true,
    },
    {
      code: 'brier_score',
      values: { single: report.calibration.brier_score },
      support: `over ${report.calibration.samples} scored steps`,
      lowerIsBetter: true,
    },
  ];

  const byCode = new Map(report.definitions.map((entry) => [entry.code, entry]));

  return (
    <div className="metrics-table">
      <div className="metrics-table__grid">
        <div className="metrics-table__row metrics-table__row--head">
          <span>Measurement</span>
          <span>
            Exact route
            <em>same edges, same techniques</em>
          </span>
          <span>
            Right places
            <em>same nodes, any mechanism</em>
          </span>
        </div>

        {rows.map((row) => {
          const definition = byCode.get(row.code);
          return (
            <MetricRow
              key={row.code}
              row={row}
              definition={definition}
              lowerIsBetter={row.lowerIsBetter ?? definition?.higher_is_better === 0}
              signed={row.signed ?? false}
            />
          );
        })}
      </div>
    </div>
  );
}

interface MetricRowProps {
  row: Row;
  definition: MetricDefinition | undefined;
  lowerIsBetter: boolean;
  signed: boolean;
}

function MetricRow({ row, definition, lowerIsBetter, signed }: MetricRowProps) {
  const label = definition?.label ?? row.code;
  // A metric whose name carries "(edge sequence)" is already split into its own
  // column here, so the qualifier is stripped rather than repeated twice per row.
  const name = label.replace(/\s*\(edge sequence\)$/, '');
  const single = 'single' in row.values;

  return (
    <div className={`metrics-table__row${lowerIsBetter ? ' metrics-table__row--inverted' : ''}`}>
      <span className="metrics-table__label">
        <span className="metrics-table__name">
          {name}
          {lowerIsBetter && <span className="metrics-table__direction">lower is better</span>}
        </span>
        {definition && (
          <span className="metrics-table__meaning" title={definition.description}>
            {definition.interpretation}
          </span>
        )}
      </span>

      {single ? (
        <span className="metrics-table__cell metrics-table__cell--wide">
          <Value
            value={(row.values as { single: number | null }).single}
            support={row.support as string}
            lowerIsBetter={lowerIsBetter}
            signed={signed}
          />
        </span>
      ) : (
        (row.values as [number | null, number | null]).map((value, index) => (
          <span className="metrics-table__cell" key={index}>
            <Value
              value={value}
              support={(row.support as [string, string])[index] ?? ''}
              lowerIsBetter={lowerIsBetter}
              signed={signed}
            />
          </span>
        ))
      )}
    </div>
  );
}

function Value({
  value,
  support,
  lowerIsBetter,
  signed,
}: {
  value: number | null;
  support: string;
  lowerIsBetter: boolean;
  signed: boolean;
}) {
  if (value === null) {
    return (
      <span className="metrics-table__value metrics-table__value--absent">
        <span className="metrics-table__number">
          <Icon name="minus" /> not measurable
        </span>
        <span className="metrics-table__support">{support}</span>
      </span>
    );
  }
  return (
    <span className="metrics-table__value">
      <span className="metrics-table__number">{fraction(value)}</span>
      <span className="metrics-table__meter" aria-hidden="true">
        <span
          className="metrics-table__meter-fill"
          style={{ width: `${goodness(value, lowerIsBetter, signed) * 100}%` }}
        />
      </span>
      <span className="metrics-table__support">{support}</span>
    </span>
  );
}

