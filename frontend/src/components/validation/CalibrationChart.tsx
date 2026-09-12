import type { CalibrationScore } from '@/api/validation';
import { formatPercent } from '@/lib/format';
import './CalibrationChart.css';

/**
 * A reliability diagram, hand-rolled in SVG.
 *
 * Same precedent as FactorWaterfall: no charting library, because the whole
 * chart is nine numbers against a diagonal and a dependency would cost more
 * than it saves.
 *
 * The question it answers is the one no ranking metric can, and the one
 * 007_ground_truth.sql was written for: when the engine says seventy percent,
 * does it happen seventy percent of the time? Each dot is one band of the
 * engine's own estimates -- across the bottom, what it predicted; up the side,
 * what the generator actually used when it built those steps. On the diagonal
 * means the estimate was right. Above it means the engine was too pessimistic,
 * below it too confident.
 */

const SIZE = 260;
const PAD_LEFT = 34;
const PAD_BOTTOM = 26;
const PAD_TOP = 10;
const PAD_RIGHT = 10;
const PLOT = SIZE - PAD_LEFT - PAD_RIGHT;
const TICKS = [0, 0.25, 0.5, 0.75, 1];

function x(value: number): number {
  return PAD_LEFT + value * PLOT;
}

function y(value: number): number {
  return PAD_TOP + (1 - value) * PLOT;
}

interface CalibrationChartProps {
  calibration: CalibrationScore;
}

export function CalibrationChart({ calibration }: CalibrationChartProps) {
  const occupied = calibration.bins.filter(
    (bin) => bin.count > 0 && bin.mean_predicted !== null && bin.mean_true !== null,
  );

  if (occupied.length === 0) {
    return (
      <p className="calibration__empty">
        No step on any reported path traverses an edge the manifest recorded a probability for, so
        there is nothing to compare the engine&rsquo;s estimates against. This happens when every
        reported path is built from rules that consume no edge.
      </p>
    );
  }

  const busiest = Math.max(...occupied.map((bin) => bin.count));
  const height = PAD_TOP + PLOT + PAD_BOTTOM;

  return (
    <div className="calibration">
      <svg
        className="calibration__chart"
        viewBox={`0 0 ${SIZE} ${height}`}
        role="img"
        aria-label="Reliability diagram: predicted probability against the probability the generator used"
      >
        <rect
          x={PAD_LEFT}
          y={PAD_TOP}
          width={PLOT}
          height={PLOT}
          className="calibration__plot"
          rx="4"
        />

        {TICKS.map((tick) => (
          <g key={tick}>
            <line x1={x(tick)} y1={PAD_TOP} x2={x(tick)} y2={PAD_TOP + PLOT} className="calibration__gridline" />
            <line x1={PAD_LEFT} y1={y(tick)} x2={PAD_LEFT + PLOT} y2={y(tick)} className="calibration__gridline" />
            <text x={x(tick)} y={PAD_TOP + PLOT + 14} className="calibration__tick calibration__tick--x">
              {tick}
            </text>
            <text x={PAD_LEFT - 6} y={y(tick) + 3} className="calibration__tick calibration__tick--y">
              {tick}
            </text>
          </g>
        ))}

        {/* Perfect calibration. Everything in this chart is read as distance from this line. */}
        <line
          x1={x(0)}
          y1={y(0)}
          x2={x(1)}
          y2={y(1)}
          className="calibration__ideal"
        />

        <polyline
          className="calibration__curve"
          points={occupied
            .map((bin) => `${x(bin.mean_predicted ?? 0)},${y(bin.mean_true ?? 0)}`)
            .join(' ')}
        />

        {occupied.map((bin) => {
          const predicted = bin.mean_predicted ?? 0;
          const observed = bin.mean_true ?? 0;
          return (
            <g key={bin.lower}>
              {/* The vertical drop to the diagonal is the error for this band, drawn
                  rather than left to be estimated from two coordinates. */}
              <line
                x1={x(predicted)}
                y1={y(observed)}
                x2={x(predicted)}
                y2={y(predicted)}
                className="calibration__error"
              />
              <circle
                cx={x(predicted)}
                cy={y(observed)}
                r={4 + 4 * Math.sqrt(bin.count / busiest)}
                className="calibration__dot"
              >
                <title>
                  {`${bin.count} step${bin.count === 1 ? '' : 's'} the engine put at `}
                  {formatPercent(predicted)}
                  {`; the generator built them at `}
                  {formatPercent(observed)}
                </title>
              </circle>
            </g>
          );
        })}

        <text x={PAD_LEFT + PLOT / 2} y={height - 2} className="calibration__axis">
          what the engine predicted
        </text>
        <text
          x={-(PAD_TOP + PLOT / 2)}
          y={10}
          transform="rotate(-90)"
          className="calibration__axis"
        >
          what actually happened
        </text>
      </svg>

      <ul className="calibration__bands">
        {occupied.map((bin) => {
          const gap = (bin.mean_predicted ?? 0) - (bin.mean_true ?? 0);
          return (
            <li key={bin.lower} className="calibration__band">
              <span className="calibration__band-range">
                {formatPercent(bin.lower, 0)}&ndash;{formatPercent(bin.upper, 0)}
              </span>
              <span className="calibration__band-count">
                {bin.count} step{bin.count === 1 ? '' : 's'}
              </span>
              <span className="calibration__band-values">
                said {formatPercent(bin.mean_predicted)}, was {formatPercent(bin.mean_true)}
              </span>
              <span
                className={`calibration__band-gap calibration__band-gap--${
                  Math.abs(gap) < 0.02 ? 'even' : gap > 0 ? 'over' : 'under'
                }`}
              >
                {Math.abs(gap) < 0.02
                  ? 'on the mark'
                  : gap > 0
                    ? `${formatPercent(gap)} too confident`
                    : `${formatPercent(-gap)} too cautious`}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
