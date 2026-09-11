import type { PathScoreFactor } from '@/api/types';
import { formatBeta, formatPercent } from '@/lib/format';
import './FactorWaterfall.css';

interface FactorWaterfallProps {
  factors: PathScoreFactor[];
}

/**
 * "Why this score", per hop.
 *
 * Because the score is a sum of log-odds terms (docs/SCOPE.md D3), each
 * factor's contribution is exactly its own beta term rather than an estimate
 * of one -- the attribution is exact Shapley, not a bar chart invented for
 * display. This renders it as a labelled step chart of the probability
 * (`p_after`) after each successive factor is applied, baseline first.
 */
export function FactorWaterfall({ factors }: FactorWaterfallProps) {
  if (factors.length === 0) {
    return <p className="factor-waterfall__empty">No factor breakdown was recorded for this hop.</p>;
  }

  const n = factors.length;
  const points = factors.map((factor, index) => {
    const pAfter = factor.p_after ?? 0;
    return {
      x: ((index + 0.5) / n) * 100,
      y: 100 - pAfter * 100,
      heightPct: pAfter * 100,
    };
  });
  const polylinePoints = points.map((p) => `${p.x},${p.y}`).join(' ');

  return (
    <div className="factor-waterfall">
      <div className="factor-waterfall__chart">
        <svg
          className="factor-waterfall__overlay"
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          <polyline points={polylinePoints} className="factor-waterfall__line" vectorEffect="non-scaling-stroke" />
          {points.map((p, i) => (
            <circle key={i} cx={p.x} cy={p.y} r="1.6" className="factor-waterfall__dot" vectorEffect="non-scaling-stroke" />
          ))}
        </svg>
        {factors.map((factor, index) => {
          const direction = factor.beta === null || factor.beta === 0 ? 'neutral' : factor.beta > 0 ? 'worse' : 'better';
          return (
            <div className="factor-waterfall__col" key={`${factor.hop_no}-${factor.seq}`}>
              <span className="factor-waterfall__pafter">{formatPercent(factor.p_after)}</span>
              <div
                className={`factor-waterfall__bar factor-waterfall__bar--${direction}`}
                style={{ height: `${points[index]?.heightPct ?? 0}%` }}
              />
            </div>
          );
        })}
      </div>

      <div className="factor-waterfall__captions">
        {factors.map((factor) => {
          const direction = factor.beta === null || factor.beta === 0 ? 'neutral' : factor.beta > 0 ? 'worse' : 'better';
          return (
            <div className="factor-waterfall__caption" key={`${factor.hop_no}-${factor.seq}-caption`}>
              <span className="factor-waterfall__kind">{factor.factor_kind}</span>
              <span className="factor-waterfall__label">{factor.factor_label}</span>
              {factor.beta !== null && (
                <span className={`factor-waterfall__beta factor-waterfall__beta--${direction}`}>
                  {formatBeta(factor.beta)} logit
                </span>
              )}
              {factor.observed_value !== null && factor.observed_value !== '' && (
                <span className="factor-waterfall__observed">{String(factor.observed_value)}</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
