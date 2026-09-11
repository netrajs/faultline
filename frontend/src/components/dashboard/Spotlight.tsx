import LiquidGlass from 'liquid-glass-react';
import { Link } from 'react-router-dom';

import type { TopRisk } from '@/api/types';
import { Icon } from '@/components/ui/Icon';
import { RiskTierBadge } from '@/components/ui/RiskTierBadge';
import { formatPercent, formatScore, isTruthy, shortId } from '@/lib/format';
import './Spotlight.css';

interface SpotlightProps {
  risk: TopRisk;
}

/**
 * The one place in the app that reaches for the real liquid-glass distortion
 * effect rather than the cheaper CSS backdrop-filter used everywhere else --
 * a single always-present hero, never one per list row, so the per-instance
 * SVG displacement cost stays negligible. Chromium renders the refraction;
 * Safari/Firefox fall back to a plain frosted blur, which still reads fine.
 */
export function Spotlight({ risk }: SpotlightProps) {
  return (
    <LiquidGlass
      mode="prominent"
      cornerRadius={20}
      blurAmount={0.09}
      saturation={150}
      elasticity={0.1}
      className="spotlight-glass"
    >
      <Link to={`/paths/${encodeURIComponent(risk.path_id)}`} className="spotlight">
        <div className="spotlight__eyebrow">
          <Icon name="alert-octagon" />
          Most critical path in this run
        </div>
        <div className="spotlight__route">
          <span className="spotlight__node" title={risk.source_node_id}>
            {risk.source_name ?? shortId(risk.source_node_id)}
          </span>
          <Icon name="arrow-narrow-right" className="spotlight__arrow" />
          <span className="spotlight__node" title={risk.target_node_id}>
            {risk.target_name ?? shortId(risk.target_node_id)}
            {isTruthy(risk.target_is_crown_jewel) && <Icon name="crown" className="spotlight__crown" />}
          </span>
        </div>
        <div className="spotlight__stats">
          <div className="spotlight__score">
            <span className="spotlight__score-value">{formatScore(risk.risk_score)}</span>
            <span className="spotlight__score-max">/10</span>
          </div>
          <RiskTierBadge code={risk.risk_tier_code} />
          <span className="spotlight__meta">
            {risk.hop_count} hop{risk.hop_count === 1 ? '' : 's'} &middot; {formatPercent(risk.p_success)} success likelihood
          </span>
        </div>
      </Link>
    </LiquidGlass>
  );
}
