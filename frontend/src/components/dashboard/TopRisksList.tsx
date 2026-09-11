import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

import type { TopRisk } from '@/api/types';
import { RiskTierBadge } from '@/components/ui/RiskTierBadge';
import { Icon } from '@/components/ui/Icon';
import { formatPercent, formatScore, isTruthy, shortId } from '@/lib/format';
import { staggerContainer, fadeInUp } from '@/theme/motion';
import './TopRisksList.css';

interface TopRisksListProps {
  risks: TopRisk[];
}

export function TopRisksList({ risks }: TopRisksListProps) {
  return (
    <motion.ol className="top-risks" initial="initial" animate="animate" variants={staggerContainer()}>
      {risks.map((risk, index) => (
        <motion.li key={risk.path_id} variants={fadeInUp()}>
          <Link to={`/paths/${encodeURIComponent(risk.path_id)}`} className="top-risks__row">
            <span className="top-risks__rank">{index + 1}</span>
            <span className="top-risks__route">
              <span className="top-risks__node" title={risk.source_node_id}>
                {risk.source_name ?? shortId(risk.source_node_id)}
              </span>
              <Icon name="arrow-narrow-right" className="top-risks__arrow" />
              <span className="top-risks__node" title={risk.target_node_id}>
                {risk.target_name ?? shortId(risk.target_node_id)}
                {isTruthy(risk.target_is_crown_jewel) && (
                  <Icon name="crown" className="top-risks__crown" />
                )}
              </span>
            </span>
            <span className="top-risks__hops">{risk.hop_count} hop{risk.hop_count === 1 ? '' : 's'}</span>
            <span className="top-risks__prob">{formatPercent(risk.p_success)}</span>
            <RiskTierBadge code={risk.risk_tier_code} size="sm" />
            <span className="top-risks__score">{formatScore(risk.risk_score)}</span>
          </Link>
        </motion.li>
      ))}
    </motion.ol>
  );
}
