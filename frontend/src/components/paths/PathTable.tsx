import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

import type { PathSummary } from '@/api/types';
import { Icon } from '@/components/ui/Icon';
import { RiskTierBadge } from '@/components/ui/RiskTierBadge';
import { formatPercent, formatScore, isTruthy, shortId } from '@/lib/format';
import { fadeInUp, staggerContainer } from '@/theme/motion';
import './PathTable.css';

interface PathTableProps {
  paths: PathSummary[];
}

export function PathTable({ paths }: PathTableProps) {
  return (
    <div className="path-table">
      <div className="path-table__head" aria-hidden="true">
        <span>#</span>
        <span>Path</span>
        <span>Hops</span>
        <span>P(success)</span>
        <span>Weakest link</span>
        <span>Impact</span>
        <span>Tier</span>
        <span>Score</span>
      </div>
      <motion.ul initial="initial" animate="animate" variants={staggerContainer()}>
        {paths.map((path) => (
          <motion.li key={path.path_id} variants={fadeInUp()}>
            <Link to={`/paths/${encodeURIComponent(path.path_id)}`} className="path-table__row">
              <span className="path-table__rank">{path.rank_in_run}</span>
              <span className="path-table__route">
                <span className="path-table__node" title={path.source_node_id}>
                  {shortId(path.source_node_id)}
                </span>
                <Icon name="arrow-narrow-right" className="path-table__arrow" />
                <span className="path-table__node" title={path.target_node_id}>
                  {shortId(path.target_node_id)}
                  {isTruthy(path.target_is_crown_jewel) && <Icon name="crown" className="path-table__crown" />}
                </span>
              </span>
              <span className="path-table__cell">{path.hop_count}</span>
              <span className="path-table__cell">{formatPercent(path.p_success)}</span>
              <span className="path-table__cell">
                {formatPercent(path.bottleneck_p)}
                {path.bottleneck_hop !== null && (
                  <span className="path-table__muted"> @hop {path.bottleneck_hop}</span>
                )}
              </span>
              <span className="path-table__cell">{formatScore(path.impact_score)}</span>
              <span className="path-table__cell">
                <RiskTierBadge code={path.risk_tier_code} size="sm" />
              </span>
              <span className="path-table__score">{formatScore(path.risk_score)}</span>
            </Link>
          </motion.li>
        ))}
      </motion.ul>
    </div>
  );
}
