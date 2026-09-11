import type { RiskTierCount } from '@/api/types';
import { formatCount } from '@/lib/format';
import { staggerContainer, fadeInUp } from '@/theme/motion';
import { motion } from 'framer-motion';
import './RiskTierBreakdown.css';

interface RiskTierBreakdownProps {
  tiers: RiskTierCount[];
}

/** Colour comes straight from the row the API returned (risk_tier.ui_color) -- the same source of truth applyRuntimeTheme writes onto the document. */
export function RiskTierBreakdown({ tiers }: RiskTierBreakdownProps) {
  const max = Math.max(1, ...tiers.map((t) => t.count));
  return (
    <motion.ul className="risk-breakdown" initial="initial" animate="animate" variants={staggerContainer()}>
      {tiers.map((tier) => (
        <motion.li key={tier.code} className="risk-breakdown__row" variants={fadeInUp()}>
          <span className="risk-breakdown__label" style={{ color: tier.ui_color }}>
            {tier.label}
          </span>
          <div className="risk-breakdown__track">
            <div
              className="risk-breakdown__fill"
              style={{
                width: `${(tier.count / max) * 100}%`,
                background: tier.ui_color,
              }}
            />
          </div>
          <span className="risk-breakdown__count">{formatCount(tier.count)}</span>
        </motion.li>
      ))}
    </motion.ul>
  );
}
