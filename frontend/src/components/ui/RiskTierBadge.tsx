import { useRiskTierMap } from '@/api/config';
import { riskBgVar, riskColorVar } from '@/theme/applyRuntimeTheme';
import './RiskTierBadge.css';

interface RiskTierBadgeProps {
  code: string;
  /** Pass through when the caller already has the row (e.g. risk/summary's by_tier), to skip a lookup. */
  label?: string;
  size?: 'sm' | 'md';
}

/** Colour always comes from the config-driven CSS custom properties written by applyRuntimeTheme -- never a literal here. */
export function RiskTierBadge({ code, label, size = 'md' }: RiskTierBadgeProps) {
  const tiers = useRiskTierMap();
  const resolvedLabel = label ?? tiers.get(code)?.label ?? code;
  return (
    <span
      className={`risk-tier-badge risk-tier-badge--${size}`}
      style={{
        color: riskColorVar(code),
        background: riskBgVar(code),
        borderColor: riskColorVar(code),
      }}
    >
      <span className="risk-tier-badge__dot" style={{ background: riskColorVar(code) }} />
      {resolvedLabel}
    </span>
  );
}
