import type { PathHop, PathNode } from '@/api/types';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { formatPercent, isTruthy, shortId } from '@/lib/format';
import { fadeInUp } from '@/theme/motion';
import { FactorWaterfall } from './FactorWaterfall';
import './HopCard.css';

interface HopCardProps {
  hop: PathHop;
  nodeLabel: (nodeId: string) => PathNode | undefined;
  delay?: number;
}

function labelFor(nodeId: string, lookup: (nodeId: string) => PathNode | undefined): string {
  const node = lookup(nodeId);
  return node?.display_name || node?.name || shortId(nodeId);
}

export function HopCard({ hop, nodeLabel, delay = 0 }: HopCardProps) {
  const gainedCapabilities = hop.capabilities.filter((cap) => isTruthy(cap.is_newly_gained));

  return (
    <GlassPanel padding="lg" className="hop-card" {...fadeInUp(delay)}>
      <div className="hop-card__header">
        <span className="hop-card__hop-no">Hop {hop.hop_no}</span>
        <div className="hop-card__route">
          <span title={hop.src_node_id}>{labelFor(hop.src_node_id, nodeLabel)}</span>
          <Icon name="arrow-narrow-right" />
          <span title={hop.dst_node_id}>{labelFor(hop.dst_node_id, nodeLabel)}</span>
        </div>
        <div className="hop-card__technique">
          <span className="hop-card__technique-name">{hop.technique_name}</span>
          {hop.attack_id && (
            <a
              className="hop-card__attack-chip"
              href={hop.attack_url ?? undefined}
              target={hop.attack_url ? '_blank' : undefined}
              rel={hop.attack_url ? 'noreferrer' : undefined}
            >
              {hop.attack_id}
              {hop.attack_url && <Icon name="external-link" />}
            </a>
          )}
        </div>
      </div>

      <p className="hop-card__rule">
        <span className="hop-card__rule-code">{hop.rule_code}</span>
        {hop.rule_description}
      </p>

      <div className="hop-card__metrics">
        <div className="hop-card__metric">
          <span className="hop-card__metric-label">P(step succeeds)</span>
          <span className="hop-card__metric-value">{formatPercent(hop.p_succ)}</span>
        </div>
        <div className="hop-card__metric">
          <span className="hop-card__metric-label">Detectability</span>
          <span className="hop-card__metric-value">
            {hop.detectability !== null ? formatPercent(hop.detectability) : '—'}
          </span>
        </div>
        <div className="hop-card__metric">
          <span className="hop-card__metric-label">-ln(p) contribution</span>
          <span className="hop-card__metric-value">{hop.neg_log_contribution.toFixed(3)}</span>
        </div>
      </div>

      {gainedCapabilities.length > 0 && (
        <div className="hop-card__capabilities">
          <span className="hop-card__capabilities-label">Capabilities gained</span>
          <div className="hop-card__capability-chips">
            {gainedCapabilities.map((cap) => (
              <span key={`${cap.capability_code}-${cap.about_node_id ?? ''}`} className="hop-card__capability-chip">
                <Icon name="key" />
                {cap.capability_code}
                {cap.about_node_id && <span className="hop-card__capability-target">on {shortId(cap.about_node_id, 6)}</span>}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="hop-card__factors">
        <h3 className="hop-card__factors-title">Why this score</h3>
        <FactorWaterfall factors={hop.factors} />
      </div>
    </GlassPanel>
  );
}
