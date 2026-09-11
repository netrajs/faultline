import type { ReactNode } from 'react';

import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { fadeInUp } from '@/theme/motion';
import './StatCard.css';

interface StatCardProps {
  icon: string;
  label: string;
  value: ReactNode;
  sublabel?: ReactNode;
  accent?: 'cyan' | 'purple' | 'neutral';
  delay?: number;
}

export function StatCard({ icon, label, value, sublabel, accent = 'neutral', delay = 0 }: StatCardProps) {
  return (
    <GlassPanel padding="md" className="stat-card" {...fadeInUp(delay)}>
      <div className={`stat-card__icon stat-card__icon--${accent}`}>
        <Icon name={icon} />
      </div>
      <div className="stat-card__body">
        <span className="stat-card__label">{label}</span>
        <span className="stat-card__value">{value}</span>
        {sublabel && <span className="stat-card__sublabel">{sublabel}</span>}
      </div>
    </GlassPanel>
  );
}
