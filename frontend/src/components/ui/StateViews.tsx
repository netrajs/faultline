import type { ReactNode } from 'react';

import { GlassPanel } from './GlassPanel';
import { Icon } from './Icon';
import { fadeInUp } from '@/theme/motion';
import './StateViews.css';

interface EmptyStateProps {
  icon: string;
  title: string;
  description: ReactNode;
  children?: ReactNode;
}

/** A well-designed "there is genuinely nothing here yet" screen. Never fabricates numbers to fill the space. */
export function EmptyState({ icon, title, description, children }: EmptyStateProps) {
  return (
    <GlassPanel padding="lg" className="state-view state-view--empty" {...fadeInUp()}>
      <div className="state-view__icon state-view__icon--empty">
        <Icon name={icon} />
      </div>
      <h2 className="state-view__title">{title}</h2>
      <p className="state-view__description">{description}</p>
      {children ? <div className="state-view__actions">{children}</div> : null}
    </GlassPanel>
  );
}

interface ErrorStateProps {
  title?: string;
  message: ReactNode;
  detail?: string;
}

/** Distinguishes "the API answered with a real error" from an empty result -- both matter, differently. */
export function ErrorState({ title = 'Could not load this', message, detail }: ErrorStateProps) {
  return (
    <GlassPanel padding="lg" className="state-view state-view--error" {...fadeInUp()}>
      <div className="state-view__icon state-view__icon--error">
        <Icon name="alert-triangle" />
      </div>
      <h2 className="state-view__title">{title}</h2>
      <p className="state-view__description">{message}</p>
      {detail ? <pre className="state-view__detail">{detail}</pre> : null}
    </GlassPanel>
  );
}

interface SkeletonBlockProps {
  className?: string;
}

function SkeletonBlock({ className = '' }: SkeletonBlockProps) {
  return <div className={`skeleton-block ${className}`.trim()} />;
}

interface LoadingStateProps {
  /** How many skeleton rows/cards to render. */
  rows?: number;
  variant?: 'cards' | 'list';
}

export function LoadingState({ rows = 3, variant = 'list' }: LoadingStateProps) {
  const items = Array.from({ length: rows }, (_, i) => i);
  if (variant === 'cards') {
    return (
      <div className="loading-grid" aria-busy="true" aria-live="polite">
        {items.map((i) => (
          <GlassPanel key={i} padding="md" className="loading-card">
            <SkeletonBlock className="skeleton-block--label" />
            <SkeletonBlock className="skeleton-block--value" />
          </GlassPanel>
        ))}
      </div>
    );
  }
  return (
    <GlassPanel padding="md" className="loading-list" aria-busy="true" aria-live="polite">
      {items.map((i) => (
        <div key={i} className="loading-list__row">
          <SkeletonBlock className="skeleton-block--pill" />
          <SkeletonBlock className="skeleton-block--line" />
          <SkeletonBlock className="skeleton-block--line skeleton-block--line-short" />
        </div>
      ))}
    </GlassPanel>
  );
}
