import { forwardRef } from 'react';
import { motion, type HTMLMotionProps } from 'framer-motion';

import './GlassPanel.css';

type Padding = 'none' | 'sm' | 'md' | 'lg';

interface GlassPanelOwnProps {
  padding?: Padding;
  /** Adds the stronger lift shadow, for the element the eye should land on first. */
  raised?: boolean;
}

type GlassPanelProps = GlassPanelOwnProps & HTMLMotionProps<'div'>;

/** The base glass surface used by every card, panel and dropdown in the app. */
export const GlassPanel = forwardRef<HTMLDivElement, GlassPanelProps>(function GlassPanel(
  { className = '', padding = 'md', raised = false, ...rest },
  ref,
) {
  const classes = ['glass-surface', 'glass-panel', `glass-panel--${padding}`, raised ? 'glass-panel--raised' : '', className]
    .filter(Boolean)
    .join(' ');
  return <motion.div ref={ref} className={classes} {...rest} />;
});
