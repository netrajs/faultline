import type { CSSProperties } from 'react';

interface IconProps {
  /** A tabler icon name with no `ti-` prefix, e.g. "route", "chart-bar". */
  name: string;
  className?: string;
  /** For a one-off colour driven by config (e.g. a node kind's ui_color) rather than a CSS class. */
  style?: CSSProperties;
}

/** Renders a Tabler webfont glyph. Icon names come from config rows (e.g. nav_item.icon), never invented client-side. */
export function Icon({ name, className = '', style }: IconProps) {
  return <i className={`ti ti-${name} ${className}`.trim()} style={style} aria-hidden="true" />;
}
