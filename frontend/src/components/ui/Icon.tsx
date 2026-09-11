interface IconProps {
  /** A tabler icon name with no `ti-` prefix, e.g. "route", "chart-bar". */
  name: string;
  className?: string;
}

/** Renders a Tabler webfont glyph. Icon names come from config rows (e.g. nav_item.icon), never invented client-side. */
export function Icon({ name, className = '' }: IconProps) {
  return <i className={`ti ti-${name} ${className}`.trim()} aria-hidden="true" />;
}
