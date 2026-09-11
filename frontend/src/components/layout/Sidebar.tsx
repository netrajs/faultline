import { NavLink } from 'react-router-dom';

import { useNavItems } from '@/api/config';
import { Icon } from '@/components/ui/Icon';
import { FALLBACK_NAV_ITEMS, IMPLEMENTED_ROUTES } from './navFallback';
import './Sidebar.css';

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

export function Sidebar({ collapsed, onToggleCollapsed }: SidebarProps) {
  const { data, isLoading, isError } = useNavItems();
  const items = data && data.length > 0 ? data : isError ? FALLBACK_NAV_ITEMS : data ?? [];

  return (
    <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="sidebar__brand">
        <span className="sidebar__brand-mark" aria-hidden="true">
          <Icon name="affiliate" />
        </span>
        {!collapsed && (
          <span className="sidebar__brand-name">
            faultline
            <span className="sidebar__brand-tag">attack path analyzer</span>
          </span>
        )}
      </div>

      <nav className="sidebar__nav" aria-label="Primary">
        {isLoading && items.length === 0 ? (
          <ul className="sidebar__skeleton" aria-hidden="true">
            {Array.from({ length: 4 }, (_, i) => (
              <li key={i} />
            ))}
          </ul>
        ) : (
          <ul>
            {items.map((item) => {
              const isStub = !IMPLEMENTED_ROUTES.has(item.route);
              return (
                <li key={item.code}>
                  <NavLink
                    to={item.route}
                    end={item.route === '/'}
                    title={collapsed ? item.label : item.description}
                    className={({ isActive }) => `sidebar__link ${isActive ? 'sidebar__link--active' : ''}`}
                  >
                    <span className="sidebar__link-icon">
                      <Icon name={item.icon} />
                    </span>
                    {!collapsed && (
                      <span className="sidebar__link-label">
                        {item.label}
                        {isStub && <span className="sidebar__link-badge">soon</span>}
                      </span>
                    )}
                  </NavLink>
                </li>
              );
            })}
          </ul>
        )}
      </nav>

      <button
        type="button"
        className="sidebar__collapse-toggle"
        onClick={onToggleCollapsed}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        <Icon name={collapsed ? 'layout-sidebar-right-expand' : 'layout-sidebar-left-expand'} />
        {!collapsed && <span>Collapse</span>}
      </button>
    </aside>
  );
}
