import { useLocation } from 'react-router-dom';

import { useNavItems } from '@/api/config';
import { useHealth } from '@/api/health';
import { Icon } from '@/components/ui/Icon';
import { FALLBACK_NAV_ITEMS, findActiveNavItem } from './navFallback';
import './Topbar.css';

function titleFromPath(pathname: string): string {
  const segment = pathname.split('/').filter(Boolean).pop();
  if (!segment) return 'Dashboard';
  return segment
    .split('-')
    .map((word) => word[0]?.toUpperCase() + word.slice(1))
    .join(' ');
}

export function Topbar() {
  const location = useLocation();
  const { data: navItems, isError } = useNavItems();
  const items = navItems && navItems.length > 0 ? navItems : isError ? FALLBACK_NAV_ITEMS : [];
  const active = findActiveNavItem(location.pathname, items);
  const { data: health, isLoading: healthLoading, isError: healthError } = useHealth();

  const title = active?.label ?? titleFromPath(location.pathname);
  const description = active?.description;

  return (
    <header className="topbar">
      <div className="topbar__title-group">
        <h1 className="topbar__title">{title}</h1>
        {description && <p className="topbar__subtitle">{description}</p>}
      </div>

      <div className="topbar__status">
        {health?.graph_version && (
          <span className="topbar__pill" title={`Canonical hash ${health.graph_version.canonical_hash}`}>
            <Icon name="git-branch" />
            {health.graph_version.label} &middot; {health.graph_version.node_count.toLocaleString()} nodes
          </span>
        )}

        <span
          className={`topbar__store-dot ${healthLoading ? 'topbar__store-dot--unknown' : health?.stores.mysql ? 'topbar__store-dot--up' : 'topbar__store-dot--down'}`}
          title={healthError ? 'API unreachable' : health?.stores.mysql ? 'MySQL reachable' : 'MySQL unreachable'}
        >
          <Icon name="database" /> MySQL
        </span>
        <span
          className={`topbar__store-dot ${healthLoading ? 'topbar__store-dot--unknown' : health?.stores.neo4j ? 'topbar__store-dot--up' : 'topbar__store-dot--down'}`}
          title={healthError ? 'API unreachable' : health?.stores.neo4j ? 'Neo4j reachable' : 'Neo4j unreachable'}
        >
          <Icon name="topology-star-3" /> Neo4j
        </span>
      </div>
    </header>
  );
}
