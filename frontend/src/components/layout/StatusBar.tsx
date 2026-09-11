import { useHealth } from '@/api/health';
import { Icon } from '@/components/ui/Icon';
import './StatusBar.css';

const APP_BUILD_LABEL = 'faultline';

export function StatusBar() {
  const { data, isLoading, isError, dataUpdatedAt } = useHealth();

  let statusIcon = 'clock';
  let statusText = 'Checking API...';
  let statusClass = 'status-bar__indicator--unknown';

  if (!isLoading) {
    if (isError) {
      statusIcon = 'plug-connected-x';
      statusText = 'API unreachable';
      statusClass = 'status-bar__indicator--down';
    } else if (data?.status === 'ok') {
      statusIcon = 'circle-check';
      statusText = 'All stores reachable';
      statusClass = 'status-bar__indicator--up';
    } else {
      statusIcon = 'alert-triangle';
      statusText = 'Degraded — Neo4j unreachable, analysis unaffected';
      statusClass = 'status-bar__indicator--degraded';
    }
  }

  return (
    <footer className="status-bar">
      <span className={`status-bar__indicator ${statusClass}`}>
        <Icon name={statusIcon} />
        {statusText}
      </span>

      <div className="status-bar__spacer" />

      {data?.graph_version && (
        <span className="status-bar__item">graph v{data.graph_version.id}</span>
      )}
      {dataUpdatedAt > 0 && (
        <span className="status-bar__item">
          checked {new Date(dataUpdatedAt).toLocaleTimeString()}
        </span>
      )}
      <span className="status-bar__item status-bar__brand">{APP_BUILD_LABEL}</span>
    </footer>
  );
}
