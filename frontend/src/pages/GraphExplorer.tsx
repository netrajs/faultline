import { useState } from 'react';

import { ApiError } from '@/api/client';
import { useContrast, useGraphStats, useGraphVersion } from '@/api/graph';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { GraphStatsHeader } from '@/components/graph/GraphStatsHeader';
import { ContrastPanel } from '@/components/graph/ContrastPanel';
import { NodeBrowser } from '@/components/graph/NodeBrowser';
import { NodeDetailPanel } from '@/components/graph/NodeDetailPanel';
import { SavedQueriesPanel } from '@/components/graph/SavedQueriesPanel';
import './GraphExplorer.css';

export function GraphExplorer() {
  const version = useGraphVersion();
  const stats = useGraphStats();
  const contrast = useContrast();
  const [selectedNodeId, setSelectedNodeId] = useState<string | undefined>(undefined);

  if (version.isLoading || stats.isLoading) {
    return (
      <div className="graph-explorer">
        <LoadingState variant="cards" rows={4} />
        <LoadingState variant="list" rows={6} />
      </div>
    );
  }

  const headError = version.error ?? stats.error;
  if (version.isError || stats.isError) {
    const isNoGraph = headError instanceof ApiError && headError.status === 404;
    if (isNoGraph) {
      return (
        <EmptyState
          icon="topology-star-3"
          title="No active graph version"
          description={headError.message}
        />
      );
    }
    return (
      <ErrorState
        message={
          headError instanceof ApiError
            ? headError.message
            : 'The API could not be reached. Confirm the backend is running and CORS allows this origin.'
        }
      />
    );
  }

  if (!version.data || !stats.data) return null;

  return (
    <div className="graph-explorer">
      <GraphStatsHeader version={version.data} stats={stats.data} />

      {contrast.isLoading && <LoadingState variant="list" rows={3} />}
      {contrast.isError && (
        <ErrorState
          message={
            contrast.error instanceof ApiError
              ? contrast.error.message
              : 'Could not load the naive-vs-engine contrast.'
          }
        />
      )}
      {contrast.data && <ContrastPanel data={contrast.data} />}

      <div className="graph-explorer__workspace">
        <NodeBrowser selectedNodeId={selectedNodeId} onSelect={setSelectedNodeId} />
        <NodeDetailPanel nodeId={selectedNodeId} onSelectNode={setSelectedNodeId} />
      </div>

      <SavedQueriesPanel />
    </div>
  );
}
