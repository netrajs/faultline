import { useNodeDetail } from '@/api/graph';
import { ApiError } from '@/api/client';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { nodeColorVar, edgeColorVar } from '@/theme/applyRuntimeTheme';
import './NodeDetailPanel.css';

const HIDDEN_ATTR_KEYS = new Set([
  'node_id',
  'name',
  'display_name',
  'is_crown_jewel',
  'criticality',
  'classification',
  'graph_version',
]);

interface NodeDetailPanelProps {
  nodeId: string | undefined;
  onSelectNode: (nodeId: string) => void;
}

/** Full detail for one node: its own attributes plus every incident edge and neighbour. */
export function NodeDetailPanel({ nodeId, onSelectNode }: NodeDetailPanelProps) {
  const detail = useNodeDetail(nodeId);

  if (!nodeId) {
    return (
      <EmptyState
        icon="click"
        title="No node selected"
        description="Pick a row from the node browser to see its attributes and incident edges."
      />
    );
  }

  if (detail.isLoading) {
    return <LoadingState variant="list" rows={5} />;
  }

  if (detail.isError) {
    return (
      <ErrorState
        message={detail.error instanceof ApiError ? detail.error.message : `Could not load node ${nodeId}.`}
      />
    );
  }

  const data = detail.data;
  if (!data) return null;

  const { node, edges } = data;
  const attrEntries = Object.entries(node.attrs).filter(([key]) => !HIDDEN_ATTR_KEYS.has(key));

  return (
    <GlassPanel padding="lg" className="node-detail">
      <div className="node-detail__header">
        <span className="node-detail__dot" style={{ background: nodeColorVar(node.kind) }} />
        <div className="node-detail__heading">
          <h2 className="node-detail__name">{node.display_name || node.name}</h2>
          <span className="node-detail__id">{node.node_id}</span>
        </div>
        {node.is_crown_jewel && (
          <span className="node-detail__crown">
            <Icon name="crown" /> Crown jewel
          </span>
        )}
      </div>

      <div className="node-detail__meta">
        <span className="node-detail__meta-item">
          <span className="node-detail__meta-label">Kind</span>
          {node.kind}
        </span>
        <span className="node-detail__meta-item">
          <span className="node-detail__meta-label">Criticality</span>
          {node.criticality ?? '—'}
        </span>
        <span className="node-detail__meta-item">
          <span className="node-detail__meta-label">Classification</span>
          {node.classification ?? '—'}
        </span>
      </div>

      {attrEntries.length > 0 && (
        <div className="node-detail__section">
          <span className="node-detail__section-title">Attributes</span>
          <dl className="node-detail__attrs">
            {attrEntries.map(([key, value]) => (
              <div key={key} className="node-detail__attr">
                <dt>{key}</dt>
                <dd>{formatAttrValue(value)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      <div className="node-detail__section">
        <span className="node-detail__section-title">Incident edges ({edges.length})</span>
        {edges.length === 0 ? (
          <p className="node-detail__empty">This node has no edges in the active graph.</p>
        ) : (
          <ul className="node-detail__edges">
            {edges.map((edge) => {
              const outgoing = edge.src_id === node.node_id;
              return (
                <li key={edge.edge_id} className="node-detail__edge">
                  <span className="node-detail__edge-direction" aria-hidden="true">
                    <Icon name={outgoing ? 'arrow-narrow-right' : 'arrow-narrow-left'} />
                  </span>
                  <span
                    className="node-detail__edge-type"
                    style={{ color: edgeColorVar(edge.edge_type) }}
                  >
                    {edge.edge_type}
                  </span>
                  <button
                    type="button"
                    className="node-detail__edge-neighbour"
                    onClick={() => onSelectNode(edge.neighbour_id)}
                  >
                    <span className="node-detail__dot node-detail__dot--sm" style={{ background: nodeColorVar(edge.neighbour_kind) }} />
                    {edge.neighbour_name}
                    {edge.neighbour_crown_jewel && <Icon name="crown" className="node-detail__edge-crown" />}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </GlassPanel>
  );
}

function formatAttrValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
