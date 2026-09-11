import { useEffect, useState } from 'react';

import { useVocabularies } from '@/api/config';
import { useGraphNodes } from '@/api/graph';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { ErrorState, LoadingState } from '@/components/ui/StateViews';
import { ApiError } from '@/api/client';
import { nodeColorVar } from '@/theme/applyRuntimeTheme';
import { formatCount } from '@/lib/format';
import './NodeBrowser.css';

const PAGE_SIZE = 25;

interface NodeBrowserProps {
  selectedNodeId: string | undefined;
  onSelect: (nodeId: string) => void;
}

/** Searchable, filterable, paginated list of every node in the active graph. */
export function NodeBrowser({ selectedNodeId, onSelect }: NodeBrowserProps) {
  const [qInput, setQInput] = useState('');
  const [q, setQ] = useState('');
  const [kind, setKind] = useState('');
  const [crownJewelsOnly, setCrownJewelsOnly] = useState(false);
  const [offset, setOffset] = useState(0);

  const vocab = useVocabularies();

  // Small debounce so every keystroke doesn't fire a request.
  useEffect(() => {
    const handle = setTimeout(() => {
      setQ(qInput);
      setOffset(0);
    }, 250);
    return () => clearTimeout(handle);
  }, [qInput]);

  const query = useGraphNodes({
    kind: kind || undefined,
    q: q || undefined,
    crownJewelsOnly,
    limit: PAGE_SIZE,
    offset,
  });

  const handleKindChange = (value: string) => {
    setKind(value);
    setOffset(0);
  };

  const handleCrownJewelsChange = (value: boolean) => {
    setCrownJewelsOnly(value);
    setOffset(0);
  };

  return (
    <GlassPanel padding="lg" className="node-browser">
      <div className="node-browser__header">
        <h2 className="node-browser__title">Node browser</h2>
        {query.data && (
          <span className="node-browser__count">
            {formatCount(query.data.items.length)}
            {query.data.total !== query.data.items.length ? ` of ${formatCount(query.data.total)}` : ''} nodes
          </span>
        )}
      </div>

      <div className="node-browser__filters">
        <label className="node-browser__search">
          <Icon name="search" />
          <input
            type="text"
            placeholder="Search by name..."
            value={qInput}
            onChange={(event) => setQInput(event.target.value)}
          />
        </label>

        <select value={kind} onChange={(event) => handleKindChange(event.target.value)}>
          <option value="">All kinds</option>
          {(vocab.data?.node_kinds ?? []).map((k) => (
            <option key={k.code} value={k.code}>
              {k.label}
            </option>
          ))}
        </select>

        <label className="node-browser__checkbox">
          <input
            type="checkbox"
            checked={crownJewelsOnly}
            onChange={(event) => handleCrownJewelsChange(event.target.checked)}
          />
          Crown jewels only
        </label>
      </div>

      {query.isLoading && <LoadingState variant="list" rows={8} />}

      {query.isError && (
        <ErrorState
          message={
            query.error instanceof ApiError
              ? query.error.message
              : 'The node list could not be loaded. Confirm the backend is running.'
          }
        />
      )}

      {query.data && query.data.items.length === 0 && (
        <p className="node-browser__empty">No nodes match these filters.</p>
      )}

      {query.data && query.data.items.length > 0 && (
        <>
          <ul className="node-browser__list">
            {query.data.items.map((node) => (
              <li key={node.node_id}>
                <button
                  type="button"
                  className={`node-browser__row${node.node_id === selectedNodeId ? ' node-browser__row--active' : ''}`}
                  onClick={() => onSelect(node.node_id)}
                >
                  <span className="node-browser__row-dot" style={{ background: nodeColorVar(node.kind) }} />
                  <span className="node-browser__row-kind">{node.kind}</span>
                  <span className="node-browser__row-name" title={node.name}>
                    {node.display_name || node.name}
                  </span>
                  {node.is_crown_jewel && <Icon name="crown" className="node-browser__row-crown" />}
                  <span className="node-browser__row-criticality" data-criticality={node.criticality ?? undefined}>
                    {node.criticality ?? '—'}
                  </span>
                </button>
              </li>
            ))}
          </ul>

          <div className="node-browser__pagination">
            <button
              type="button"
              className="pill-button"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              Previous
            </button>
            <span className="node-browser__page-label">
              {offset + 1}–{Math.min(offset + PAGE_SIZE, query.data.total)} of {formatCount(query.data.total)}
            </span>
            <button
              type="button"
              className="pill-button"
              disabled={offset + PAGE_SIZE >= query.data.total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              Next
            </button>
          </div>
        </>
      )}
    </GlassPanel>
  );
}
