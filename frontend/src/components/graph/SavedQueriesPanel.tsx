import { useState } from 'react';

import { useRunSavedQuery, useSavedQueries, type SavedQueryRunResponse } from '@/api/graph';
import { ApiError } from '@/api/client';
import { GlassPanel } from '@/components/ui/GlassPanel';
import { Icon } from '@/components/ui/Icon';
import { ErrorState, LoadingState } from '@/components/ui/StateViews';
import { formatCount } from '@/lib/format';
import './SavedQueriesPanel.css';

/**
 * Pre-approved, named Cypher only. There is no free-text query box here on
 * purpose: the Explorer is a read surface, and a client-supplied Cypher field
 * would turn it into a write surface with full database authority.
 */
export function SavedQueriesPanel() {
  const queries = useSavedQueries();
  const runQuery = useRunSavedQuery();
  const [activeCode, setActiveCode] = useState<string | undefined>(undefined);
  const [result, setResult] = useState<SavedQueryRunResponse | undefined>(undefined);

  const handleRun = (code: string) => {
    setActiveCode(code);
    runQuery.mutate(
      { code, limit: 200 },
      {
        onSuccess: (data) => setResult(data),
      },
    );
  };

  if (queries.isLoading) {
    return (
      <GlassPanel padding="lg" className="saved-queries">
        <h2 className="saved-queries__title">Saved queries</h2>
        <LoadingState variant="list" rows={4} />
      </GlassPanel>
    );
  }

  if (queries.isError) {
    return (
      <GlassPanel padding="lg" className="saved-queries">
        <h2 className="saved-queries__title">Saved queries</h2>
        <ErrorState
          message={queries.error instanceof ApiError ? queries.error.message : 'Could not load saved queries.'}
        />
      </GlassPanel>
    );
  }

  const items = queries.data ?? [];

  return (
    <GlassPanel padding="lg" className="saved-queries">
      <div className="saved-queries__header">
        <h2 className="saved-queries__title">Saved queries</h2>
        <span className="saved-queries__note">
          <Icon name="lock" /> Only pre-approved Cypher can run here — no free-text queries.
        </span>
      </div>

      {items.length === 0 ? (
        <p className="saved-queries__empty">No saved queries are configured.</p>
      ) : (
        <ul className="saved-queries__list">
          {items.map((sq) => {
            const isRunning = runQuery.isPending && activeCode === sq.code;
            return (
              <li key={sq.code} className={`saved-queries__item${activeCode === sq.code ? ' saved-queries__item--active' : ''}`}>
                <div className="saved-queries__item-body">
                  <div className="saved-queries__item-heading">
                    <span className="saved-queries__item-label">{sq.label}</span>
                    <span className="saved-queries__item-purpose" data-purpose={sq.purpose}>
                      {sq.purpose}
                    </span>
                  </div>
                  <p className="saved-queries__item-description">{sq.description}</p>
                </div>
                <button
                  type="button"
                  className="pill-button pill-button--primary"
                  disabled={isRunning}
                  onClick={() => handleRun(sq.code)}
                >
                  {isRunning ? 'Running…' : 'Run'}
                </button>
              </li>
            );
          })}
        </ul>
      )}

      {activeCode && runQuery.isError && (
        <ErrorState
          message={runQuery.error instanceof ApiError ? runQuery.error.message : `Could not run ${activeCode}.`}
        />
      )}

      {result && <SavedQueryResultTable result={result} />}
    </GlassPanel>
  );
}

function SavedQueryResultTable({ result }: { result: SavedQueryRunResponse }) {
  const columns = result.rows.length > 0 ? Object.keys(result.rows[0] as Record<string, unknown>) : [];

  return (
    <div className="saved-queries__result">
      <div className="saved-queries__result-heading">
        <span className="saved-queries__result-label">{result.label}</span>
        <span className="saved-queries__result-count">
          {formatCount(result.row_count)} row{result.row_count === 1 ? '' : 's'}
          {result.truncated ? ` (showing first ${formatCount(result.rows.length)})` : ''}
        </span>
      </div>

      {result.rows.length === 0 ? (
        <p className="saved-queries__empty">This query returned no rows against the active graph.</p>
      ) : (
        <div className="saved-queries__table-scroll">
          <table className="saved-queries__table">
            <thead>
              <tr>
                {columns.map((col) => (
                  <th key={col}>{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((row, i) => (
                <tr key={i}>
                  {columns.map((col) => (
                    <td key={col}>{formatCell(row[col])}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
