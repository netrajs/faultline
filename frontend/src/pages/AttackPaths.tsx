import { useState } from 'react';

import { ApiError } from '@/api/client';
import { usePaths } from '@/api/paths';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/StateViews';
import { PathFiltersBar, type PathFiltersState } from '@/components/paths/PathFiltersBar';
import { PathTable } from '@/components/paths/PathTable';
import './AttackPaths.css';

const PAGE_SIZE = 50;

export function AttackPaths() {
  const [filters, setFilters] = useState<PathFiltersState>({ tier: '', crownJewelsOnly: false, maxHops: '' });
  const [offset, setOffset] = useState(0);

  const query = usePaths({
    tier: filters.tier || undefined,
    crownJewelsOnly: filters.crownJewelsOnly,
    maxHops: filters.maxHops ? Number(filters.maxHops) : undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const handleFiltersChange = (next: PathFiltersState) => {
    setFilters(next);
    setOffset(0);
  };

  if (query.isLoading) {
    return (
      <div className="attack-paths">
        <LoadingState variant="list" rows={1} />
        <LoadingState variant="list" rows={8} />
      </div>
    );
  }

  if (query.isError) {
    const error = query.error;
    if (error instanceof ApiError && error.status === 404) {
      return <EmptyState icon="route" title="No completed discovery run yet" description={error.message} />;
    }
    return (
      <ErrorState
        message={
          error instanceof ApiError
            ? error.message
            : 'The API could not be reached. Confirm the backend is running and CORS allows this origin.'
        }
      />
    );
  }

  const data = query.data;
  if (!data) return null;

  return (
    <div className="attack-paths">
      <PathFiltersBar value={filters} onChange={handleFiltersChange} resultCount={data.items.length} total={data.total} />

      {data.items.length === 0 ? (
        <EmptyState
          icon="filter-off"
          title="No paths match these filters"
          description="Widen the tier, hop cap or crown-jewel filter to see more of this run's results."
        />
      ) : (
        <>
          <PathTable paths={data.items} />
          <div className="attack-paths__pagination">
            <button
              type="button"
              className="pill-button"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              Previous
            </button>
            <span className="attack-paths__page-label">
              {offset + 1}–{Math.min(offset + PAGE_SIZE, data.total)} of {data.total}
            </span>
            <button
              type="button"
              className="pill-button"
              disabled={offset + PAGE_SIZE >= data.total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}
