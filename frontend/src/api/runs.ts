import { useQuery } from '@tanstack/react-query';

import { apiGet } from './client';
import type { RunSummary } from './types';

export function useRuns(limit = 20) {
  return useQuery({
    queryKey: ['runs', limit],
    queryFn: () => apiGet<RunSummary[]>('/runs', { limit }),
    retry: 1,
  });
}
