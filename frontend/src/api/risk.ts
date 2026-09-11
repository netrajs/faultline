import { useQuery } from '@tanstack/react-query';

import { apiGet } from './client';
import type { RiskSummary, TopRisk } from './types';

export function useRiskSummary() {
  return useQuery({
    queryKey: ['risk', 'summary'],
    queryFn: () => apiGet<RiskSummary>('/risk/summary'),
    retry: 1,
  });
}

export function useTopRisks(n = 5) {
  return useQuery({
    queryKey: ['risk', 'top', n],
    queryFn: () => apiGet<TopRisk[]>('/risk/top', { n }),
    retry: 1,
  });
}
